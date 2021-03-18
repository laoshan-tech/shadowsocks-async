from __future__ import annotations

import datetime
import json
import logging
from typing import Union

import peewee
from cryptography.exceptions import InvalidTag

from shadowsocks import protocol_flag as flag
from shadowsocks.ciphers import SUPPORT_METHODS

logger = logging.getLogger(__name__)
db = peewee.SqliteDatabase(":memory:")


class IPSetField(peewee.CharField):
    """
    IP列表
    """

    field_type = "VARCHAR"

    def db_value(self, value) -> str:
        if type(value) is not set:
            value = []

        data = json.dumps(list(value))
        if len(data) > self.max_length:
            raise ValueError(f"Data too long for {self.name}.")

        return data

    def python_value(self, value) -> Union[set, None]:
        if value is None:
            return value
        else:
            return set(json.loads(value))


class User(peewee.Model):
    """
    用户表
    """

    id = peewee.IntegerField(verbose_name="用户ID", primary_key=True, unique=True)
    port = peewee.IntegerField(verbose_name="端口", index=True)
    method = peewee.CharField(verbose_name="加密方法", max_length="64")
    password = peewee.CharField(verbose_name="密码", unique=True, max_length="128")
    upload_traffic = peewee.BigIntegerField(verbose_name="上传流量", default=0)
    download_traffic = peewee.BigIntegerField(verbose_name="下载流量", default=0)
    total_traffic = peewee.BigIntegerField(verbose_name="总流量", default=0)
    last_use_time = peewee.DateTimeField(verbose_name="上次使用时间", null=True, index=True)
    conn_ip_set = IPSetField(verbose_name="连接IP", default=set())
    single_port_access_weight = peewee.BigIntegerField(verbose_name="单端口搜索权重", default=0, index=True)
    is_deleted = peewee.BooleanField(verbose_name="是否删除", default=False, index=True)

    class Meta:
        database = db

    @classmethod
    def list_by_port(cls, port) -> peewee.ModelSelect:
        """
        返回对应端口的所有用户
        :param port:
        :return:
        """
        return cls.select().where(cls.port == int(port)).order_by(cls.single_port_access_weight.desc())

    @classmethod
    @db.atomic("EXCLUSIVE")
    def __create_or_update_user_from_data(cls, data: dict) -> None:
        user_id = data.pop("user_id")
        user, created = cls.get_or_create(id=user_id, defaults=data)
        if not created:
            user.update_from_dict(data)
            user.save()
        logger.debug(f"正在创建/更新用户 {user}")

    @classmethod
    def create_or_update_user_from_data_list(cls, user_data_list: list) -> None:
        """
        从用户数据列表中创建或更新User表
        :param user_data_list:
        :return:
        """
        user_ids = []
        for user_data in user_data_list:
            user_ids.append(user_data["user_id"])
            cls.__create_or_update_user_from_data(user_data)
        cnt = cls.update(is_deleted=True).where(cls.id.not_in(user_ids)).execute()
        if cnt:
            logger.info(f"成功删除 {cnt} 个用户")

    @db.atomic("EXCLUSIVE")
    def record_ip(self, peer) -> None:
        """
        记录连接IP
        :param peer:
        :return:
        """
        if not peer:
            return

        self.conn_ip_set.add(peer[0])
        User.update(conn_ip_set=self.conn_ip_set).where(User.id == self.id).execute()

    @db.atomic("EXCLUSIVE")
    def record_traffic(self, upload, download) -> None:
        """
        记录流量
        :param upload:
        :param download:
        :return:
        """
        User.update(
            download_traffic=User.download_traffic + download,
            upload_traffic=User.upload_traffic + upload,
            total_traffic=User.total_traffic + upload + download,
            last_use_time=datetime.datetime.now(),
        ).where(User.id == self.id).execute()

    @classmethod
    def find_access_user(cls, port, method, ts_protocol, first_data) -> User:
        """
        查找对应的user
        :param port:
        :param method:
        :param ts_protocol:
        :param first_data:
        :return:
        """
        cipher_cls = SUPPORT_METHODS[method]
        access_user = None

        for user in cls.list_by_port(port).iterator():
            try:
                cipher = cipher_cls(user.password)
                if ts_protocol == flag.TRANSPORT_TCP:
                    cipher.decrypt(first_data)
                else:
                    cipher.unpack(first_data)
                access_user = user
                break
            except InvalidTag:
                continue

        if access_user:
            # 记下成功访问的用户，下次优先找到他
            User.update(single_port_access_weight=User.single_port_access_weight + 1).where(User.id == access_user.id)

        return access_user
