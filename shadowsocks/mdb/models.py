import json
import logging

import peewee

from shadowsocks.mdb import BaseModel, IPSetField, db

logger = logging.getLogger(__name__)


class User(BaseModel):
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
    def __create_or_update_user_from_data(cls, data):
        user_id = data.pop("user_id")
        user, created = cls.get_or_create(user_id=user_id, defaults=data)
        if not created:
            user.update_from_dict(data)
            user.save()
        logger.debug(f"正在创建/更新用户 {user}")
        return user

    @classmethod
    def __create_or_update_by_user_data_list(cls, user_data_list: list):
        """
        从用户数据列表中创建或更新User表
        :param user_data_list:
        :return:
        """
        user_ids = []
        for user_data in user_data_list:
            user_ids.append(user_data["user_id"])
            cls.__create_or_update_user_from_data(user_data)
        cnt = cls.delete().where(cls.user_id.not_in(user_ids)).execute()
        if cnt:
            logger.info(f"成功删除 {cnt} 个用户")

    @classmethod
    def create_or_update_from_json(cls, path):
        """
        从JSON配置文件中创建或更新User表
        :param path:
        :return:
        """
        with open(path, "r") as f:
            data = json.load(f)
        cls._create_or_update_by_user_data_list(data["users"])
