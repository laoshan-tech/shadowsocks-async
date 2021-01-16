import peewee

from shadowsocks.mdb import BaseModel, IPSetField


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
