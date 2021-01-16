import datetime
import json

import peewee

db = peewee.SqliteDatabase(":memory:")


class BaseModel(peewee.Model):
    """
    基础Model
    """

    created = peewee.DateTimeField(verbose_name="创建时间", default=datetime.datetime.now)
    updated = peewee.DateTimeField(verbose_name="更新时间", default=datetime.datetime.now)
    is_deleted = peewee.BooleanField(verbose_name="是否删除", default=False, index=True)

    class Meta:
        database = db


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

    def python_value(self, value):
        if value is None:
            return value
        else:
            return set(json.loads(value))
