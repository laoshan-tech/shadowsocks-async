import asyncio
import json
import logging
from collections import defaultdict

import httpx

from shadowsocks.consts import get_api_cls
from shadowsocks.core import LocalTCP, LocalUDP
from shadowsocks.mdb.models import User, db

logger = logging.getLogger(__name__)


class ProxyMan:
    """
    1. 将model的调用都放在这里
    2. server相关的东西也放在这里
    app -> proxyman -> core ->cipherman/model
    """

    AEAD_METHOD_LIST = [
        "chacha20-ietf-poly1305",
        "aes-128-gcm",
        "aes-256-gcm",
    ]

    def __init__(self, use_json, sync_time, listen_host, panel_type, endpoint):
        self.use_json = use_json
        self.sync_time = sync_time
        self.listen_host = listen_host
        self.panel_type = panel_type
        self.endpoint = endpoint
        self.api = None
        self.loop = asyncio.get_event_loop()
        # NOTE {"port":{"tcp":tcp_server,"udp":udp_server}}
        self.__running_servers__ = defaultdict(dict)

    @staticmethod
    def get_user_from_json(path):
        """
        从JSON配置文件中创建或更新User表
        :param path:
        :return:
        """
        with open(path, "r") as f:
            data = json.load(f)
            User.create_or_update_user_from_data_list(data["users"])

    async def get_user_from_remote(self):
        """
        从远程拉取用户列表
        :return:
        """
        if self.api is None:
            self.api = get_api_cls(self.panel_type)

        user_data = await self.api.fetch_user_list()
        User.create_or_update_user_from_data_list(user_data)

    @staticmethod
    async def flush_metrics_to_remote(url):
        fields = [
            User.user_id,
            User.ip_list,
            User.tcp_conn_num,
            User.upload_traffic,
            User.download_traffic,
        ]
        with db.atomic("EXCLUSIVE"):
            users = list(User.select(*fields).where(User.need_sync == True))
            User.update(ip_list=set(), upload_traffic=0, download_traffic=0, need_sync=False).where(
                User.need_sync == True
            ).execute()

        data = []
        for user in users:
            data.append(
                {
                    "user_id": user.user_id,
                    "ip_list": list(user.ip_list),
                    "tcp_conn_num": user.tcp_conn_num,
                    "upload_traffic": user.upload_traffic,
                    "download_traffic": user.download_traffic,
                }
            )
        async with httpx.AsyncClient() as client:
            await client.post(url, json={"data": data})

    async def sync_from_remote(self):
        try:
            await self.flush_metrics_to_remote(self.endpoint)
            await self.get_user_from_remote(self.endpoint)
        except Exception as e:
            logger.error(f"从远程API同步用户出错 {e}")

    async def sync_from_json(self):
        try:
            self.get_user_from_json("userconfig.json")
        except Exception as e:
            logger.error(f"从JSON数据同步用户出错 {e}")

    async def get_server_by_port(self, port):
        return self.__running_servers__.get(port)

    async def start_and_check_ss_server(self):
        """
        启动ss server并且定期检查是否要开启新的server
        TODO 关闭不需要的server
        """

        if self.use_json:
            await self.sync_from_json()
        else:
            await self.sync_from_remote()

        for user in User.select().where(User.is_deleted is False):
            try:
                await self.init_server(user)
            except Exception as e:
                logging.error(e)
                self.loop.stop()

        self.loop.call_later(
            self.sync_time, self.loop.create_task, self.start_and_check_ss_server(),
        )

    async def init_server(self, user: User):

        running_server = await self.get_server_by_port(user.port)
        if running_server:
            return

        tcp_server = await self.loop.create_server(LocalTCP(user.port), self.listen_host, user.port, reuse_port=True)
        udp_server, _ = await self.loop.create_datagram_endpoint(
            LocalUDP(user.port), (self.listen_host, user.port), reuse_port=True
        )
        self.__running_servers__[user.port] = {
            "tcp": tcp_server,
            "udp": udp_server,
        }
        logging.info(f"user:{user} method:{user.method} password:{user.password} {self.listen_host}:{user.port} 已启动")

    def close_server(self):
        for port, server_data in self.__running_servers__.items():
            server_data["tcp"].close()
            server_data["udp"].close()
            logging.info(f"port:{port} 已关闭!")
