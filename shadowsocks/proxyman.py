import asyncio
import json
import logging
from collections import defaultdict

from shadowsocks.consts import get_api_cls
from shadowsocks.core import LocalTCP, LocalUDP
from shadowsocks.mdb.models import User

logger = logging.getLogger(__name__)


class ProxyMan:
    """
    1. 将model的调用都放在这里
    2. server相关的东西也放在这里
    app -> proxyman -> core ->cipherman/model
    """

    def __init__(self, use_json, sync_time, listen_host, panel_type, endpoint):
        self.use_json = use_json
        self.sync_time = sync_time
        self.listen_host = listen_host
        self.panel_type = panel_type
        self.endpoint = endpoint
        self.api = None if use_json else get_api_cls(self.panel_type)
        self.loop = asyncio.get_event_loop()
        # NOTE {"port":{"tcp":tcp_server,"udp":udp_server}}
        self.__running_servers__ = defaultdict(dict)

    @staticmethod
    def __get_user_from_json(path):
        """
        从JSON配置文件中创建或更新User表
        :param path:
        :return:
        """
        with open(path, "r") as f:
            data = json.load(f)
            User.create_or_update_user_from_data_list(data["users"])

    async def __get_user_from_remote(self):
        """
        从远程拉取用户列表
        :return:
        """
        user_data = await self.api.fetch_user_list()
        User.create_or_update_user_from_data_list(user_data)

    async def __report_user_stats(self):
        """
        上报用户数据
        :return:
        """
        users = User.select().where(User.is_deleted == False)
        User.update(conn_ip_set=set(), upload_traffic=0, download_traffic=0, total_traffic=0).where(
            User.is_deleted == False
        )
        await self.api.report_user_stats(user_data=users)

    async def __sync_from_remote(self):
        try:
            await self.__report_user_stats()
            await self.__get_user_from_remote()
        except Exception as e:
            logger.exception(f"从远程API同步用户出错 {e}")

    async def __sync_from_json(self):
        try:
            self.__get_user_from_json("userconfig.json")
        except Exception as e:
            logger.exception(f"从JSON数据同步用户出错 {e}")

    async def __get_server_by_port(self, port):
        return self.__running_servers__.get(port)

    async def start_and_check_ss_server(self):
        """
        启动ss server并且定期检查是否要开启新的server
        TODO 关闭不需要的server
        :return:
        """
        if self.use_json:
            await self.__sync_from_json()
        else:
            await self.__sync_from_remote()

        for user in User.select().where(User.is_deleted == False):
            try:
                await self.__init_server(user)
            except Exception as e:
                logger.exception(e)
                self.loop.stop()

        self.loop.call_later(
            self.sync_time, self.loop.create_task, self.start_and_check_ss_server(),
        )

    async def __init_server(self, user: User):
        running_server = await self.__get_server_by_port(user.port)
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
        logger.info(f"user:{user} method:{user.method} password:{user.password} {self.listen_host}:{user.port} 已启动")

    def close_server(self):
        """
        关闭所有server
        :return:
        """
        for port, server_data in self.__running_servers__.items():
            server_data["tcp"].close()
            server_data["udp"].close()
            logging.info(f"port:{port} 已关闭!")
