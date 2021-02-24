import logging

from shadowsocks.api import BaseApi

logger = logging.getLogger(__name__)


class TYZApi(BaseApi):
    def __init__(self):
        super().__init__()

    def __prepare_api(self) -> None:
        self.fetch_api = self.endpoint
        self.report_api = self.endpoint

    async def fetch_user_list(self) -> list:
        req = await self.session.get(url=self.fetch_api)
        user_data = req.json()["users"]
        logger.info(f"获取用户信息成功，本次获取到 {len(user_data)} 个用户信息")
        return user_data

    async def report_user_stats(self, user_data: list = None) -> None:
        if user_data is None:
            user_data = []

        req = await self.session.post(url=self.report_api, json={"user_stats": user_data})
        status = req.json()["status"]
        message = req.json()["message"]
        if status:
            logger.info(f"上报用户信息成功")
        else:
            logger.info(f"上报用户信息异常 {message}")
