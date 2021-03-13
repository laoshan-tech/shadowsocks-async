import httpx


class BaseApi(object):
    """
    API基类
    """

    session = httpx.AsyncClient()

    def __init__(self, endpoint: str = ""):
        self.endpoint = endpoint
        self.fetch_api = ""
        self.report_api = ""

        self.__prepare_api()

    def __prepare_api(self) -> None:
        """
        拼装API地址
        :return:
        """
        self.fetch_api = self.endpoint
        self.report_api = self.endpoint

    async def fetch_user_list(self) -> list:
        """
        获取user列表
        :return:
        """
        raise NotImplementedError("fetch_user_list method not defined")

    async def report_user_stats(self, user_data: list) -> None:
        """
        上报user信息
        :param user_data:
        :return:
        """
        raise NotImplementedError("report_user_stats method not defined")
