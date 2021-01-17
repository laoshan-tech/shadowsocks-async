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

    def __prepare_api(self):
        """
        拼装API地址
        :return:
        """
        self.fetch_api = self.endpoint
        self.report_api = self.endpoint

    async def fetch_user_list(self):
        """
        获取user列表
        :return:
        """
        raise NotImplementedError("fetch_user_list method not defined")

    async def report_user_stats(self):
        """
        上报user信息
        :return:
        """
        raise NotImplementedError("report_user_stats method not defined")
