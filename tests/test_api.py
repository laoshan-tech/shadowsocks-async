from shadowsocks.api.tyz import TYZApi
from shadowsocks.consts import PanelType, get_api_cls


class TestAPIConsts(object):
    def test_api_consts(self):
        assert get_api_cls(PanelType.TYZ) is TYZApi
        assert get_api_cls("not_exists") is None
