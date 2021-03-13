from enum import unique, Enum
from typing import Union

from shadowsocks.api import BaseApi
from shadowsocks.api.tyz import TYZApi

AEAD_METHOD_LIST = [
    "chacha20-ietf-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
]


@unique
class PanelType(Enum):
    TYZ = "tyz"
    SSPanel = "sspanel"
    V2Board = "v2board"


def get_api_cls(panel: Union[PanelType, str]) -> Union[BaseApi, None]:
    """
    获取API类
    :param panel:
    :return:
    """
    panel_api_map = {PanelType.TYZ: TYZApi}
    return panel_api_map.get(panel)
