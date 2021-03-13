from __future__ import annotations

from shadowsocks import protocol_flag as flag
from shadowsocks.ciphers import SUPPORT_METHODS
from shadowsocks.mdb.models import User
from shadowsocks.utils import AutoResetBloomFilter


class CipherMan:
    """
    TODO 流量、链接数限速
    """

    bf = AutoResetBloomFilter()

    def __init__(
        self, user_port: int = None, access_user: User = None, ts_protocol: int = flag.TRANSPORT_TCP, peer=None,
    ):
        self.user_port = user_port
        self.access_user = access_user
        self.ts_protocol = ts_protocol
        self.peer = peer

        self.cipher = None
        self._buffer = bytearray()

        if self.access_user:
            self.method = access_user.method
        else:
            self.method = User.list_by_port(self.user_port).first().method  # NOTE 所有的user用的加密方式必须是一种

        self.cipher_cls = SUPPORT_METHODS.get(self.method)
        if not self.cipher_cls:
            raise Exception(f"暂时不支持这种加密方式:{self.method}")
        if self.cipher_cls.AEAD_CIPHER and self.ts_protocol == flag.TRANSPORT_TCP:
            self._first_data_len = self.cipher_cls.tcp_first_data_len()
        else:
            self._first_data_len = 0

    @classmethod
    def get_cipher_by_port(cls, port, ts_protocol, peer) -> CipherMan:
        user_query = User.list_by_port(port)
        if user_query.count() == 1:
            access_user = user_query.first()
        else:
            access_user = None
        return cls(port, access_user=access_user, ts_protocol=ts_protocol, peer=peer)

    def encrypt(self, data: bytes):
        self.record_user_traffic(0, len(data))

        if self.ts_protocol == flag.TRANSPORT_UDP:
            cipher = self.cipher_cls(self.access_user.password)
            return cipher.pack(data)

        if not self.cipher:
            self.cipher = self.cipher_cls(self.access_user.password)
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes):
        if self.access_user is None and len(data) + len(self._buffer) < self._first_data_len:
            self._buffer.extend(data)
            return

        if not self.access_user:
            self._buffer.extend(data)
            if self.ts_protocol == flag.TRANSPORT_TCP:
                first_data = self._buffer[: self._first_data_len]
            else:
                first_data = self._buffer
            salt = first_data[: self.cipher_cls.SALT_SIZE]
            if salt in self.bf:
                raise RuntimeError(f"repeated salt founded!,peer:{self.peer},{salt}")
            else:
                self.bf.add(salt)

            access_user = User.find_access_user(self.user_port, self.method, self.ts_protocol, first_data)

            if not access_user:
                raise RuntimeError(
                    f"can not find enable access user: {self.user_port}-{self.ts_protocol}-{self.cipher_cls}"
                )
            if not access_user.enable:
                raise RuntimeError(f"access user not have traffic: {access_user}")
            self.access_user = access_user
            self.record_user_ip(self.peer)
            data = bytes(self._buffer)
        if not self.cipher:
            self.cipher = self.cipher_cls(self.access_user.password)

        self.record_user_traffic(len(data), 0)
        if self.ts_protocol == flag.TRANSPORT_TCP:
            return self.cipher.decrypt(data)
        else:
            return self.cipher_cls(self.access_user.password).unpack(data)

    def record_user_ip(self, peer):
        self.access_user and self.access_user.record_ip(peer)

    def record_user_traffic(self, ut_data_len: int, dt_data_len: int):
        self.access_user and self.access_user.record_traffic(ut_data_len, dt_data_len)

    def close(self):
        return
