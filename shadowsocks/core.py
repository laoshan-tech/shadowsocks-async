import asyncio
import logging
import socket
import struct

from shadowsocks import protocol_flag as flag
from shadowsocks.cipherman import CipherMan
from shadowsocks.utils import parse_header

logger = logging.getLogger(__name__)


class LocalHandler:
    """
    事件循环一共处理五个状态

    STAGE_INIT  初始状态 socket5握手
    STAGE_CONNECT 连接建立阶段 从本地获取addr 进行dns解析
    STAGE_STREAM 建立管道(pipe) 进行socket5传输
    STAGE_DESTROY 结束连接状态
    STAGE_ERROR 异常状态
    """

    STAGE_INIT = 0
    STAGE_CONNECT = 1
    STAGE_STREAM = 2
    STAGE_DESTROY = -1
    STAGE_ERROR = 255

    def __init__(self, port):
        super().__init__()

        self.port = port
        self.cipher_man = None

        self._stage = None
        self._peer = None
        self.remote = None
        self.transport = None
        self._transport_protocol = None
        self._transport_protocol_human = None
        self._is_closing = False
        self.connect_buffer = bytearray()

    def _init_transport(self, transport: asyncio.Transport, peer, protocol):
        self._stage = self.STAGE_INIT
        self.transport = transport
        self._peer = peer
        self._transport_protocol = protocol
        if protocol == flag.TRANSPORT_TCP:
            self._transport_protocol_human = "tcp"
        else:
            self._transport_protocol_human = "udp"

    def close(self):
        self._stage = self.STAGE_DESTROY
        if self._is_closing:
            return
        self._is_closing = True

        if self._transport_protocol == flag.TRANSPORT_TCP:
            self.transport and self.transport.close()
            self.cipher_man and self.cipher_man.close()
        self.remote and self.remote.close()

    def write(self, data: bytes):
        if self._transport_protocol == flag.TRANSPORT_TCP:
            if self.transport.is_closing():
                return
            self.transport.write(data)
        else:
            self.transport.sendto(data, self._peer)

    def handle_connection_made(self, transport_protocol, transport, peername):
        self._init_transport(transport, peername, transport_protocol)

    def handle_eof_received(self):
        self.close()

    def handle_connection_lost(self, exc):
        self.close()

    def handle_data_received(self, data):
        """
        异步wrapper
        :param data:
        :return:
        """
        if not self.cipher_man:
            self.cipher_man = CipherMan.get_cipher_by_port(self.port, self._transport_protocol, self._peer)

        try:
            data = self.cipher_man.decrypt(data)
        except Exception as e:
            logger.exception(
                f"decrypt data error:{e} remote:{self._peer},type:{self._transport_protocol_human} closing..."
            )
            self.close()
            return

        if not data:
            return

        if self._stage == self.STAGE_INIT:
            asyncio.create_task(self._handle_stage_init(data))
        elif self._stage == self.STAGE_CONNECT:
            self._handle_stage_connect(data)
        elif self._stage == self.STAGE_STREAM:
            self._handle_stage_stream(data)
        elif self._stage == self.STAGE_ERROR:
            self.close()
        elif self._stage == self.STAGE_DESTROY:
            self.close()
        else:
            logger.warning(f"unknown stage:{self._stage}")

    async def _handle_stage_init(self, data):
        atype, dst_addr, dst_port, header_length = parse_header(data)
        if not all([atype, dst_addr, dst_port, header_length]):
            logger.warning(f"parse_header_error atype: {flag.get_atype_for_human(atype)} port: {self.port}")
            self.close()
            return
        else:
            logger.info(
                "parse_header_success atype: {} {} from: {} dst: {}:{}".format(
                    self._transport_protocol_human, flag.get_atype_for_human(atype), self._peer[0], dst_addr, dst_port,
                )
            )
            payload = data[header_length:]

        loop = asyncio.get_running_loop()
        if self._transport_protocol == flag.TRANSPORT_TCP:
            self._stage = self.STAGE_CONNECT
            self._handle_stage_connect(payload)
            try:
                task = loop.create_connection(lambda: RemoteTCP(self), dst_addr, dst_port)
                _, remote_tcp = await asyncio.wait_for(task, 5)
            except Exception as e:
                self._stage = self.STAGE_ERROR
                self.close()
                logger.warning(f"connection_failed, {type(e)} e: {dst_addr}:{dst_port}")
            else:
                self.remote = remote_tcp
        else:
            try:
                task = loop.create_datagram_endpoint(
                    lambda: RemoteUDP(dst_addr, dst_port, payload, self), remote_addr=(dst_addr, dst_port),
                )
                await asyncio.wait_for(task, 5)
            except Exception as e:
                self._stage = self.STAGE_ERROR
                self.close()
                logger.warning(f"connection_failed, {type(e)} e: {dst_addr}:{dst_port}")

    def _handle_stage_connect(self, data):
        # 在握手之后，会耗费一定时间来来和remote建立连接,但是ss-client并不会等这个时间
        if not self.remote or self.remote.ready is False:
            self.connect_buffer.extend(data)
        else:
            self._stage = self.STAGE_STREAM
            self._handle_stage_stream(data)

    def _handle_stage_stream(self, data):
        self.remote.write(data)


class LocalTCP(asyncio.Protocol):
    """
    Local Tcp Factory
    """

    def __init__(self, port):
        self.port = port
        self._handler = None
        self._transport = None

    def _init_handler(self):
        self._handler = LocalHandler(self.port)

    def __call__(self):
        local = LocalTCP(self.port)
        local._init_handler()
        return local

    def pause_writing(self):
        self._handler.remote.transport.pause_reading()

    def resume_writing(self):
        self._handler.remote.transport.resume_reading()

    def connection_made(self, transport):
        self._transport = transport
        peer = self._transport.get_extra_info("peername")
        self._handler.handle_connection_made(flag.TRANSPORT_TCP, transport, peer)

    def data_received(self, data):
        self._handler.handle_data_received(data)

    def eof_received(self):
        self._handler.handle_eof_received()

    def connection_lost(self, exc):
        self._handler.handle_connection_lost(exc)


class RemoteTCP(asyncio.Protocol):
    def __init__(self, local_handler):
        super().__init__()
        self.local = local_handler
        self.peer = None
        self._transport = None
        self.ready = False
        self._is_closing = False
        self.cipher_man = None

    def write(self, data):
        if not self._transport.is_closing():
            self._transport.write(data)

    def close(self):
        if self._is_closing:
            return
        self._is_closing = True

        self._transport and self._transport.close()
        self.local.close()

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        self.peer = self._transport.get_extra_info("peername")
        self.cipher_man = CipherMan(access_user=self.local.cipher_man.access_user, peer=self.peer)
        transport.write(self.local.connect_buffer)
        self.ready = True

    def data_received(self, data):
        self.local.write(self.cipher_man.encrypt(data=data))

    def pause_reading(self):
        self.local.transport.pause_reading()

    def resume_reading(self):
        self.local.transport.resume_reading()

    def eof_received(self):
        self.close()

    def connection_lost(self, exc):
        self.close()


class LocalUDP(asyncio.DatagramProtocol):
    """
    Local Udp Factory
    """

    def __init__(self, port):
        self.port = port
        self._protocols = {}
        self._transport = None

    def __call__(self):
        local = LocalUDP(self.port)
        return local

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, peername):
        if peername in self._protocols:
            handler = self._protocols[peername]
        else:
            handler = LocalHandler(self.port)
            self._protocols[peername] = handler
            handler.handle_connection_made(flag.TRANSPORT_UDP, self._transport, peername)

        handler.handle_data_received(data)

    def error_received(self, exc):
        # TODO clean udp conn
        pass


class RemoteUDP(asyncio.DatagramProtocol):
    def __init__(self, addr, port, data, local_hander):
        super().__init__()
        self.addr = addr
        self.port = port
        self.data = data
        self.local = local_hander
        self.peer = None
        self._transport = None
        self.cipher_man = None
        self._is_closing = False

    def write(self, data):
        self._transport and not self._transport.is_closing() and self._transport.sendto(data)

    def close(self):
        if self._is_closing:
            return

        self._is_closing = True
        self._transport and self._transport.close()
        del self.local

    def connection_made(self, transport):
        self._transport = transport
        self.peer = self._transport.get_extra_info("peername")
        self.write(self.data)

    def datagram_received(self, data, peer, *args):
        if not self.cipher_man:
            self.cipher_man = CipherMan(access_user=self.local.cipher_man.access_user, ts_protocol=flag.TRANSPORT_UDP)

        assert self.peer == peer
        # 源地址和端口
        bind_addr = peer[0]
        bind_port = peer[1]
        if "." in bind_addr:
            addr = socket.inet_pton(socket.AF_INET, bind_addr)
        elif ":" in bind_addr:
            addr = socket.inet_pton(socket.AF_INET6, bind_addr)
        else:
            raise Exception("add not valid")
        port = struct.pack("!H", bind_port)
        # 构造返回的报文结构
        data = b"\x01" + addr + port + data
        data = self.cipher_man.encrypt(data)
        self.local.write(data)

    def error_received(self, exc):
        self.close()

    def connection_lost(self, exc):
        self.close()
