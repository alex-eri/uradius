import asyncio
from . import constants as C
from .packet import Packet
from cachetools import TTLCache
from asyncache import cached
import logging
logger = logging.getLogger('protocol')

def nas_cache_key(request, *args, **kwargs):
    return request.remote

nas_cache = TTLCache(1024, 1000)
nas_cached = cached(nas_cache, key=nas_cache_key)


class AbstractProtocol(asyncio.Protocol):
    def __init__(self, loop, handler, *a, **kw):
        self.loop = loop
        self.handler = handler
        self.__coa_counter = 0
        self.coas = {}
        super().__init__(*a, **kw)

    @property
    def coa_counter(self):
        self.__coa_counter += 1
        self.__coa_counter %= 256
        return self.__coa_counter

    def connection_made(self, transport):
        logger.debug('connection_made')
        self.transport = transport

    def connection_lost(self, exc):
        self.transport = None

    async def request(self, data, addr):
        logger.debug(addr)
        request = Packet(
            data=data,
            remote=addr,
            dictionary=self.handler.d,
            protocol=self,
            )
        request.parse()
        nas = await nas_cached(self.handler.on_nas)(request)
        request.nas = nas
        if not nas:
            return
        request.secret = nas['secret']
        request.check()

        if request.Code == C.AccessRequest:
            responce = request.reply()
            code = await self.handler.on_auth(request, responce)
            if code is True:
                responce.Code = C.AccessAccept
            elif code is False:
                responce.Code = C.AccessReject
            elif isinstance(code, int):
                responce.Code = code
            if responce.Code == C.AccessAccept:
                await self.handler.on_accept(request, responce)
            elif responce.Code == C.AccessReject:
                await self.handler.on_reject(request, responce)
        elif request.Code == C.AccountingRequest:
            responce = request.reply(C.AccountingResponse)
            await self.handler.on_acct(request, responce)
        elif request.Code in [DisconnectACK, DisconnectNAK, CoAACK, CoANAK]:
            self.coas[(request.Identifier, request.remote)].set_result(request)

        await self.responce(request, responce)

    async def responce(self, request, responce):
        self.data_send(responce.build(), request.remote)

        async def send_coa(coa, timeout=3):
            fut = self.coas[(coa.Identifier, request.remote)] = asyncio.Future()
            self.data_send(coa.build(), request.remote)
            try:
                res = await asyncio.wait_for(fut, timeout=timeout)
            finally:
                del self.coas[(coa.Identifier, request.remote)]
            return res

        await self.handler.on_reply(request, responce, send_coa)


class TCPProtocol(AbstractProtocol):

    def data_send(self, data, addr=None):
        self.transport.write(data)

    def data_received(self, data):
        addr = self.transport.get_extra_info('peername')
        self.loop.create_task(self.request(data, addr))


class RadsecProtocol(TCPProtocol):
    "TCP wrapped into TLS, secret always 'radsec'"
    "TODO cert check"
    async def responce(self, request, responce):
        responce.secret = b'radsec'
        super().responce(request, responce)


class UDPProtocol(AbstractProtocol):

    def data_send(self, data, addr):
        self.transport.sendto(data, addr)

    def datagram_received(self, data, addr):
        self.loop.create_task(self.request( data, addr))

