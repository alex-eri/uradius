import argparse
import asyncio
import gc
import os.path
import pathlib
import socket
import ssl
import uvloop
import importlib
import constants as C

from handler import AbstractHandler
from packet import Packet

import dictionary

import logging

from cachetools import TTLCache
from asyncache import cached


def nas_cache_key(request, *args, **kwargs):
    return request.remote

nas_cache = TTLCache(1024, 1000)
nas_cached = cached(nas_cache, key=nas_cache_key)


class AbstractProtocol(asyncio.Protocol):
    def __init__(self, loop, handler, *a, **kw):
        self.loop = loop
        self.handler = handler
        super().__init__(*a, **kw)

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.transport = None

    async def request(self, data, addr):
        request = Packet(data=data, remote=addr, dictionary=self.handler.d)
        nas = await nas_cached(self.handler.on_nas)(request)
        if not nas:
            return

        request.secret = nas['secret']
        request.check()
        await self.handler.on_preauth(request)
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
        await self.responce(request, responce)

    async def responce(self, request, responce):
        self.data_send(responce.build(), request.remote)


class TCPProtocol(AbstractProtocol):

    def data_send(self, data, addr=None):
        self.transport.write(data)

    def data_received(self, data):
        addr = self.transport.get_extra_info('peername')
        self.loop.create_task(self.request(data, addr))


class UDPProtocol(AbstractProtocol):

    def data_send(self, data, addr):
        self.transport.sendto(data, addr)

    def datagram_received(self, data, addr):
        self.loop.create_task(self.request( data, addr))

