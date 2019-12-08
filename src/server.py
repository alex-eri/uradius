import argparse
import asyncio
import pathlib
import ssl
import uvloop
import importlib

import importlib.util
import logging

import constants as C
import dictionary

from handler import AbstractHandler
from protocol import UDPProtocol, TCPProtocol

import time


async def main(handlerclasspath):
    loop = asyncio.get_running_loop()
    servers = []

    #Handler = importlib.import_module(handlerclassname).Handler

    spec = importlib.util.spec_from_file_location("handler", handlerclasspath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    Handler = mod.Handler
    t = time.time()
    dct = dictionary.Dictionary('/usr/share/freeradius/dictionary')
    logging.info(time.time()-t)
    handler = type('Handler', (Handler, AbstractHandler), {'c': C})(dct, loop)

    if 'udp':
        servers.append((await loop.create_datagram_endpoint(
            lambda: UDPProtocol(loop, handler), local_addr=('0.0.0.0', 1812))))
        servers.append((await loop.create_datagram_endpoint(
            lambda: UDPProtocol(loop, handler), local_addr=('0.0.0.0', 1813))))

    if 'tcp':

        server = await loop.create_server(lambda: TCPProtocol(loop, handler), '0.0.0.0', 1812)
        await server.start_serving()
        servers.append(server)
        server = await loop.create_server(lambda: TCPProtocol(loop, handler), '0.0.0.0', 1813)
        await server.start_serving()
        servers.append(server)

    if 'tls':

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        try:
            server_context.load_cert_chain(
                    (pathlib.Path(__file__).parent /
                        'certs' / 'ssl_cert.pem'),
                    (pathlib.Path(__file__).parent /
                        'certs' / 'ssl_key.pem'))

            server_context.check_hostname = False
            server_context.verify_mode = ssl.CERT_NONE

            server = await loop.create_server(lambda: TCPProtocol(loop, handler), '0.0.0.0', 2083, ssl=server_context)
            await server.start_serving()
            servers.append(server)

        except FileNotFoundError:
            "Certificates not found"
            pass
        except Exception as e:
            raise e

    await handler.ready
    logging.info('ready')

    return servers, handler


async def close(servers, handler):
    for server in servers:
        if type(server) == tuple:
            server[0].close()
        else:
            server.close()
    await handler.on_close()
    for server in servers:
        if type(server) == tuple:
            pass
        else:
            await server.wait_closed()


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("handler")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--verbosity", help="output verbosity", choices='DEBUG INFO WARNING ERROR FATAL'.split())
    args = parser.parse_args()

    level = logging.ERROR
    if args.debug:
        level = logging.DEBUG
    if args.verbosity:
        level = getattr(logging, args.verbosity)

    logging.basicConfig(level=level)

    uvloop.install()
    loop = asyncio.get_event_loop()
    servers, handler = loop.run_until_complete(main(args.handler))
    if servers:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
    asyncio.run(close(servers, handler))
