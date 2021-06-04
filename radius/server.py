import argparse
import asyncio
import pathlib
import ssl
import uvloop
import importlib
import os
import importlib.util
import logging

from . import constants as C
from . import dictionary

from .handler import AbstractHandler
from .protocol import UDPProtocol, TCPProtocol, RadsecProtocol

import time


async def main(args):
    if args['tls_generate']:
        from . import tlscert
        import socket
        c, k = tlscert.generate_selfsigned_cert(
                socket.gethostname()
                )
        os.makedirs(pathlib.Path(args['tls_cert']).parent, exist_ok=True)
        with open(args['tls_cert'], 'wb') as f:
            f.write(c)
        os.makedirs(pathlib.Path(args['tls_key']).parent, exist_ok=True)
        with open(args['tls_key'], 'wb') as f:
            f.write(k)

    loop = asyncio.get_running_loop()
    servers = []

    #Handler = importlib.import_module(handlerclassname).Handler

    spec = importlib.util.spec_from_file_location("handler", args['handler'])
    if not spec:
        exit(1)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    Handler = mod.Handler
    t = time.time()
    dct = dictionary.Dictionary(args['dictionary'])
    logging.info(time.time()-t)

    handler_bases =  [Handler, AbstractHandler]

    if args['eap']:
        from .eap.session import EAP
        handler_bases.append(EAP)

    handler = type('Handler', handler_bases, {'c': C})(dct, loop, args)

    if args['udp']:
        servers.append((await loop.create_datagram_endpoint(
            lambda: UDPProtocol(loop, handler), local_addr=('0.0.0.0', 1812))))
        servers.append((await loop.create_datagram_endpoint(
            lambda: UDPProtocol(loop, handler), local_addr=('0.0.0.0', 1813))))

    if args['tcp']:

        server = await loop.create_server(lambda: TCPProtocol(loop, handler), '0.0.0.0', 1812)
        await server.start_serving()
        servers.append(server)
        server = await loop.create_server(lambda: TCPProtocol(loop, handler), '0.0.0.0', 1813)
        await server.start_serving()
        servers.append(server)


    if args['tls']:

        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.check_hostname = False
        server_context.verify_mode = ssl.CERT_NONE

        try:
            server_context.load_cert_chain(
                    args['tls_cert'],
                    args['tls_key'])

        except FileNotFoundError as e:
            logging.critical("Certificates not found")
            raise e
        except Exception as e:
            raise e

        server = await loop.create_server(lambda: RadsecProtocol(loop, handler), '0.0.0.0', 2083, ssl=server_context)
        await server.start_serving()
        servers.append(server)


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


def run():
    #print(pathlib.Path(__file__))

    parser = argparse.ArgumentParser()
    parser.add_argument("handler", nargs='?')
    parser.add_argument("--dictionary", default=(pathlib.Path(__file__).parent / 'dictionary' / 'dictionary'))
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--verbosity", help="output verbosity", choices='DEBUG INFO WARNING ERROR FATAL'.split())
    parser.add_argument("--tcp", action="store_true")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--eap", action="store_true")
    parser.add_argument("--tls-generate", action="store_true")
    parser.add_argument("--tls-cert", default=(pathlib.Path(__file__).parent / 'certs' / 'ssl_cert.pem' ))
    parser.add_argument("--tls-key", default=(pathlib.Path(__file__).parent / 'certs' / 'ssl_key.pem') )
    args = parser.parse_args()

    level = logging.ERROR
    if args.debug:
        level = logging.DEBUG
    if args.verbosity:
        level = getattr(logging, args.verbosity)

    logging.basicConfig(level=level)

    #uvloop.install()
    loop = asyncio.get_event_loop()
    servers, handler = loop.run_until_complete(main(vars(args)))
    if servers:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
    asyncio.run(close(servers, handler))

if __name__ == "__main__":
    run()
