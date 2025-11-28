import argparse
import asyncio
import pathlib
import ssl
import platform

# if platform.system() == 'Linux':
#     import uvloop
# else:
#    uvloop == None

import importlib
import os, os.path
import importlib.util
import logging

from . import constants as C
from . import dictionary

from .handler import AbstractHandler
from .protocol import UDPProtocol, TCPProtocol, RadsecProtocol

import time
import multiprocessing
import socket
import setproctitle



def stream_process(protocol_factory, sock: socket.socket, ssl=None):
    addr = sock.getsockname()
    setproctitle.setproctitle(f'radius { "radsec" if ssl else "tcp" } {addr[0]}:{addr[1]}')
    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(
        loop.create_server(protocol_factory, sock=sock, ssl=ssl)
        )
    try:
        loop.run_forever()
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        # loop.run_until_complete(server.get_protocol().wait_closed())
        loop.close()

def stream_process_pool(protocol_factory, port, ssl=None, n=4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    processes = [ multiprocessing.Process(target=stream_process, args=(protocol_factory, sock, ssl), name=f"tcp {port} #{i}") for i in range(n) ]
    return processes


def udp_process(protocol_factory, sock):
    addr = sock.getsockname()
    setproctitle.setproctitle(f'radius udp {addr[0]}:{addr[1]}')
    loop = asyncio.new_event_loop()
    transport, protocol = loop.run_until_complete(
        loop.create_datagram_endpoint(protocol_factory, sock=sock)
        )
    try:
        loop.run_forever()
    finally:
        transport.close()
        loop.close()

def udp_process_pool(protocol_factory, port, n=4):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))
    processes = [ multiprocessing.Process(target=udp_process, args=(protocol_factory, sock), name=f"udp {port} #{i}") for i in range(n) ]
    return processes


async def main(**args):
    if args.get('tls_generate'):
         args['tls_regenerate'] = not (os.path.isfile(args['tls_cert']) and  os.path.isfile(args['tls_key']))
        
    if args.get('tls_regenerate'):
        from . import tlscert
        import socket
        c, k, cc, kk = tlscert.generate_selfsigned_ca(
                socket.gethostname()
                )
        os.makedirs(pathlib.Path(args['tls_ca_cert']).parent, exist_ok=True)
        with open(args['tls_ca_cert'], 'wb') as f:
            f.write(c)
        os.makedirs(pathlib.Path(args['tls_ca_key']).parent, exist_ok=True)
        with open(args['tls_ca_key'], 'wb') as f:
            f.write(k)
        c, k = tlscert.generate_selfsigned_cert(
                socket.gethostname(), ca=cc, cakey=kk
                )
        os.makedirs(pathlib.Path(args['tls_cert']).parent, exist_ok=True)
        with open(args['tls_cert'], 'wb') as f:
            f.write(c)
        os.makedirs(pathlib.Path(args['tls_key']).parent, exist_ok=True)
        with open(args['tls_key'], 'wb') as f:
            f.write(k)

    loop = asyncio.get_running_loop()
    servers = []

    if args.get('handler'):
        spec = importlib.util.spec_from_file_location("handler", args['handler'])
        if not spec:
            exit(1)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        Handler = mod.Handler
    elif args.get('handler_class'):
        Handler = args.get('handler_class')
    else:
        raise Exception('handler or handler_class required')
        
    t = time.time()
    dct = dictionary.Dictionary(args.get('dictionary', pathlib.Path(__file__).parent / 'dictionary' / 'dictionary'))
    logging.info(time.time()-t)

    handler_bases =  [Handler, AbstractHandler]

    if args.get('eap'):
        from .eap.session import EAP
        handler_bases =  [Handler, EAP]

    handler = lambda : type('Handler', tuple(handler_bases), {'c': C})(dct, args)

    if args.get('udp'):
        if args.get('eap'):
            udp_workers = 1
        else:
            udp_workers = args['workers']
        servers.extend(udp_process_pool(lambda: UDPProtocol(handler()), 1812, n=udp_workers))
        servers.extend(udp_process_pool(lambda: UDPProtocol(handler()), 1813, n=udp_workers))

    if args.get('tcp'):
        servers.extend(stream_process_pool(lambda: TCPProtocol(handler()), 1812, n=args['workers']))
        servers.extend(stream_process_pool(lambda: TCPProtocol(handler()), 1813, n=args['workers']))

    if args.get('tls'):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.check_hostname = False
        server_context.verify_mode = ssl.CERT_OPTIONAL

        try:
            server_context.load_cert_chain(
                    args['tls_cert'],
                    args['tls_key'])

        except FileNotFoundError as e:
            logging.critical("Certificates not found")
            raise e
        except Exception as e:
            raise e

        servers.extend(stream_process_pool(lambda: RadsecProtocol(handler()), 2083, ssl=server_context, n=args['workers']))
        servers.extend(stream_process_pool(lambda: RadsecProtocol(handler()), 2084, ssl=server_context, n=args['workers']))

    return servers


async def close(servers):
    for server in servers: server.terminate()
    for server in servers: server.join()
    for server in servers: server.close()


def run():
    #print(pathlib.Path(__file__))

    parser = argparse.ArgumentParser()
    parser.add_argument("handler", nargs='?')
    parser.add_argument("--dictionary", default=(pathlib.Path(__file__).parent / 'dictionary' / 'dictionary'))
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--journald", action="store_true")
    parser.add_argument("--verbosity", help="output verbosity", choices='DEBUG INFO WARNING ERROR FATAL'.split())
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--tcp", action="store_true")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--eap", action="store_true")
    parser.add_argument("--tls-regenerate", action="store_true")
    parser.add_argument("--tls-generate", action="store_true")
    parser.add_argument("--tls-ca-cert", default=(pathlib.Path(__file__).parent / 'certs' / 'ca_cert.pem' ))
    parser.add_argument("--tls-ca-key", default=(pathlib.Path(__file__).parent / 'certs' / 'ca_key.pem') )    
    parser.add_argument("--tls-cert", default=(pathlib.Path(__file__).parent / 'certs' / 'ssl_cert.pem' ))
    parser.add_argument("--tls-key", default=(pathlib.Path(__file__).parent / 'certs' / 'ssl_key.pem') )
    args = parser.parse_args()

    level = logging.ERROR
    if args.debug:
        level = logging.DEBUG
    if args.verbosity:
        level = getattr(logging, args.verbosity)
    if args.journald:
        from systemd import journal
        logging.basicConfig(level=level, handlers=[journal.JournalHandler(SYSLOG_IDENTIFIER='uradius')])
    else:
        logging.basicConfig(level=level)

    #uvloop.install()
    loop = asyncio.new_event_loop()
    servers = loop.run_until_complete(main(**vars(args)))

    for server in servers: server.start()

    if servers:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            loop.run_until_complete(close(servers))
        finally:
            loop.stop()
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
            
    

if __name__ == "__main__":
    run()
