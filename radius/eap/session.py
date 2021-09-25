import secrets
import ssl
import asyncio
import struct
import radius.sslkeylog as sslkeylog
from cachetools import TTLCache
from asyncache import cached
import traceback

from radius.constants import *

from radius import mschap

import logging
logger = logging.getLogger('eap')

class EAP_TLS:

    def __init__(self, context, *a, **kw):
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self.sslo = context.wrap_bio(self._in, self._out, server_side=True)
        self.start = 1

    def unwrap(self):
        return self.sslo.unwrap()

    def pending(self):
        return self.sslo.pending()

    def out_pending(self):
        return self._out.pending

    def read(self, *a, **kw):
        r = self.sslo.read(*a, **kw)
        return r

    def write(self, data, *a, **kw):
        if data:
            return self.sslo.write(data, *a, **kw)

    def feed(self, data):
        self.start = 0
        return self._in.write(data)

    def pull(self):
        try:
            hs = self.sslo.do_handshake()
            print('ready', hs)

        except ssl.SSLWantReadError as e:
            print('ssl want read')
            pass
        o = self._out.read(1024)
        return o


class EAP_Session:
    def __init__(self, context, method=PEAP, *a, **kw):
        self.code1 = Request
        self.code2 = Request
        self.data = dict()
        self.resp = dict()
        self.tls = EAP_TLS(context)
        self.phase = 0
        self.ident = 0
        self.user = None
        self.success = False
        self.keys = None
        self.finished2 = False
        self.finished1 = False
        self.method = method
        self.tail = b''
        self.on_user = asyncio.Future()
        self.on_data = asyncio.Future()
        self.started = False
        self.tls_ready = False

    async def phase1(self, data):
        t = data[0]
        body = data[1:]
        if t == Identity:
            self.data['Identity'] = body.decode('utf8')
            self.code1 = Request
        elif t == PEAP or t == EAPTLS:
            flags = body[0]
            # TLSFlags = flags
            more = flags & 0x40
            TLS = b''
            l = 0
            if flags & 0x80:
                l = int.from_bytes(body[1:5], 'big')
                if l:
                    TLS = body[5:l+5]
                else:
                    TLS = body[5:]
            else:
                TLS = body[1:]

            self.tls.feed(TLS)
            try:
                if not more:
                    to_write = await self.phase2()
                    if to_write:
                        self.tls.write(to_write)
            except ssl.SSLWantReadError:
                self.code1 = Request
            if self.finished2:
                self.tls.write(b'')
                if self.finished1:
                    self.code1 = Success
                self.finished1 = True

    def phase2start(self):
        print('p2strat')
        self.challenge = secrets.token_bytes(16)
        self.chapid = self.ident
        ms_data = mschap.create_plain_text(self.challenge, pad=False) + b'bimo'
        return bytearray([MSCHAPV2, Challenge, self.chapid]) + (4 + len(ms_data)).to_bytes(2, 'big') + ms_data


    async def phase2(self):
        self.phase = 2
        data = self.tail + self.tls.read()
        if self.method == EAPTLS:
            self.code2 = Success
            self.success = True
            self.finished2 = True
        if not data:
            return b''
        try:
            t = data[0]
            body = data[1:]
            if t == Identity:
                self.code2 = Request
                self.user = body.decode()
            elif t == MSCHAPV2:
                logger.debug("MSCHAPV2: %s", body.hex())
                OpCode = body[0]
                if OpCode == Success:
                    if self.success:
                        self.finished2 = True
                    return b''
                MS_CHAPv2_ID = body[1]
                MS_Length = int.from_bytes(body[2:4], 'big')
                Value_Size = body[4]
                Response = body[5:5+Value_Size]
                PeerChallenge = Response[:16]
                NTResponse = Response[24:-1]
                Flags = Response[48]
                User = body[5+Value_Size:]
                self.user = User.decode()
                self.on_user.set_result(self.user)
                db_code, db_data = await self.on_data
                if db_data.get('password'):
                    password = db_data.get('password')
                    auth_resp = self.mschap2(password, PeerChallenge, NTResponse, self.challenge, User)
                else:
                    self.code2 = Failure
                    ms_data = "E=0000000647 R=0 C=" + self.challenge.hex() + " V=3 M=FAILED"
                    return bytearray([MSCHAPV2, Failure, MS_CHAPv2_ID]) +(4 + len(ms_data)).to_bytes(2, 'big') + ms_data.encode()
                if auth_resp:
                    self.code2 = Success
                    self.success = True
                    ms_data = auth_resp.encode() + b' M=OK'
                    return bytearray([MSCHAPV2, Success, MS_CHAPv2_ID]) + (4 + len(ms_data)).to_bytes(2, 'big') + ms_data
                else:
                    self.code2 = Failure
                    ms_data = "E=0000000691 R=0 C=" + self.challenge.hex() + " V=3 M=FAILED"
                    return bytearray([MSCHAPV2, Failure, MS_CHAPv2_ID]) + (4 + len(ms_data)).to_bytes(2, 'big') + ms_data.encode()
            return b''
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            self.tail = data


    def mschap2(self, cleartext, peer_challenge, nt_response, authenticator_challenge, user):
        print(cleartext, peer_challenge, nt_response, authenticator_challenge, user)
        success = mschap.generate_nt_response_mschap2(
            authenticator_challenge,
            peer_challenge,
            user,
            cleartext) == nt_response
        if success:
            auth_resp = mschap.generate_authenticator_response(
                cleartext,
                nt_response,
                peer_challenge,
                authenticator_challenge,
                user)
            return auth_resp[1:]

    async def on_message(self, message):
        print(id(self))
        code, ident, length = message[0], message[1], message[2] << 8 | message[3]
        self.ident = ident
        await self.phase1(message[4:length])
        if self.code1 == Request:
            self.ident = (ident+1) % 256
        print(self.tls.sslo.get_channel_binding() , self.phase , length )
        if self.started:
            pass
        elif self.tls_ready:
            self.started = True
            if self.method == PEAP:
                body2 = self.phase2start()
                # TODO Nak
                data2 = bytearray([self.code2, self.ident]) + (4 + len(body2)).to_bytes(2, 'big') + body2
                self.tls.write(body2)
        elif self.tls.sslo.get_channel_binding():
            print('ready')
            self.tls_ready = True
        if self.code1 == Success:
            body = b''
        else:
            tls_data = self.tls.pull()
            more = self.tls.out_pending() and 1
            if self.method == PEAP:
                flags = more << 6 | self.tls.start << 5 | PEAP_version
                body = bytearray([PEAP, flags])
            if self.method == EAPTLS:
                flags = more << 6 | self.tls.start << 5
                body = bytearray([EAPTLS, flags])
            body += tls_data
        data = bytearray([self.code1, self.ident]) + (4 + len(body)).to_bytes(2, 'big') + body
        return data

import radius.handler

class EAP(radius.handler.AbstractHandler):
    def __init__(self, dct, args,  *a, **kw):
        logger.debug('init')
        super().__init__( dct, args, *a, **kw)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.keylog_filename = "/tmp/sslkey.log"
        context.load_cert_chain(certfile=args['tls_cert'], keyfile=args['tls_key'])
        self.ctx = context
        self.session_cache = TTLCache(10000, 10)
        self.method = PEAP

    async def on_eap(self, request, response):

        ### eap воркеры будут жить отдельно, воркер выбирается через `(request.Identifier, *request.remote).__hash__() % n`
        ###
        ### соединение по двум парам очередей. одна для еапа, вторая для узера

#        def on_user(r):
#            asyncio.ensure_future(
#                self.on_framed(request, response, r.result())
#            ).add_done_callback(lambda r: )

        userdata = {}

        message = request['EAP-Message']
        key = (message[1], request['NAS-IP-ADDRESS'], request[44], request.remote[0])
        sess = self.session_cache.pop(key, None) or EAP_Session(self.ctx, self.method)
        key = ((message[1]+1) % 256, request['NAS-IP-ADDRESS'], request[44], request.remote[0])
        if sess.code1 == Request:
            self.session_cache[key] = sess
        resp = asyncio.ensure_future(sess.on_message(message))
        tasks = [resp]
        if not sess.on_user.done():
            tasks.append(sess.on_user)

        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if sess.on_user.done():
            if sess.on_data.done():
                code, userdata = sess.on_data.result()
            else:
                code, userdata = await self.on_framed(request, response, await sess.on_user)
                sess.on_data.set_result((code, userdata))

        request['user-name'] = sess.user
        response['EAP-Message'] = await resp

        if sess.code1 == Success:
            salt = mschap.create_salt()
            material = sslkeylog.export_keying_material(sess.tls.sslo, 4 * EAP_TLS_MPPE_KEY_LEN, "client EAP encryption")
            recvkey = material[:EAP_TLS_MPPE_KEY_LEN]
            sendkey = material[EAP_TLS_MPPE_KEY_LEN:EAP_TLS_MPPE_KEY_LEN*2]
            emsk = material[EAP_TLS_MPPE_KEY_LEN*2:EAP_TLS_MPPE_KEY_LEN*4]
            SessionId = bytes([PEAP]) + sslkeylog.get_client_random(sess.tls.sslo) + sslkeylog.get_server_random(sess.tls.sslo)
            sendkey = mschap.create_plain_text(sendkey)
            recvkey = mschap.create_plain_text(recvkey)
            sendkeye = mschap.radius_encrypt_keys(sendkey, request.secret, request.RequestAuthenticator, salt)
            recvkeye = mschap.radius_encrypt_keys(recvkey, request.secret, request.RequestAuthenticator, salt)
            response['Microsoft.MS-MPPE-Send-Key'] = salt + sendkeye
            response['Microsoft.MS-MPPE-Recv-Key'] = salt + recvkeye
            response[102] = SessionId #'EAP-Key-Name'
        if sess.code1 == Success:
            return AccessAccept, userdata
        if sess.code1 == Failure:
            return AccessReject, userdata
        return AccessChallenge, userdata
