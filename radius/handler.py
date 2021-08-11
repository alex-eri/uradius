import asyncio
from .constants import *
from .dictionary import Attr

import logging
logger = logging.getLogger('handler')


class InternalHandler:
    def __init__(self, dct, args, *a, **kw):
        loop = asyncio.get_running_loop()
        self.d = self.dict = self.dictionary = dct
        self.attributes = {}
        if dct:
            self.attributes = dct.attributes
        self.ready = loop.create_task(self.on_init(args))

    async def on_auth(self, request, response):
        success = False

        if request['EAP-Message']:
            success = await self.on_eap(request, response)
            if success != AccessAccept:
                return success

        success, c = await self.on_framed(request, response, request['user-name'])
        if success != AccessReject and c.get('password'):
            success = request.check_password(c['password'], response)
            if not success:
                response['Reply-Message'] = 'bad password'

        if success:
            if c.get('ip'):
                response['Framed-IP-Address'] = c['ip'].ip
                response['Framed-IP-Netmask'] = c['ip'].netmask
            if c.get('bandwidth'):
                rate = c["bandwidth"]
                if request.nas['type'] == "mikrotik" and rate >= 1:
                    bust, to = int(rate*3), int(rate*1)
                    rate = int(rate)
                    response['Mikrotik.Mikrotik-Rate-Limit'] = f'{rate}M {bust}M {to}M 10'
                else:
                    rate = int(rate)
                    response['X-Ascend-Data-Rate'] = rate << 20
            if c.get('ippool'):
                response['Framed-Pool'] = c['ippool']
            if c.get('routes'):
                response['Framed-Route'] = c['routes']
            if c.get('timeout'):
                response['Session-Timeout'] = c['timeout']

            for k,v in c.items():
                if isinstance(k, Attr):
                    response[k] = v

        return success



class AbstractHandler(InternalHandler):

    async def on_eap(self, request, response):
        raise NotImplementedError('Enable EAP (--eap argument)')

    async def on_init(self, args):
        """
        After creating instance of handler. Connect to database here
        """
        for k,v in args.items():
            print(k, v)
        raise NotImplementedError('async def on_init(self, args)')


    async def on_nas(self, request):
        """
        if secret for NAS not cached, return secret
        """
        for k,v in request.items():
            print(k.name, v)
        raise NotImplementedError('async def on_nas(self, request)')

    async def on_close(self):
        """
        Disconnect database here
        """
        pass


    async def on_framed(self , request, response, username):
        """
        return password, ip/mask, routes, ippool
        """
        for k,v in request.items():
            print(k.name, v)
        raise NotImplementedError('async def on_framed(self , request, response, username)')


    async def on_login(self , request, response, username):
        """
        return password, group
        """
        for k,v in request.items():
            print(k.name, v)
        raise NotImplementedError


    async def on_acct(self , request, response):
        """
        Acc
        """
        for k,v in request.items():
            print(k.name, v)
        raise NotImplementedError('async def on_acct(self , request, response)')


    async def on_reject(self , request, response):
        for k,v in response.items():
            print(k.name, v)
        return

    async def on_accept(self , request, response):
        for k,v in response.items():
            print(k.name, v)
        return

    async def on_reply(self, request, response, send_coa):
        return
        if request.Code == AccountingRequest:
            coa_req = request.coa(CoARequest)
            coa_req['X-Ascend-Data-Rate'] = 1 << 20
            coa_res = await send_coa(coa_req)
