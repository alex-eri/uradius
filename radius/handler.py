from .constants import *

from .dictionary import Attr

import logging
logger = logging.getLogger('handler')


class InternalHandler:
    def __init__(self, dct, loop, args, *a, **kw):
        self.d = self.dict = self.dictionary = dct
        self.attributes = {}
        if dct:
            self.attributes = dct.attributes
        self.ready = loop.create_task(self.on_init(args))


    async def on_auth(self, request, response):
        success = False

        # if request['Service-Type'] == ServiceTypeLogin:
        #     c = await self.on_login(request, response, request['user-name'])
        #     if c:
        #         success = request.check_password(c['password'], response)
        #     if success and c.get('group'):
        #         response['Mikrotik.Mikrotik-Group'] = c.get('group')
        #     return success

        # elif request['Service-Type'] == ServiceTypeFramed or request['Service-Type'] is None:
        if True:
            if request['EAP-Message']:
                success = await self.on_eap(request, response)
                if success != AccessAccept:
                    return success

            success, c = await self.on_framed(request, response, request['user-name'])
            if c.get('password'):
                success = request.check_password(c['password'], response)

            if success:
                if c.get('ip'):
                    response['Framed-IP-Address'] = c['ip'].ip
                    response['Framed-IP-Netmask'] = c['ip'].netmask
                if c.get('bandwidth'):
                    rate = c["bandwidth"]
                    if request.nas['type'] == "mikrotik" and rate >= 1:
                        bust, to = int(rate*5), int(rate*1.5)
                        rate = int(rate)
                        response['Mikrotik.Mikrotik-Rate-Limit'] = f'{rate}M {bust}M {to}M 10'
                    else:
                        rate = int(rate)
                        response['X-Ascend-Data-Rate'] = rate << 20
                if c.get('ippool'):
                    response['Framed-Pool'] = c['ippool']
                if c.get('routes'):
                    response['Framed-Route'] = c['routes']

                for k,v in c.items():
                    if isinstance(k, Attr):
                        response[k] = v

        return success



class AbstractHandler(InternalHandler):

    async def on_eap(self, request, response):
        raise NotImplementedError

    async def on_init(self, args):
        """
        After creating instance of handler. Connect to database here
        """
        raise NotImplementedError


    async def on_nas(self, request):
        """
        if secret for NAS not cached, return secret
        """
        raise NotImplementedError

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
            print(k,v)
        raise NotImplementedError


    async def on_login(self , request, response, username):
        """
        return password, group
        """
        for k,v in request.items():
            print(k,v)
        raise NotImplementedError


    async def on_acct(self , request, response):
        """
        Acc
        """
        for k,v in request.items():
            print(k,v)
        raise NotImplementedError


    async def on_reject(self , request, response):
        return

    async def on_accept(self , request, response):
        return

