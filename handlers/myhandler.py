import logging
logger = logging.getLogger('my')


class Handler:
    async def on_init(self):
        pass

    async def on_nas(self, request):
        return {'secret': b'testing123'}

    async def on_close(self):
        pass

    async def on_preauth(self, request):
        for k, v in request.items():
            logger.debug((k, v))
        pass

    async def on_preacct(self, request):
        for k, v in request.items():
            logger.debug((k, v))

    async def on_auth(self, request, response):
        sucess = request.mschap2('132')
        if sucess:
            response['Microsoft.MS-CHAP2-Success'] = sucess
#        response["Mikrotik.Mikrotik-RealM"] = "gg"
#        response[16] = 8000
#        response[(14559, 8)] = "2"
        for k, v in response.items():
            logger.debug((k, v))
        return sucess and True or False

    async def on_acct(self, request, response):
        for k, v in response.items():
            logger.debug((k, v))

    async def on_accept(self, request, response):
        pass

    async def on_reject(self, request, response):
        pass
