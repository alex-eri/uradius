from radius.constants import AccessRequest,AccessAccept,AccessReject
import multiprocessing


class Handler:

    # хандлер один на все запросы, атрибуты повешанные на self могут перезаписаться

    async def on_init(self, args):
        # тут создаешь инстанс базы - запускается один раз на воркер
        # базу вешаешь на self
        pass

    async def on_nas(self, request):
        # request словарь-подобный объект ключ принимает строковой и цифровой из словаря
        # для обычных атрибутов "Framed-IP-Address" или 8
        # для вендорных "Microsoft.MS-CHAP-Challenge" или (tuple) (311, 11)
        called = request['Called-Station-Id']

        if request['MIKROTIK.MIKROTIK-HOST-IP']:
            nastype = 'mikrotik'
        else:
            nastype = 'un'
        # тут делаешь запрос к базе по called и в ответ выдаешь словарь с 'secret' для этого наса и любыми дополнительными атрибутами ретурном.
        # эти ответы кешируются
        # словарь доступен в request.nas
        return {'secret':'testing123', 'admin': 0, 'type': nastype}



    async def on_framed(self , request, response, username):
        print(multiprocessing.current_process())
        # тут делай запрос к базе, верни AccessReject или AccessAccept и словарь с атрибутами и паролем
        print(request.remote)
        for k,v in request.items():
            print(k.name, v)

        admin = request.nas['admin'] # свободные атрибуты наса тут
        passw = 'test' # пароль равен маку
        code = AccessReject
        return code, {'bandwidth':10, 'timeout': 3600, 'password': passw }


    async def on_reject(self , request, response):
        # вызывается перед отправкой ответа
        print('on_reject')
        for k,v in response.items():
            print(k.name, v)
        return

    async def on_accept(self , request, response):
        # вызывается перед отправкой ответа, тут можно сформировать радиус сессию и записать её в бд
        print('on_accept')
        for k,v in response.items():
            print(k.name, v)
        return

    async def on_close(self):
        pass


    async def on_reply(self, request, responce, send_coa):
        # вызывается после отправки пакета
        # send_coa() - async функция для отправки coa,
        # coa_req = request.coa(CoARequest)
        # coa_res = await send_coa(coa_req)
        pass

    async def on_acct(self, request, response):
        # аккаунтинг
        print('acct',request.remote)
        for k,v in request.items():
            print(k.name, v)
        return

