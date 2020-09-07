class AbstractHandler:
    def __init__(self, dct, loop, args, *a, **kw):
        super().__init__(*a, **kw)
        self.d = self.dict = self.dictionary = dct
        self.attributes = {}
        if dct:
            self.attributes = dct.attributes
        self.ready = loop.create_task(self.on_init(args))

    async def on_init(self):
        """
        After creating instance of handler. Connect to database here
        """
        raise NotImplementedError

    async def on_nas(self, request):
        """
        if secret for NAS not cached, return secret
        """
        raise NotImplementedError

    async def on_preauth(self, request):
        """
        packet is valid, do username canonization and similar stuff here
        """
        raise NotImplementedError

    async def on_auth(self, request, response):
        """
        check database and set response attributes here
        """
        raise NotImplementedError

    async def on_accept(self, request, response):
        """
        insert accounting cookie, insert session in database
        """
        raise NotImplementedError

    async def on_reject(self, request, response):
        """
        called if response type reject
        """
        raise NotImplementedError

    async def on_postauth(self, request, response):
        """
        just before send answer
        """
        raise NotImplementedError

    async def on_close(self):
        """
        On server shutdown
        """
        raise NotImplementedError

    async def on_preacct(self, request):
        """
        packet is valid, do username canonization and similar stuff here
        """
        raise NotImplementedError

    async def on_acct(self, request, response):
        """
        write database and set response attributes here
        """
        raise NotImplementedError
