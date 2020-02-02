import asyncpg
import logging
import json

logger = logging.getLogger('ppp')

NASQ='''select * from networkaccess.nas where
          enabled and
          (identity = $2 and ip && $1::cidr) or
          (identity = '' and ip && $1::cidr)
           ORDER BY ip DESC NULLS LAST, identity DESC NULLS LAST LIMIT 1'''

USERQ = '''
select password,ip,bandwidth,routes from networkaccess.devices WHERE
    enabled and
    gid = $1 and
    (nas @> $2 or nas is null) and
    username = $3
'''

ADMINQ = '''select password,"group" from networkaccess.sysadmins WHERE
    gid = $1 and
    username = $2 and
    enabled;
    '''


async def conninit(conn):
        await conn.set_type_codec(
            'json',
            encoder=json.dumps,
            decoder=json.loads,
            schema='pg_catalog'
        )


class Handler:
    async def on_init(self):
        self.pool = await asyncpg.create_pool(
            database='bimo2019.12',
            user='postgres',
            command_timeout=10,
            init=conninit
            )

    async def on_nas(self, request):
        request.parse()
        ident = request['NAS-Identifier']
        ip = request.remote[0]
        async with self.pool.acquire() as conn:
            request.nas = await conn.fetchrow(NASQ, ip, ident)
        return dict(request.nas)

    async def on_close(self):
        await self.pool.close()

    async def on_preauth(self, request):
        pass

    async def on_preacct(self, request):
        pass

    async def on_auth(self, request, response):
        success = False
        if request['Service-Type'] == 1:
            async with self.pool.acquire() as conn:
                c = await conn.fetchrow(ADMINQ, request.nas['gid'], request['user-name'])
            if c:
                success = request.check_password(c['password'], response)
            if success:
                response['Mikrotik.Mikrotik-Group'] = c['group']
        else:
            async with self.pool.acquire() as conn:
                c = await conn.fetchrow(USERQ, request.nas['gid'], request.nas['id'], request['user-name'])
            logging.debug(c)
            if c:
                success = request.check_password(c['password'], response)
            if success:
                if c['ip']:
                    response['Framed-IP-Address'] = c['ip'].ip
                    response['Framed-IP-Netmask'] = c['ip'].netmask
                if c['bandwidth']:
                    rate = c["bandwidth"]
                    if request.nas['type'] == "mikrotik":
                        response['Mikrotik.Mikrotik-Rate-Limit'] = f'{rate}M {rate*5}M {rate*1.5}M 10'
                    else:
                        response['X-Ascend-Data-Rate'] = rate << 20
                if c['ippool']:
                    response['Framed-Pool'] = c['ippool']
                if c['routes']:
                    response['Framed-Route'] = c['routes']


        for k, v in response.items():
            logger.debug((k, v))
        return success

    async def on_acct(self, request, response):
        for k, v in response.items():
            logger.debug((k, v))

    async def on_accept(self, request, response):
        pass

    async def on_reject(self, request, response):
        pass