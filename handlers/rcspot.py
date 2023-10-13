from radius.constants import AccessRequest,AccessAccept,AccessReject,AccountingRequest
from datetime import datetime, timezone
import asyncpg
import json
from uuid import uuid4
import logging
logger = logging.getLogger('handler')


class Handler:
    NASQ = "SELECT secret, user_id FROM nas_check($1, $2);"
    USERQ = "SELECT bandwidth, not_after, service_id from auth_check($1, $2, $3)"

    async def on_init(self, args):
        async def conninit(conn):
            await conn.set_type_codec(
                'json',
                encoder=json.dumps,
                decoder=json.loads,
                schema='pg_catalog'
            )

        self.pool = await asyncpg.create_pool(
            host='localhost',
            ssl=False,
            database='rcspot',
            user='radius',
            password='132132',
            command_timeout=10,
            init=conninit
            )
        logger.info('handler ready')

    async def on_nas(self, request):
        called = request['Called-Station-Id']
        if request['MIKROTIK.MIKROTIK-HOST-IP']:
            nastype = 'mikrotik'
        else:
            nastype = 'hz'
        async with self.pool.acquire() as conn:
            nas = await conn.fetchrow(self.NASQ, called, request.remote[0])
        if nas:
            return {'secret': nas['secret'], 'gid': nas['user_id'] , 'type': nastype}
        raise Exception('Unknown NAS', request.remote, called)

    async def on_framed(self , request, response, username):
        passw = request['Calling-Station-Id']
        code = AccessReject
        ret = {}
        async with self.pool.acquire() as conn:
           c = await conn.fetchrow(self.USERQ, username, request['Called-Station-Id'], request.nas['gid'])
        if c:
            code = AccessAccept
            timeout = (c['not_after'] - datetime.now(timezone.utc)).seconds
            ret = {
                'bandwidth': c['bandwidth'],
                'timeout': timeout,
                'password': passw
            }
            
            response['Class'] = uuid4().bytes
            
            await conn.execute('insert into rcspot.accounting (identity, called, class, service, username, start) values ($1,$2,$3,$4,%5,%6)',
                request['NAS-Identifier'],
                request['Called-Station-Id'],
                response['Class'],
                c['service_id'],
                username,
                datetime.now(timezone.utc)
                )
        else:
            ret = {
                self.d['Reply-Message']: "not found"
            }
        return code, ret

    async def on_close(self):
        await self.pool.close()
        
    async def on_accept(self, request, response):
        pass 


    async def on_acct(self, request, response):
        # аккаунтинг
        
        inbytes = request.as_uint32('Acct-Input-Gigawords') << 32 + request.as_uint32('Acct-Input-Octets')
        outbytes = request.as_uint32('Acct-Output-Gigawords') << 32 + request.as_uint32('Acct-Output-Octets')
        
        async with self.pool.acquire() as conn:
            if request['Acct-Status-Type'] == seld.d('Acct-Status-Type').choices('Acct-Status-Type'):
                await conn.execute('update rcspot.accounting set start=%3 where class=%1 and username=%2',
                    request['Class'],
                    request['User-Name'],
                    request['Event-Timestamp']
                )
            await conn.execute('update rcspot.accounting set sensor=%3, octets=%4, packets=%5, session_time=%6, stop=%7 where class=%1 and username=%2',
                request['Class'],
                request['User-Name'],
                request.remote[0],
                [inbytes,outbytes],
                [request.as_uint32('Acct-Input-Packets'), request.as_uint32('Acct-Output-Packets')],
                request['Acct-Session-Time'],
                request['Event-Timestamp']
            )
              

        print('acct',request.remote)
        for k,v in request.items():
            print(k.name, v)
        return

