import asyncpg
import json

import logging
logger = logging.getLogger('handler')

"""
CREATE USER uradius WITH PASSWORD '8d757i6d46w';
CREATE DATABASE bimo2021 OWNER uradius;


CREATE TABLE IF NOT EXISTS nas (
    id bigserial,
    gid uuid default 'fa95da59-5d34-42b2-91cc-62083cde7b8f',
    identity text,
    ip cidr default '0.0.0.0/0',
    secret text
);

CREATE TABLE IF NOT EXISTS devices (
    enabled boolean,
    gid uuid default 'fa95da59-5d34-42b2-91cc-62083cde7b8f',devices
    nas bigint

);



"""

class Handler:
    NASQ='''select sercet, admin_id from nas where
              enabled and
              called = $1
               ORDER BY id DESC NULLS LAST, called DESC NULLS LAST LIMIT 1'''

    ABONQ = '''
    select bandwidth,time_range, from devices WHERE
        enabled and
        admin_id = $1 and
        called = $2 and
        username = $3,
        time_range @> now()
    '''

    ADMINQ = '''select password,"group" from sysadmins WHERE
        gid = $1 and
        username = $2 and
        enabled;
        '''

    async def on_init(self, args):
        async def conninit(conn):
            await conn.set_type_codec(
                'json',
                encoder=json.dumps,
                decoder=json.loads,
                schema='pg_catalog'
            )

        self.pool = await asyncpg.create_pool(
            database='bimo2021',
            user='uradius',
            password='8d757i6d46w',
            command_timeout=10,
            init=conninit
            )
        logger.info('handler ready')
        # set peap
        self.method = 25 #PEAP


    async def on_nas(self, request):
        """
        if secret for NAS not cached, return secret
        """
        ident = request['NAS-Identifier']
        ip = request.remote[0]
        async with self.pool.acquire() as conn:
            nas = await conn.fetchrow(self.NASQ, ip, ident)
        if nas:
            return dict(nas)
        else:
            return None

    async def on_close(self):
        """
        Disconnect database here
        """
        await self.pool.close()


    async def on_framed(self , request, response, username):
        """
        return password, ip/mask, routes, ippool
        """
        async with self.pool.acquire() as conn:
            c = await conn.fetchrow(self.USERQ, request.nas['gid'], request.nas['id'], username)
            logger.debug(c)
            return c

    async def on_reject(self , request, response):
        pass
    async def on_accept(self , request, response):
        pass


    async def on_login(self , request, response, username):
        """
        return password, group
        """
        raise NotImplementedError


    async def on_acct(self , request, response):
        """
        Acc
        """
        raise NotImplementedError
