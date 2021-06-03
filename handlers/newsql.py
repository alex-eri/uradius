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
    NASQ='''select * from nas where
              enabled and
              (identity = $2 and ip && $1::cidr) or
              (identity IS NULL and ip && $1::cidr)
               ORDER BY masklen(ip) DESC NULLS LAST, identity DESC NULLS LAST LIMIT 1'''

    USERQ = '''
    select * from devices WHERE
        enabled and
        gid = $1 and
        ( $2 = ANY(nas) or nas is null) and
        username = $3
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
