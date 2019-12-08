import struct
import constants as C
import hmac, hashlib
import ipaddress
import os
import itertools
from datetime import datetime
import dictionary
import logging
from collections import defaultdict
Identifiers = itertools.cycle(range(256))


class Multidict(defaultdict):
    def __init__(self):
        super(Multidict, self).__init__(list)

    # def __missing__(self, key):
    #     self
    #     return list()

    def __setitem__(self, key, value):
        if isinstance(value, (list)):
            super().__setitem__(key, value)
        else:
            super().__setitem__(key, [value])

    def append(self, key, value):
        self[key].append(value)

    def reset(self, key, value):
        self[key] = [value]

    def items(self):
        for k in self.keys():
            for v in self[k]:
                yield (k, v)


class Packet:
    def __init__(self, data=b'', remote=None, secret=None, dictionary=None):
        self.d = dictionary
        self.remote = remote
        self.secret = secret

        if data:
            self.__data = data
        else:
            self.__data = struct.pack('!BBH16s', 0, next(Identifiers), 20, os.urandom(16))
        self.__data = bytearray(self.__data)
        self.__attrs = Multidict()
        self.__ma_cursor = None
        self.__reply = None

    def items(self):
        if not self.__attrs and self.__data[2]:
            self.parse()
        if self.d:
            for k, v in self.__attrs.items():
                if not isinstance(k, dictionary.Attribute):
                    k = self.d.attributes(k)
                yield k, self.decode(k, v)
        else:
            for k, v in self.__attrs.items():
                yield k, v

    def reply(self, code=C.AccessReject):
        if not self.__reply:
            data = self.__data[:20]
            data[0] = code
            self.__reply = Packet(
                data=data,
                secret=self.secret,
                dictionary=self.d
                )
            if self.__ma_cursor:
                self.__reply[C.MessageAuthenticator] = None

        return self.__reply

    @property
    def Code(self):
        return self.__data[0]

    @Code.setter
    def Code(self, v):
        self.__data[0] = v

    @property
    def Identifier(self):
        return self.__data[1]

    @property
    def RequestAuthenticator(self):
        return self.__data[4:20]

    def __getitem__(self, key):
        key = key.upper()
        if not self.__attrs and self.__data[2]:
            self.parse()
        if self.__attrs[key]:
            return self.__attrs[key][-1]

    def __setitem__(self, k, v):
        if self.d:
            if type(k) == str:
                k = self.d.attributes[k.upper()]
            if type(k) in [int, tuple]:
                k = self.d.attributes(k)
        self.__attrs[k] = v

    @property
    def Attributes(self):
        if not self.__attrs:
            self.parse()
        return self.__attrs

    def check(self):
        if not self.__attrs:
            self.parse()

        if self.__ma_cursor:
            d = self.get_message_authenticator(self.__ma_cursor)
            if d != self.__attrs[C.MessageAuthenticator][0]:
                raise Exception('MessageAuthenticator not valid')

    def get_message_authenticator(self, cursor):
        m = hmac.HMAC(key=self.secret, digestmod=hashlib.md5)
        m.update(self.__data[:cursor])
        m.update(bytes(16))
        m.update(self.__data[cursor+16:])
        return m.digest()

    def parse(self):
        cursor = 20
        while cursor < len(self.__data):
            k, l = struct.unpack_from('!BB', self.__data, cursor)
            cursor += 2
            if k == 26:
                v, t, l = struct.unpack_from('!LBB', self.__data, cursor)
                k = (v, t)
                cursor += 6
            l2 = l-2
            v = self.__data[cursor:cursor+l2]
            if k == C.MessageAuthenticator:
                self.__ma_cursor = cursor

            self.__attrs[k] += [v]
            cursor += l2

    def decript1(self, v):
        last = self.RequestAuthenticator.copy()
        buf = v
        pw = b''
        while buf:
            hash = hashlib.md5(self.secret + last).digest()
            for i in range(16):
                pw += bytes((hash[i] ^ buf[i],))

            (last, buf) = (buf[:16], buf[16:])

        pw = pw.rstrip(b'\x00')
        return pw

    def set(self, key, value):
        """
        Set attribute to speciefed value. If attribute exists new attribute inserted.
        """
        self.__attr[key] = value

    def reset(self, key, value):
        """
        Reset attribute to speciefed value
        """
        self.__attrs.reset(key, value)

    def decode(self, k, v):
        """
        The type field can be one of the standard types:


         string       UTF-8 printable text (the RFCs call this "text")
         octets       opaque binary data (the RFCs call this "string")
         ipaddr       IPv4 address
         date         Seconds since January 1, 1970 (32-bits)
         integer      32-bit unsigned integer
         ipv6addr     IPv6 Address
         ipv6prefix   IPV6 prefix, with mask
         ifid         Interface Id (hex:hex:hex:hex)
         integer64    64-bit unsigned integer
        The type field can be one of the following non-standard types:


         ether        Ethernet MAC address
         abinary      Ascend binary filter format
         byte         8-bit unsigned integer
         short        16-bit unsigned integer
         signed       31-bit signed integer (packed into 32-bit field)
         tlv          Type-Length-Value (allows nested attributes)
         ipv4prefix   IPv4 Prefix as given in RFC 6572.
        """

        if isinstance(v, bytearray):
            typ, flags = k.value.type
            if 'has_tag' in flags:
                logging.warning(f'Tags not supported')
            if 'encrypt=1' in flags:
                v = self.decript1(v)
            if 'concat' in flags and len(self.__attr[k]) > 1:
                v = [bytearray().join(self.__attr[k])]
                self.__attr.reset(k, v)

            if typ in ['octets', 'ipaddr', 'ipv6addr', 'ether', 'ipv6prefix', 'ipv4prefix']:
                v = bytes(v)
                if typ in ['ipaddr', 'ipv6addr']:
                    v = ipaddress.ip_address(v)
                elif typ == 'ether':
                    v = dictionary.MACAddress(v)
                elif typ == 'ipv4prefix':
                    v = ipaddress.IPv4Network((v[2:], v[1]))
                elif typ == 'ipv6prefix':
                    v = ipaddress.IPv6Network(((v[2:]+bytes(16))[:16], v[1]))

            elif typ == 'string':
                v = v.decode()
            elif typ in ['integer', 'integer64', 'short', 'byte', 'date', 'ifid']:
                v = int.from_bytes(v, 'big')
                if typ == 'date':
                    v = datetime.fromtimestamp(v)
            elif typ == 'signed':
                v = int.from_bytes(v, 'big', True)
            else:
                logging.warning(f'Type "{typ}" not supported')

        return v

    @staticmethod
    def encode(v):
        if isinstance(v, bytes):
            return v
        elif isinstance(v, bytearray):
            return bytes(v)
        elif isinstance(v, int):
            return struct.pack("!L",v)
        elif isinstance(v, str):
            return v.encode('utf8')
        elif isinstance(v, ipaddress.IPv4Address):
            return v.packed

    def build(self):

        resp = self.__data[:20].copy()
        body = bytearray()
        for k, v in self.__attrs.items():
#            if isinstance(k, dictionary.Enum):
#                k = k.value
            if k == C.MessageAuthenticator:
                continue
            v = Packet.encode(v)
            length = len(v)
            while length > 0:
                if isinstance(k, int):
                    if length > 253:
                        cut = 253
                    else:
                        cut = length
                    key = (k, cut + 2)
                elif isinstance(k, tuple):
                    if length > 249:
                        cut = 249
                    else:
                        cut = length
                    key = struct.pack("!BBLBB", 26, cut+8, k[0], k[1], cut+2)
                else:
                    break
                body.extend(key)
                body.extend(v[:cut])
                v = v[cut:]
                length -= cut

        ma_cursor = 0
        if self.__data[0] in \
                (C.AccessRequest, C.AccessAccept, C.AccessReject, C.AccessChallenge):

            if C.MessageAuthenticator in self.__attrs.keys():
                ma_cursor = len(body)+2
                body.extend((C.MessageAuthenticator, 18))
                body.extend(bytes(16))

        struct.pack_into("!H", resp, 2, 20+len(body))
        resp.extend(body)

        self.__data = resp

        if ma_cursor:
            ma_cursor += 20
            message_authenticator = self.get_message_authenticator(ma_cursor)
            self.reset(C.MessageAuthenticator, message_authenticator)
            resp[ma_cursor:ma_cursor+16] = message_authenticator

        authenticator = hashlib.md5(resp+self.secret).digest()
        struct.pack_into("!16s", resp, 4, authenticator)

        return bytes(resp)



    def as_bytes(self, k):
        return self.__attrs[k]

    def as_string(self, k, encoding='UTF8'):
        return self.__attrs[k].decode(encoding)

    def as_byte(self, k):
        return struct.unpack('!B', self.self.__attrs[k])

    def as_uint16(self, k):
        return struct.unpack('!H', self.self.__attrs[k])

    def as_uint32(self, k):
        return struct.unpack('!L', self.self.__attrs[k])

    def as_uint64(self, k):
        return struct.unpack('!Q', self.self.__attrs[k])

