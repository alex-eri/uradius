#code
Request = 1
Success = 3
Response = 2
Failure = 4

#type
Identity = 1
LegacyNak = 3
MD5Challenge = 4

PEAP = 25
MSCHAPV2 = 26

#mschap
Challenge = 1
Response = 2
Success = 3
Failure = 4
ChangePassword =5

import struct
import uuid
import logging

logger = logging.getLogger('eap.message')
debug = logger.debug



class EAP:

    def __init__(self, Identity):
        self.Identity = Identity

    def eap_body(self, data):
        r = data()
        t = data[0]
        body = data[1:]

        if t == Identity:
            r['Identity'] = body.decode('utf8')
        elif t == LegacyNak:
            r['LegacyNak'] = body[0]
        elif t == MD5Challenge:
            l =  body[0]
            r['MD5Challenge'] = body[1:l+1]
        elif t== MSCHAPV2:
            print('TODO')

        elif t == PEAP:
            flags = body[0]
            r['TLSFlags'] = flags
            r['TLSMore'] = flags & 0x40

            if flags & 0x80:
                l = body[1] << 32 | body[2] << 16 | body[3] << 8 | body[4]
                if l:
                    r['TLS'] = body[5:l+5]
                else:
                    r['TLS'] = body[5:]
            else:
                r['TLS'] = body[1:]


    def eap(self, data):
        code,ident,length = data[0],data[1],data[2] << 8 | data[3]
        data = data[4:length]

        return code,ident,length, self.eap_body(data)