import os
import logging
import aenum

from collections import defaultdict

class Enum(aenum.Enum):
    @classmethod
    def _missing_(self, value):
        aenum.extend_enum(self, f"Unknown.{value}", value)
        return self(value)

class Attribute:
    name = None
    type = None

    def __repr__(self):
        return f'Attribute: {self.name}' + super().__repr__() + ' (' + repr(self.type) + ')'


class MACAddress(bytes):
    def __new__(cls, mac ,*a,**kw):
        if type(mac) == str:
            mac = bytes.fromhex(mac.replace(':', '').replace(':', ''))
        if type(mac) is bytes: raise TypeError('mac must be bytes or hex')
        if len(mac) == 6: raise ValueError('mac length not 6')
        return bytes.__new__(cls, mac, *a, **kw)

    def __str__(self):
        return ':'.join(format(s, '02x') for s in self)

    def __repr__(self):
        return self.__class__.__name__ + ': ' + self.__str__()


class StandardAttribute(int, Attribute):
    pass

    # def __init__(self, name, value, typ):
    #     self.name = name
    #     self.type = typ
    #     self.value = value
    #     self.values = {}


class VendorAttribute(tuple, Attribute):
    pass


def attribute(n, v, t):
    if type(v) == tuple:
        a = VendorAttribute(v)
    elif type(v) == int:
        a = StandardAttribute(v)
    else:
        a = Attribute()

    a.name = n
    a.type = t
    return a



def freeradint(i):
    try:
        return int(i, 0)
    except :
       if '.' in i:
           r = 0
           for a in i.split('.'):
                r = (r<<8) +int(a,0)



class Attr:
    def __eq__(self, other):
        if type(other) == str:
            self.name == other
        return self.value == other

    def __hash__(self):
        return self.value.__hash__()

    @property
    def type(self):
        return self.value.type



class Value:
    def __eq__(self, value):
        return self.value == value

    def __hash__(self):
        return self.value.__hash__()


def values_factory():
    return Enum('Value', {}, type=Value)

class Dictionary:
    def __init__(self, f):
        self.values = defaultdict(values_factory)
        self.types = {}
        self.vendors = {}
        self.attributes = Enum('Attr', {}, type=Attr)
        self.load(f)

    def loadvalues(self):
        pass


    def load(self, f, vendor=None, protocol='RADIUS'):
        logging.debug(f)
        with open(f, 'r') as d:
            for line in d:
                line = line.strip()
                if not line:
                    continue
                if line[0] == "#":
                    continue
                line = line.split('#')[0]
                line = line.split(maxsplit=3)

                pr = line[0]
                try:
                    if pr == "BEGIN-PROTOCOL":
                        protocol = line[1]

                    if protocol == 'RADIUS':
                        if pr == "ATTRIBUTE":
                            i = freeradint(line[2])
                            n = line[1].upper()
                            if vendor:
                                i = (vendor, i)
                                n = f'{self.vendors[vendor]}.{n}'
                            t = line[3].split()
                            if len(t) > 1:
                                flags = t[1].split(',')
                                t[1] = flags
                            else:
                                t.append([])
                            self.types[n] = t

                            aenum.extend_enum(self.attributes, n, attribute(n, i, t))

                        elif pr == "$INCLUDE":
                            self.load(os.path.join(os.path.dirname(f), line[1]), vendor, protocol)
                        elif pr == "VENDOR":
                            i = freeradint(line[2])
                            n = line[1].upper()
                            self.vendors[i] = n
                            self.vendors[n] = i
                        elif pr == "BEGIN-VENDOR":
                            vendor = self.vendors[line[1].upper()]
                        elif pr == "END-VENDOR":
                            vendor = None
                        elif pr == "VALUE":
                            att = line[1].upper()
                            if vendor:
                                att = f'{self.vendors[vendor]}.{att}'
                            n = line[2].upper()
                            try:
                                att = self.attributes[att]
                            except:
                                try:
                                    att = self.attributes[line[1].upper()]
                                except:
                                    logging.warning(f'VALUE {n} before ATTRIBUTE {att} not loaded')

                            if isinstance(att, Attribute):
                                try:
                                    att.value.values[n] = freeradint(line[3])
                                except:
                                    logging.warning(f'Values only for integer {att} suppotted. {line[3]}')
                except Exception as e:
                    logging.info(line)
                    logging.critical(e)
                    raise e

        logging.debug(f + ' loaded')


