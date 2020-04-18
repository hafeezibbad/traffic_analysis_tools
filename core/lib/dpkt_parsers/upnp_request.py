import dpkt
from dpkt.http import Request, Message
from dpkt.compat import BytesIO


class UpnpRequest(Request):
    """Just a little helper class to add M-SEARCH as a method"""

    def __init__(self, *args, **kwargs):
        self.__methods = self._Request__methods
        self.__methods['M-SEARCH'] = None
        self.__proto = self._Request__proto

        super(UpnpRequest, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline().decode("ascii", "ignore")
        if line.startswith('HTTP/'):
            # Work around needed to process pages where HTTP method is not specified. Mainly GET requests.
            line = 'GET * ' + line

        l = line.strip().split()
        if len(l) < 2:
            raise dpkt.UnpackError('invalid request: %r' % line)
        if l[0] not in self.__methods:
            raise dpkt.UnpackError('invalid http method: %r' % l[0])
        if len(l) == 2:
            # HTTP/0.9 does not specify a version in the request line
            self.version = '0.9'
        else:
            if not l[2].startswith(self.__proto):
                raise dpkt.UnpackError('invalid http version: %r' % l[2])
            self.version = l[2][len(self.__proto) + 1:]
        self.method = l[0]
        self.uri = l[1]
        Message.unpack(self, f.read())
