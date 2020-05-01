import dpkt
from dpkt.http import Request, Message
from dpkt.compat import BytesIO


class UpnpRequest(Request):
    """Just a little helper class to add M-SEARCH as a method"""
    # pylint: disable=no-member
    def __init__(self, *args, **kwargs):
        self.__methods = self._Request__methods
        self.__methods['M-SEARCH'] = None
        self.__proto = self._Request__proto

        super(UpnpRequest, self).__init__(*args, **kwargs)

    # pylint: disable=attribute-defined-outside-init
    def unpack(self, buf):
        f = BytesIO(buf)
        line = f.readline().decode("ascii", "ignore")
        if line.startswith('HTTP/'):
            # Work around needed to process pages where HTTP method is not specified. Mainly GET requests.
            line = 'GET * ' + line

        line = line.strip().split()
        if len(line) < 2:
            raise dpkt.UnpackError('invalid request: %r' % line)
        if line[0] not in self.__methods:
            raise dpkt.UnpackError('invalid http method: %r' % line[0])
        if len(line) == 2:
            # HTTP/0.9 does not specify a version in the request line
            self.version = '0.9'
        else:
            if not line[2].startswith(self.__proto):
                raise dpkt.UnpackError('invalid http version: %r' % line[2])
            self.version = line[2][len(self.__proto) + 1:]
        self.method = line[0]
        self.uri = line[1]
        Message.unpack(self, f.read())
