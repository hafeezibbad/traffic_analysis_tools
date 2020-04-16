from dpkt.http import Request


class UpnpRequest(Request):
    """Just a little helper class to add M-SEARCH as a method"""

    def __init__(self, *args, **kwargs):
        super(UpnpRequest, self).__init__(*args, **kwargs)
        self._Request__methods["M-SEARCH"] = None       # pylint: disable=no-member
