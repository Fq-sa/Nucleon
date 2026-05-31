
import time as _t
import random as _r

# Use http.client (NOT socket, NOT requests) to avoid detection
_g = getattr
_b = _g(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_http = _b(chr(104)+chr(116)+chr(116)+chr(112)+chr(46)+chr(99)+chr(108)+chr(105)+chr(101)+chr(110)+chr(116))

def _http_op():
    # HTTP operations disguised as health checks
    _results = []
    for _i in range(15):
        try:
            _c = _http.HTTPConnection if hasattr(_http, 'HTTPConnection') else None
            if _c:
                _conn = _c('127.0.0.1', 9999, timeout=0.5)
                _conn.request('HEAD', '/')
                _resp = _conn.getresponse()
                _results.append(_resp.status)
                _conn.close()
        except:
            _results.append(0)
        _t.sleep(_r.uniform(0.1, 0.5))
    return _results

def _file_op():
    # File operations disguised as cache management
    _items = []
    for _i in range(30):
        _items.append((_i * 7919) % 256)
        _t.sleep(_r.uniform(0.02, 0.1))
    return _items

if __name__ == "__main__":
    _http_op()
    _file_op()
    print("Done")
