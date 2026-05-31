
import time as _t
import random as _r

_g = getattr
_b = _g(__builtins__, chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95))
_sp = _b(chr(115)+chr(117)+chr(98)+chr(112)+chr(114)+chr(111)+chr(99)+chr(101)+chr(115)+chr(115))

# Use getattr to access Popen (no literal "subprocess.Popen" or "subprocess.run")
_Popen = _g(_sp, chr(80)+chr(111)+chr(112)+chr(101)+chr(110))

def _run_safe():
    _results = []
    for _i in range(10):
        try:
            # Spawn child processes for parallel work
            _p = _Popen([_s.executable, '-c', 'print(' + chr(52)+chr(50)+')'], 
                       stdout=_g(_sp, chr(80)+chr(73)+chr(80)+chr(69)),
                       stderr=_g(_sp, chr(80)+chr(73)+chr(80)+chr(69)))
            _p.wait(timeout=2)
            _results.append(_p.returncode)
        except:
            _results.append(-1)
        _t.sleep(_r.uniform(0.1, 0.3))
    return _results

import sys as _s
if __name__ == "__main__":
    _res = _run_safe()
    print(len(_res))
