import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x455182: {"old-desp": 0x20, "new-desp": 0x40}}
#force_insts = {}

CRYPTO = [MD5Desc]
exec_path = '/Users/vm2p/Documents/repositories/ALICE/testcases/curl-7.56.0/src/curl'
patch = SHA256Patch

triton_cmdline = "/Users/vm2p/Documents/repositories/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /Users/vm2p/Documents/repositories/ALICE/python/taint_triton_pin.py /Users/vm2p/Documents/repositories/ALICE/testcases/curl-7.56.0/src/curl --digest --user susan:bye2 http://localhost:5000/ --cookie-jar ."

fns = []
