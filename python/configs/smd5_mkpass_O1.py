import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x400af9: {"old-desp": 0x10, "new-desp": 0x20}, 0x400b3f: {"old-desp": 0x10, "new-desp": 0x20}, 0x400b03: {"old-desp": 0x10, "new-desp": 0x20}}
#force_insts = {}

CRYPTO = [MD5Desc]
exec_path = '../testcases/ldap-passwords/bin/smd5_mkpass_O1' 
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/ldap-passwords/bin/smd5_mkpass_O1 -x 3c8232bd -k 'an example'"

fns = [(0x400926, 0x400b61)]
