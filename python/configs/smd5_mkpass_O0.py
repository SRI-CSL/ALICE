import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x40095d: {"old-desp": 0x10, "new-desp": 0x20}}

CRYPTO = [MD5Desc]
exec_path = '../testcases/ldap-passwords/bin/smd5_mkpass_O0' 
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/ldap-passwords/bin/smd5_mkpass_O0 -x 3c8232bd -k 'an example'"

fns = []
