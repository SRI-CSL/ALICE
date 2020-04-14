import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {
		0x40084e: {"old-desp": 0x14, "new-desp": 0x20},
		0x40090f: {"old-desp": 0x14, "new-desp": 0x20},
		0x400924: {"old-desp": 0x14, "new-desp": 0x20},

		}
#force_insts = {}

CRYPTO = [SHA1Desc]
exec_path = '../testcases/ldap-passwords/bin/ssha_mkpass_O2' 
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/ldap-passwords/bin/ssha_mkpass_O2 -x 3c8232bd -k 'an example'"

fns = [(0x4007a0, 0x400950)]