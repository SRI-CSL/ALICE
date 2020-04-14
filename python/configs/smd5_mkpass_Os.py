import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {
                0x40095a: {"old-desp": 0x10, "new-desp": 0x20},
                0x400982: {"old-desp": 0x10, "new-desp": 0x20},

                }



CRYPTO = [MD5Desc]
exec_path = '../testcases/ldap-passwords/bin/smd5_mkpass_Os' 
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/ldap-passwords/bin/smd5_mkpass_Os -x 3c8232bd -k 'an example'"

fns = [(0x4007d0, 0x4009a7)]
fns = []
