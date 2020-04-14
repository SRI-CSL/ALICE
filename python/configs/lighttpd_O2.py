import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x451b67: {"old-desp": 0x1c, "new-desp": 0x2c}, 0x451b45: {"old-desp": 0x14, "new-desp": 0x20}} #lightly O2

CRYPTO = [SHA1Desc]
exec_path = '../../../testapps/lighttpd-1.4.49/oak/lighttpd-O2'
patch = SHA256Patch

triton_cmdline = "sudo /home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/testapps/lighttpd-1.4.49/oak/lighttpd-O2 -f /home/osboxes/testapps/lighttpd-1.4.49/oak/lighttpd.conf -D  -i 100"

fns = []
