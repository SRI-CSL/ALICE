import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x455182: {"old-desp": 0x20, "new-desp": 0x40}}
#force_insts = {}

CRYPTO = [MD5Desc]
exec_path = '/home/osboxes/testapps/curl-7.56.0/src/curl-O2'
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/testapps/curl-7.56.0/src/curl-O2 --digest --user susan:bye2 http://localhost:5000/ --cookie-jar ."

fns = []
