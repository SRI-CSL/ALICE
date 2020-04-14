import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x40234f: {"old-desp": 0x28, "new-desp": 0x40}}
#force_insts = {}

CRYPTO = [SHA1Desc]
exec_path = '../testcases/coreutils-5.2.1/bin/sha1sum_O1'
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/coreutils-5.2.1/bin/sha1sum_O1 --string oakoakoak"

fns = []
