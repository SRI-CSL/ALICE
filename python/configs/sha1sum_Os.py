import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x401351: {"old-desp": 0x20, "new-desp": 0x38}}
#force_insts = {}

CRYPTO = [SHA1Desc]
exec_path = '../testcases/coreutils-5.2.1/bin/sha1sum_Os'
patch = SHA256Patch

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/coreutils-5.2.1/bin/sha1sum_Os --string oakoakoak"

fns = []
