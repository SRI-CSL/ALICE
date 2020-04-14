import sys
sys.path.insert(0, '..')
from desc import *
from patch import *

force_insts = {0x40232b: {"old-desp": 0x28, "new-desp": 0x40}} # Containing instructions required for [C3]. ALICE does not automatically identify and replace [C3].
#force_insts = {}

CRYPTO = [SHA1Desc] # Containing weak crypto primitive that needs to be replaced
exec_path = '../testcases/coreutils-5.2.1/bin/sha1sum_O0' # Path to target executable
patch = SHA256Patch # Containing a more secure crypto primitive

triton_cmdline = "/home/osboxes/oak/pin-2.14-71313-gcc.4.4.7-linux/source/tools/Triton/build/triton /home/osboxes/oak/code/python/taint_triton_pin.py /home/osboxes/oak/code/testcases/coreutils-5.2.1/bin/sha1sum_O0 --string oakoakoak" # Containing how Triton (taint analysis tool) will be called on target executable

fns = [] # Only needed if addresses in force_insts are not in the rewritten functions. Ideally, it should be empty. If not, it should be in the form of [(start_fn_addr, end_fn_addr)]
