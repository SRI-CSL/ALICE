from patcher import Patcher
from func_args import AliceArg
from desc import *
import subprocess
import collections
import os
from alice_logger import RewriterLog
import json

Log = RewriterLog

class PatchEntry:

    def __init__(self, entry, arg_name, argv):
        self.entry = entry
        self.arg_name = arg_name
        self.argv = argv

    # arg_name = out_in_inlen or in_inlen_out or out_in, ...
    def get_out_index(self):
        return self.arg_name.split("_").index("out")+1 # +1 because array starts at index 0

class PatchDesc:

    def __init__(self, name, patch_dir, script_name, code_name, data_name, crypto_desc):
        self.name = name
        self.patch_dir = patch_dir
        self.script_name = script_name
        self.code_name = code_name
        self.data_name = data_name
        self.crypto = crypto_desc

    def __str__(self):
        return str(self.name)


SHA256Patch = PatchDesc('sha256', '../patch/sha256', 'generate_patch.sh', 'code', 'data', SHA256Desc)

def generate_all_possible_args(input_bytes, input_len, output_bytes, in_addr=0x200, out_addr=0x300):

    print("input bytes = " + str(input_bytes) + " output_bytes = " + str(output_bytes))
    print("type input bytes = " + str(type(input_bytes)) + " type output_bytes = " + str(type(output_bytes)))
    print("in_addr = " + str(in_addr) + " type = " + str(type(in_addr)))
    
    input_arg = AliceArg(AliceArg.TYPE_BYTE_POINTER, in_addr, input_bytes)
    inlen_arg = AliceArg(AliceArg.TYPE_INT, input_len)
    output_arg = AliceArg(AliceArg.TYPE_BYTE_POINTER, out_addr, output_bytes, output_bytes)
    # TODO: out_in_inlen cannot happen at the same time as out_in!!!!
    #return collections.OrderedDict([("out_in_inlen", (output_arg, input_arg, inlen_arg))])
    #return collections.OrderedDict([("out_in", (output_arg, input_arg, inlen_arg))])
    #return collections.OrderedDict([("in_inlen_out", (input_arg, inlen_arg, output_arg))])
    #return collections.OrderedDict([("in_inlen_out", (input_arg, inlen_arg, output_arg)), ("out_in", (output_arg, input_arg, inlen_arg))])

    print("input_arg = " + str(input_arg.val).encode().hex() + " input_arg = " + str(input_arg.val) + " inlen_arg = " + str(inlen_arg.val) + " output_arg = " + str(output_arg.val).encode().hex())
    
    #return collections.OrderedDict([("in_inlen_out", (input_arg, inlen_arg, output_arg)), ("out_in", (output_arg, input_arg)), ("out_in_inlen", (output_arg, input_arg, inlen_arg)) ])
    return collections.OrderedDict([("in_inlen_out", (input_arg, inlen_arg, output_arg)), ("out_in", (output_arg, input_arg)), ("out_in_inlen", (output_arg, input_arg, inlen_arg)) ])


class CryptoPatcher:
    def __init__(self, exec_path):
        self.path = exec_path
        self.patcher = Patcher(self.path)

    def test_inject_patch(self, binary):
        # First get addresses of code and data by calling dummy patcher
        dummy = Patcher(self.path)
        with dummy.bin.collect() as patchset:
            addr = patchset.inject(raw=binary)
        return addr

    def apply_patch(self, patch_desc, old_entry, entry_name):
        # First get addresses of code and data by calling dummy patcher
        dummy = Patcher(self.path)
        dummy_addr1 = hex(0x800000)
        dummy_addr2 = hex(0x900000)
        dummy_addr3 = hex(0xa00000)
        self._run_script(patch_desc.patch_dir, patch_desc.script_name, dummy_addr1, dummy_addr2, dummy_addr3, patch_desc.data_name, patch_desc.code_name, entry_name)
        with dummy.bin.collect() as patchset:
            data_addr = self._inject_exec(patchset, patch_desc.patch_dir, patch_desc.data_name)
            code_addr = self._inject_exec(patchset, patch_desc.patch_dir, patch_desc.code_name)
            entry_addr = self._inject_exec(patchset, patch_desc.patch_dir, entry_name)

        # Now inject the real patch with correct addresses
        self._run_script(patch_desc.patch_dir, patch_desc.script_name, hex(data_addr), hex(code_addr), hex(entry_addr), patch_desc.data_name, patch_desc.code_name, entry_name)
        with self.patcher.bin.collect() as patchset:
            data_addr = self._inject_exec(patchset, patch_desc.patch_dir, patch_desc.data_name)
            code_addr = self._inject_exec(patchset, patch_desc.patch_dir, patch_desc.code_name)
            entry_addr = self._inject_exec(patchset, patch_desc.patch_dir, entry_name)
            patchset.patch(old_entry, jmp=entry_addr)

    def _run_script(self, script_dir, script_name, *script_args):
        pwd = os.getcwd()
        os.chdir(script_dir)
        script = [os.path.join(os.getcwd(), script_name)] + list(script_args)
        Log.debug('Script input: ' + str(list(script_args)))
        popen = subprocess.Popen(script, stdout=subprocess.PIPE)
        popen.wait() 
        Log.debug('Script output: ' + popen.stdout.read())
        os.chdir(pwd)

    def _inject_exec(self, pt, base_dir, file_name):
        with open(os.path.join(base_dir, file_name), "rb") as f:
            binary = f.read()
            addr = pt.inject(raw=binary)
        return addr

    def save(self, path):
        self.patcher.save(path)


