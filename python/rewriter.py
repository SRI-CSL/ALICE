from patcher import Patcher
from expand_local_buffer import *
import subprocess
import collections
import os
from alice_logger import RewriterLog

Log = RewriterLog


class NewCryptoPatch:

    def __init__(self, patch_desc, entry_pt, entry_name):
        self.patch_desc = patch_desc
        self.data_addr = 0x800000
        self.code_addr = 0x900000
        self.entry_addr = 0xa00000
        self.entry_name = entry_name
        self.old_entry_pt = entry_pt

class NewDataPatch:

    def __init__(self, addr, old_size, new_size):
        self.old_addr = addr
        self.new_addr = None 
        self.old_size = old_size
        self.new_size = new_size

class Rewriter:
    def __init__(self, exec_path):
        self.path = exec_path
        self.patcher = Patcher(self.path)
        self.patches = []
        self.data_patches = []

    def add_patch(self, patch):
        if isinstance(patch, NewDataPatch):
            self.data_patches.append(patch)
        else:
            self.patches.append(patch)

    def add_patches(self, patches):
        for patch in patches:
            self.add_patch(patch)
    
    def apply_patches(self):
        Log.debug('------------------------------------------------------')
        Log.debug('Applying dummy patch to determine final locations')
        self._apply_patches(False)
        Log.debug('------------------------------------------------------')
        Log.debug('----------- Again just in case -----------')
        self._apply_patches(False)
        Log.debug('------------------------------------------------------')
        Log.debug('Now applying real patch')
        self._apply_patches(True)

    def _apply_patches(self, deploy):
        if deploy:
            dummy = self.patcher
        else:
            dummy = Patcher(self.path)

        out_data_patches = []
        for patch in self.data_patches:
            init_data = ''
            for i in range(0, patch.new_size):
                init_data += '\00'
            with dummy.bin.collect() as patchset:
                patch.new_addr = patchset.inject(raw=init_data)
            out_data_patches.append(patch)
        self.data_patches = out_data_patches

        out_patches = []
        for patch in self.patches:
            if isinstance(patch, NewCryptoPatch):
                self._run_script(patch.patch_desc.patch_dir, patch.patch_desc.script_name, \
                    hex(patch.data_addr), hex(patch.code_addr), hex(patch.entry_addr), patch.patch_desc.data_name, \
                    patch.patch_desc.code_name, patch.entry_name)
                with dummy.bin.collect() as patchset:
                    patch.data_addr = self._inject_exec(patchset, patch.patch_desc.patch_dir, patch.patch_desc.data_name)
                    patch.code_addr = self._inject_exec(patchset, patch.patch_desc.patch_dir, patch.patch_desc.code_name)
                    patch.entry_addr = self._inject_exec(patchset, patch.patch_desc.patch_dir, patch.entry_name)
                    patchset.patch(patch.old_entry_pt, jmp=patch.entry_addr)
            elif isinstance(patch, ExpandLocalBufferPatch):
                patch.rewrite(patch.start_addr)
                patch.print_asm()
                nops = ''
                for i in range(patch.elb.start_vaddr+4, patch.elb.end_vaddr):
                    nops += 'nop\n'
                with dummy.bin.collect() as patchset:
                    patch.start_addr = patchset.inject(raw=patch.compile())
                    patchset.patch(patch.elb.start_vaddr+4, asm=nops)
                    patchset.patch(patch.elb.start_vaddr, jmp=patch.start_addr)
            else:
                raise NotImplementedError('No record for patch: ' + patch)
            out_patches.append(patch)
        self.patches = out_patches
                             
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


