from capstone import CS_OPT_SYNTAX_ATT
from capstone.x86 import *
from expand_local_buffer import *
from angr_caller_analysis import *
from alice_logger import ScoperLog

Log = ScoperLog

# Buffer allocated in BSS/DATA sections
class ExpandStaticBuffer:

    def __init__(self, binary, buffer_addr, buffer_old_size, buffer_new_size):
        self.angr_proj = binary.angr_proj
        # Sanity check
        if not (self.angr_proj.loader.main_object.sections_map['.bss'].contains_addr(buffer_addr)
            or self.angr_proj.loader.main_object.sections_map['.data'].contains_addr(buffer_addr)):
            raise ValueError('Buffer at: ' + hex(buffer_addr) + ' is not statically allocated')
        
        self.fub = None 
        self.binary = binary
        self.cfg = binary.ca.cfg
        self.buffer_addr = buffer_addr
        self.buffer_old_size = buffer_old_size
        self.buffer_new_size = buffer_new_size
        self.caller_inst_addrs = self.binary.ca.data_refs(buffer_addr, buffer_addr+buffer_old_size)

    # Return all functions and corresponding instruction using this statically allocated buffer
    def functions_use_buffer(self):
        if self.fub:
            return self.fub.copy()

        self.angr_proj.arch.capstone.syntax = CS_OPT_SYNTAX_ATT
        
        out = {}
        # Iterate through all "roughly" detected location
        # Roughly detected location can have false positive
        for cinst_addr in self.caller_inst_addrs:

            # Check which function it belongs to
            for fn_entry, fn in self.cfg.functions.items():
        
                fn_entry, fn_exit = self.binary.ca.get_func_scope(fn_entry)
                if cinst_addr < fn_entry or cinst_addr > fn_exit:
                    continue

                # Check which block it belongs to
                for angr_bb in fn.blocks:
                    if cinst_addr >= angr_bb.addr and cinst_addr < angr_bb.addr+angr_bb.size:

                        # Check which instruction it belongs to
                        for inst in angr_bb.capstone.insns:
    
                            # Which operand
                            for operand in inst.operands:

                                # It belongs to operand if operand has a type of IMM and its imm value == buffer_addr
                                if operand.type == X86_OP_IMM and operand.imm >= self.buffer_addr and operand.imm < self.buffer_addr + self.buffer_old_size:
                                    if operand.imm == self.buffer_addr:
                                        if fn_entry not in out.keys():
                                            out[fn_entry] = [inst.address]
                                        else:
                                            out[fn_entry].append(inst.address)
                                    else:
                                        Log.warning('Instruction at: ' + hex(inst.address) + ' accessing data at ' + hex(operand.imm) + 'but buffer starts at ' + hex(self.buffer_addr) + '-' + hex(self.buffer_addr+self.buffer_old_size))
        self.fub = out.copy()
        return out                        
                             
                    
    

if __name__ == '__main__':

    path = '/home/oak/ALICE-scp/ALICE/code/testbench/src/expand_buffer/bin/test11.o'
    binary = Binary(path)
    binary.ca = AngrCallerAnalysis(binary)

    buffer_addr = 0x602060
    old_size = 16
    new_size = 32
    esb = ExpandStaticBuffer(binary, buffer_addr, old_size, new_size)
    print (esb.functions_use_buffer())
