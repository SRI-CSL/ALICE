import angr
from capstone import *
from capstone.x86 import *
from capstone.x86_const import *
import expand_local_buffer

class TerminationCondition:

    def __init__(self, addr, const_before, const_after):
        self.addr = addr
        self.before = const_before
        self.after = const_after

def op_access_iter_stack(op):
    return (op.type == X86_OP_MEM and (op.mem.base == X86_REG_RBP or op.mem.base == X86_REG_RSP) and op.mem.index != 0)

class ExpandTaintedBuffer:

    def __init__(self, binary, fn, buffer_offset, buffer_original_size, expand_size):
        self.buffer_offset = buffer_offset
        self.buffer_original_size = buffer_original_size
        self.expand_size = expand_size
        self.proj = binary.angr_proj
        self.proj.arch.capstone.syntax = CS_OPT_SYNTAX_ATT
        #fn = cfg.functions[fn.addr]
        self.lf = self.proj.analyses.LoopFinder([fn])
        self.elb = expand_local_buffer.ExpandLocalBuffer(binary, fn.addr, fn.addr+fn.size)

    # Algorithm:
    # For each loop:
    # If any of buffer_offset is read iteratively, put up a flag f
    # If any other buffer is written iteratively, store offset of that buffer in "change_offset"
    # At the end of loop, if flag f is on and change_offset is not empty:
    # (1) expand each of change_offset by how many number of times it appears in the loop * expanded_size
    # (2) Look at cmp instruction at loop head, if it uses a constant as a termination codition and that constant matches 
    #     original buffer_offset's size, increase it to the new size
    # That's it!
    def find(self):
        src = expand_local_buffer.ELB_SRC_REG
        dest = expand_local_buffer.ELB_DST_REG
        elb_calls = []
        term_conds = []
        for loop in self.lf.loops:
            print loop
            found = False
            change_offsets = []
            for lb in loop.body_nodes:
                insns = self._capstone_insns(lb)
                # TODO: adjust stack size

                for insn in insns:
                    if len(insn.operands) != 2:
                        continue

                    if op_access_iter_stack(insn.operands[src]) and expand_local_buffer.stack_offset(insn.operands[src], self.elb.stack_size) == self.buffer_offset:
                        found = True
                    
                    if op_access_iter_stack(insn.operands[dest]) and not expand_local_buffer.stack_offset(insn.operands[dest], self.elb.stack_size) == self.buffer_offset:
                        # Replace this guy
                        change_offsets.append(expand_local_buffer.stack_offset(insn.operands[dest], self.elb.stack_size))

            if found and len(change_offsets) > 0:

                for co in set(change_offsets):
                    # TODO: add the correct old size, REALLY IMPORTANT
                    base_size = 16*change_offsets.count(co)
                    new_size = 16 + self.expand_size*change_offsets.count(co)
                    elb_calls.append(expand_local_buffer.ExpandLocalBufferCall(None, None, co, base_size, new_size))

                le_insns = self._capstone_insns(loop.entry)
                print 'Somehow need to change ins: ', le_insns[-2]

                # TODO: (2) change loop termination condition
                term_cond = self._get_loop_termination(loop.entry, self.buffer_original_size)
                if term_cond is not None:
                    term_conds.append(term_cond)
                
            
        return elb_calls, term_conds
                
    def _get_loop_termination(self, loop_entry, hash_original_size):
        insns = self._capstone_insns(loop_entry)
        cmp_insn = insns[-2]
        jmp_insn = insns[-1]
        if 'cmp' not in cmp_insn.mnemonic:
            return None
        if not jmp_insn.group(X86_GRP_JUMP):
            return None
        if len(cmp_insn.operands) != 2:
            return None
        
        # Now get loop termination condition
        term_cond = None
        for op in cmp_insn.operands:
            if op.type == X86_OP_IMM:
                term_cond = op.imm
                break
       
        if term_cond is None:
            return None
        if hash_original_size - term_cond < 2:
            return TerminationCondition(cmp_insn.address, term_cond, self.expand_size+term_cond)
        return None

    def _capstone_insns(self, loop_block):
        return self.proj.factory.block(loop_block.addr).capstone.insns


if __name__ == "__main__":

    from binary import *

    path = '../testbench/src/expand_buffer/bin/test1.o'
    binary = Binary(path)
    cfg = binary.angr_proj.analyses.CFGFast()
    main_fn = cfg.functions['main']
    elb = expand_local_buffer.ExpandLocalBuffer(binary, main_fn.addr, main_fn.addr+main_fn.size)
    print 'Stack size: ', hex(elb.stack_size)

    etb = ExpandTaintedBuffer(binary, main_fn, 0x10, 0x10, 0x10)

    ecs, tcs = etb.find()
    for ec in ecs:
        print 'Offset: ', hex(ec.stack_offset), 'Expand by', hex(ec.diff_size)
    for tc in tcs:
        print 'TerminationCondition: ', hex(tc.before), ' ---> ', hex(tc.after)
