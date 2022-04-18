from elf_binary import *
from capstone.x86 import *
#from patcher import *
from capstone import *
from keystone import *
from expand_tainted_buffer import *
from expand_static_buffer import *
from alice_logger import ScoperLog
import operator

Log = ScoperLog
######################################################
class RewriteError(Exception):
    pass


# Assume ATT syntax
ELB_SRC_REG = 0
ELB_DST_REG = 1

def op_pc_disp(op):
    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
        return op.mem.disp
    return None

def inst_pc_disp(inst):
    out = None
    for op in inst.operands:
        disp = op_pc_disp(op)
        if disp is not None:
            if out is not None:
                raise NotImplementedError("Multiple PC displacement in single instruction: " + construct_asm(inst))
            out = disp
            return out
        
def op_access_stack(op):
    if op.type == X86_OP_REG:
        return op.reg in [X86_REG_RBP, X86_REG_RSP]
    if op.type == X86_OP_MEM:
        return op.mem.base in [X86_REG_RBP, X86_REG_RSP]

def inst_access_stack(inst):
    for op in inst.operands:
        if op_access_stack(op):
            return True
    return False

# Compute stack offset w.r.t SP
def stack_offset(op, stack_size):
    if not op_access_stack(op):
        return None
    if op.type == X86_OP_REG and op.reg == X86_REG_RBP:
        return stack_size
    if op.type == X86_OP_REG and op.reg == X86_REG_RSP:
        return 0
    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RBP:
        return stack_size + op.mem.disp
    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RSP:
        return op.mem.disp
    raise NotImplementedError("Unimplement stack_offset for op: " + str(op))

# Compute a new stack offset w.r.t RSP
# Computation is really simple: if old_offset < base_offset+original_size, new_offset = old_offset
# Otherwise, new_offset = old_offset + (new_size - original_size)
def new_stack_offset(op, base_offset, original_size, new_size, stack_size):
    if new_size <= original_size:
        raise ValueError("New size is not greater than original size! "+str(new_size)+" vs "+str(original_size))
    if not op_access_stack(op):
        return None

    # Access to stack by using BP and SP registers is fine, dont need to modify
    if op.type == X86_OP_REG and op.reg == X86_REG_RBP:
        return None
    if op.type == X86_OP_REG and op.reg == X86_REG_RSP:
        return None

    diff = new_size - original_size
    if op.type == X86_OP_MEM:
        old_offset = stack_offset(op, stack_size)
        if old_offset < base_offset+original_size:
            new_offset = old_offset
        else:
            new_offset = old_offset + diff
        return new_offset

    raise NotImplementedError("Unimplement change_stack_offset for op: " + str(op))


# Re-calculate displacement w.r.t. RBP or RSP after expanding buffer to the new size
def compute_new_disp(op, buffer_offset, original_size, new_size, current_stack_size):

    # If it's not mem type, there's no displacement/offset
    if op.type != X86_OP_MEM:
        return None, None
    # Compute new stack offset w.r.t RSP
    new_offset = new_stack_offset(op, buffer_offset, original_size, new_size, current_stack_size)

    # Compute displacement w.r.t base register (either RBP or RSP)
    if new_offset is not None:
        # If its RSP, just return our new_offset
        if op.mem.base == X86_REG_RSP:
            return new_offset, op.mem.disp

        # If it's RBP, we compute displacement based on new_offset
        # E.g. if stack size is 0x50 and new offset is 0x40, disp w.r.t RBP is 0x40-0x50=-0x10,
        # then if we increase stack size to 0x60 and new offset becomes 0x40 -> our new disp w.r.t RBP is 0x40-0x60=-0x20
        if op.mem.base == X86_REG_RBP:
            return new_offset - (current_stack_size+new_size-original_size), op.mem.disp

    return None, None

def replace_disp(assembly, old_disp, new_disp, absolute=True):
    if absolute:
        old_disp = abs(old_disp)
        new_disp = abs(new_disp)
        # First try to replace hex(old_disp) first
    if assembly.count(hex(old_disp)) == 1:
        return assembly.replace(hex(old_disp), hex(new_disp).rstrip("L"))
    elif assembly.count(hex(old_disp)) > 1:
        raise ValueError('Instruction contains more than one ' + hex(old_disp) + ' : ' + assembly)

    # Now replace hex(old_disp) without 0x leading
    if assembly.count(hex_0(old_disp)) > 1:
        raise ValueError('Instruction contain more than one ' + hex_0(old_disp) + ' : ' + assembly)
    elif assembly.count(hex_0(old_disp)) == 0:
        return assembly
    return assembly.replace(hex_0(old_disp), hex(new_disp))

# Determine whether instruction inst modifies stack size or not. If so, return the size changes
def stack_size_change(inst):
    # Assume caller convention??
    if inst.mnemonic == "pushq":
        return 8
    if inst.mnemonic == "popq":
        return -8
    if len(inst.operands) < 2:
        return 0
    # TODO: is it true?
    # Only way to modify stack size is through sub or add instruction
    if inst.mnemonic in ['subq', 'addq'] and inst.operands[ELB_DST_REG].type == X86_OP_REG \
       and inst.operands[ELB_DST_REG].reg == X86_REG_RSP and inst.operands[ELB_SRC_REG].type == X86_OP_IMM:
        # sub instruction, stack size increases
        if inst.mnemonic == 'subq':
            return inst.operands[ELB_SRC_REG].imm
        # add instruction -> stack size decreases
        else:
            return -inst.operands[ELB_SRC_REG].imm
    return 0

def construct_asm(inst):
    return inst.mnemonic + ' ' + inst.op_str

def hex_0(i):
    h = hex(i)
    return h[2:]

def is_source(inst, reg_type):
    if len(inst.operands) < 2:
        return False
    return inst.operands[ELB_SRC_REG].type == X86_OP_REG and inst.operands[ELB_SRC_REG].reg == reg_type

def is_dest(inst, reg_type):
    if len(inst.operands) < 2:
        return False
    return inst.operands[ELB_DST_REG].type == X86_OP_REG and inst.operands[ELB_DST_REG].reg == reg_type

def twos_comp(val, bits):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)        # compute negative value
    return val                         # return positive value as is

class ExpandLocalBufferPatch:
    NUM_ELB_PATCHES = 0
    def __init__(self, elb, label_prefix='.oak_', label_num=1, data_mapping={}):
        self.elb = elb
        self.NUM_ELB_PATCHES += 1
        self.label_prefix = label_prefix + str(self.NUM_ELB_PATCHES) + '_'
        self.label_num = label_num
        self.ks = Ks(self.elb.binary.angr_proj.arch.ks_arch, self.elb.binary.angr_proj.arch.ks_mode)
        self.ks.syntax = KS_OPT_SYNTAX_ATT
        self.assembly = None
        self.start_addr = 0
        self.labels = self.assign_labels()
        self.symoblized_assembly = None
        self.new_assembly = None
        self.data_mapping = data_mapping

    def print_asm(self, assembly=None):
        ip = self.start_addr
        if assembly is None:
            assembly = self.new_assembly
            
        for asm in assembly:
            tmp = self.asm_single_inst(asm, ip)
            Log.info(hex(ip) + ": " + asm)
            ip += len(tmp)

    def asm_single_inst(self, asm, addr=0):
        if 'fs' in asm:
            Log.warning("FS register, asm inst: "+str(asm))
            if asm == 'movq %fs:0x28, %rax':
                tmp = [0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0]
            elif asm == 'xorq %fs:0x28, %rcx':
                tmp = [0x64, 0x48, 0x33, 0x0c, 0x25, 0x28, 0, 0, 0]
            elif asm == 'xorq %fs:0x28, %rax':
                tmp = [0x64, 0x48, 0x33, 0x04, 0x25, 0x28, 0, 0, 0]
            elif asm == 'xorq %fs:0x28, %rsi':
                #tmp = [0x64, 0x48, 0x31, 0x34, 0x25, 0x28, 0x00, 0x00, 0x00]
                tmp = [0x64, 0x48, 0x33, 0x34, 0x25, 0x28, 0x00, 0, 0]
            elif asm == 'xorq %fs:0x28, %rdi':
                tmp = [0x64, 0x48, 0x33, 0x3c, 0x25, 0x28, 0x00, 0, 0]
            elif asm == 'xorq %fs:0x28, %rdx':
                tmp = [0x64, 0x48, 0x33, 0x14, 0x25, 0x28, 0x00, 0, 0]
            elif asm == 'movq %fs:0x28, %rcx':
                tmp = [0x64, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0, 0]
            elif asm == 'xorq %fs:0x28, %rbx':
                tmp = [0x64, 0x48, 0x33, 0x1c, 0x25, 0x28, 0x00, 0, 0]

            else: 
                raise NotImplementedError(asm)
            Log.warning("FS register, asm : "+str(tmp))
        else:
            try:
                tmp, count = self.ks.asm(asm, addr=addr)
            except Exception as e:
                Log.debug('Exception: ' + hex(addr) + ': ' + asm)
                raise e
            
            # for some reason, ks outputs wrong count for rep stosq %rax, (%rdi)
            if count != 1:
                if 'rep' in asm:
                    Log.warning('Warning: this assembly produces multiple statement: ' + hex(addr) + ':' + asm + ' ' + str(count)+' '+str([hex(x) for x in tmp]))
                else:
                    raise RewriteError('Assembly outputs multiple statement (' + str(count) + '): ' + asm + ' at addr: ' + hex(addr))

        return tmp


    def compile(self):
        ip = self.start_addr
        out = []
        for asm in self.new_assembly:
            tmp = self.asm_single_inst(asm, ip)
            ip += len(tmp)
            out.extend(tmp)
        return bytearray(out)


    # Three instructions to look for:
    # call xxxx -> for now, do nothing. TODO: change address if the callee needs to be relocated
    # jmp xxxx -> if jump target is not in relocation part, do nothing. Otherwise, change value accordingly
    # lea rpi($disp) .... -> first compute absolute address (rpi+$disp), readjust $disp based on new address
    def assign_labels(self):
        out_assembly = []
        labels = {}
        
        # Symbolize all jump/call/lea targets
        for inst in self.elb.assembly:
            if (inst.group(X86_GRP_JUMP) or inst.group(X86_GRP_CALL)) and len(inst.operands) == 1 and inst.operands[ELB_SRC_REG].type == X86_OP_IMM:
                imm = inst.operands[ELB_SRC_REG].imm
                if imm not in labels:
                    labels[imm] = self.label_prefix+ format(self.label_num, '06d')
                    self.label_num += 1
            if inst.mnemonic == 'leaq' and len(inst.operands) == 2:
                src_mem = inst.operands[ELB_SRC_REG].mem
                if src_mem.base == X86_REG_RIP:
                    lea_absolute_target = twos_comp(src_mem.disp, 32) + inst.address + inst.size
                    if lea_absolute_target not in labels:
                        labels[lea_absolute_target] = self.label_prefix+str(self.label_num)
                        self.label_num += 1
        for k,v in labels.items():
            Log.debug('Labels: ' + hex(k)+' -> '+v)
        return labels
    
    # Try to produce new assembly code after applying mod_assembly patch
    # We only need to know the size, correctness is not important here
    def rewrite_based_on_labels(self, new_vaddr=0):
        labels = self.labels 
        labels_to_new_addr = {}
        ip = new_vaddr
        out_assembly = {}
        for inst in self.elb.assembly:
            new_assembly = construct_asm(inst)

            if inst.address in labels:
                labels_to_new_addr[labels[inst.address]] = ip

            if inst.address in self.elb.mod_assembly:
                new_assembly = self.elb.mod_assembly[inst.address]

                # Replace all data mapping
            for old_addr, new_addr in self.data_mapping.items():
                old_addr = int(old_addr)
                new_addr = int(new_addr)
                if hex(old_addr) in new_assembly:
                    old_new_assembly = new_assembly
                    new_assembly = replace_disp(new_assembly, old_addr, new_addr, False)
                    Log.debug('Data access changes: ' + new_assembly + '--------->' + old_new_assembly)
                    
                    # Assign label to that absolute address
            if (inst.group(X86_GRP_JUMP) or inst.group(X86_GRP_CALL)) and len(inst.operands) == 1 \
               and inst.operands[ELB_SRC_REG].type == X86_OP_IMM and inst.operands[ELB_SRC_REG].imm in labels:
                new_assembly = inst.mnemonic + ' ' + labels[inst.operands[ELB_SRC_REG].imm]
                
	        # sanity check
                Log.warning("Ins size for: "+hex(ip)+" "+new_assembly+" size: "+hex(inst.size))
                # TODO: this is heuristic that new inst size wont change
                new_inst_size = inst.size
            else:

                encoding = self.asm_single_inst(new_assembly, addr=ip)
                new_inst_size = len(encoding)
                
                Log.debug("Labeling: "+hex(ip)+" "+str(new_assembly)+" ("+hex(new_inst_size)+") "+str([hex(x) for x in encoding]))

                
                ip_disp = inst_pc_disp(inst)
                if ip_disp is not None:
                    old_new_assembly = new_assembly
                    # Recompute IP's displacement
                    absolute_addr = inst.address + ip_disp + inst.size
                    new_ip_disp = absolute_addr - ip - new_inst_size
                    #print hex(inst.address), hex(absolute_addr), ip, new_inst_size, hex(new_ip_disp)
                    new_assembly = replace_disp(new_assembly, ip_disp, new_ip_disp, False)
                    Log.debug('Displacement changes: ' + new_assembly + '--------->' + old_new_assembly)

            out_assembly[ip] = {'new_assembly': new_assembly, 'old_assembly': construct_asm(inst), 'old_addr': inst.address, 'old_inst': inst}
            ip += new_inst_size
            self.symbolized_assembly = out_assembly
        return labels_to_new_addr

    # Rewrite the function w.r.t new_vaddr address
    def rewrite(self, new_vaddr):
        labels_to_new_addr = self.rewrite_based_on_labels(new_vaddr)
        self.resolve_symbols(labels_to_new_addr, new_vaddr)
        old_addr_to_labels = self.labels
        self.resolve_unused_symbols(old_addr_to_labels)
        self.new_assembly = []
        self.new_assembly.extend(self.symbolized_assembly)
        return self.new_assembly

    def resolve_symbols(self, labels_to_new_addr, new_vaddr):
        out = []
        keylist = self.symbolized_assembly.keys()
        keylist.sort()
        for key in keylist: # in self.symbolized_assembly.items():
            a = key
            d = self.symbolized_assembly[a]
            ass = d['new_assembly']
            old_inst = d['old_inst']
            old_ass = construct_asm(old_inst)
            for label, addr in labels_to_new_addr.items():
                old_ass = ass
                ass = ass.replace(label, hex(addr).rstrip("L"))
                if old_ass != ass:
                    Log.debug('Change!: ' + old_ass + '----->' + ass + ' ' + label + ' ' + hex(addr))
                    
            out.append(ass)

            # For some reasons, nop produces unpredictable result, e.g., nopl 0(%rax) -> nop BYTE PTR [rax] or nop DWORD PTR [rax+0x0]
            if 'nop' in ass:
                continue

            try:
                old_addr = d['old_addr']
                Log.debug("assing: "+str(ass))
                new_encoding = self.asm_single_inst(ass, addr=a)
                #Log.debug("Whyyy?: "+hex(a)+' '+str(ass)+" "+str([hex(x) for x in encoding])+"("+hex(len(encoding))+")")
                #Log.debug("assing: "+str(old_ass))
                #old_encoding = self.asm_single_inst(old_ass, addr=old_addr)
                size_diff = old_inst.size - len(new_encoding)
                if size_diff < 0:
                    raise ValueError('You are fucked!! the new instruction is larger than the old instruction. (n vs o) '+ass+' - '+old_ass)
                elif size_diff > 0:
                    Log.warning('New instruction is shorter than old inst (n vs o) '+ass+' - '+old_ass)
                    Log.warning('New instruction is shorter than old inst (n vs o) '+str([hex(x) for x in new_encoding])+' - '+str([hex(x) for x in old_inst.bytes]))
                    Log.warning('New instruction is shorter than old inst (n vs o) '+hex(a)+' - '+hex(old_inst.address))
                    for i in range(0, size_diff):
                        Log.warning('adding nop')
                        out.append('nop')
            except Exception as e:
                Log.warning("cant disassemble: "+str(ass)+" "+str(old_ass))
                Log.warning(str(e))
                #Log.debug("Whyyy?: "+str(d['old_assembly'])+" "+str([hex(x) for x in encoding])+"("+hex(len(encoding))+")")
        self.symbolized_assembly = out

    def resolve_unused_symbols(self, old_addr_to_labels):
        out = []
        for ass in self.symbolized_assembly:
            for addr, label in old_addr_to_labels.items():
                old_ass = ass
                ass = ass.replace(label, hex(addr).rstrip("L"))
                if old_ass != ass:
                    Log.debug('Change2!: ' + old_ass + '----->' + ass + ' ' + label + ' ' + hex(addr))

            out.append(ass)
            self.symbolized_assembly = out


class ExpandBufferManager:

    def __init__(self, binary, scoper):
        self.binary = binary
        self.scoper = scoper
        self.elbs = {}
        self.esbs = {}
        self.data_mapping = {}

    def add_data_mapping(self, old_addr, new_addr):
        self.data_mapping[old_addr] = new_addr

    # Generate patches for rewriter
    def generate_patches(self):
        Log.info('ELB Manager: generating ' + str(len(self.elbs)) + ' patch(es)')
        patches = []
        for _, elb in self.elbs.items():
            elb.expand()
            patches.append(ExpandLocalBufferPatch(elb, data_mapping=self.data_mapping))
        return patches

    def expand_static_mem(self, binary, addr, old_size, new_size):
        if addr in self.esbs:
            if self.esbs[addr].buffer_old_size != old_size:
                Log.warning('Expand Stack Buffer at' + hex(addr) + ' already existed but size is different: ' + str(old_size) + ' vs ' + str(self.esbs[addr].buffer_old_size))

            if self.esbs[addr].buffer_old_size < old_size:
                Log.warning('Skipping this in ESB')
                return
            
        # Create dummy ELB, so that we will patch it 
        self.esbs[addr] = ExpandStaticBuffer(binary, addr, old_size, new_size)
        fn_use_buffer = self.esbs[addr].functions_use_buffer()
        Log.debug('Expanding static mem: ' + hex(addr) + ' ' + str(fn_use_buffer))
        for fn_entry in fn_use_buffer.keys():
            fn_start, fn_end = self.scoper.get_function_scope(fn_entry)
            elb = self.get_elb(fn_start, fn_end)
            self.set_elb(elb)


    def expand_stack_mem(self, fn_entry, stack_offset, old_size, new_size, force_insts=None, hc_fn_end=None):
        fn_start, fn_end = self.scoper.get_function_scope(fn_entry)
        if hc_fn_end is not None:
            fn_end = hc_fn_end
            elb = self.get_elb(fn_start, fn_end)
            elb.force_insts.update(force_insts)
            elb.add_elb_call(ExpandLocalBufferCall(None, None, stack_offset, old_size, new_size))
            self.set_elb(elb)

    # Obsolete
    def process(self, fn_entry, call_output_reg, call_output_old_size, call_output_new_size):
        Log.warning('EBM: process function is obsolete')
        callers = self.binary.ca.code_refs(fn_entry)
        for caller in callers:
            self._process(caller, call_output_reg, call_output_old_size, call_output_new_size)
            
    def _process(self, call_addr, call_output_reg, call_output_old_size, call_output_new_size):
        fn_start, fn_end = self.scoper.get_function_scope(call_addr)
        elb = self.get_elb(fn_start, fn_end)
        
        stack_offset, src_reg = elb.add_call(call_addr, call_output_reg, call_output_old_size, call_output_new_size)
        if stack_offset is not None:
            Log.debug('Stack offset that needs to be expanded is at: ' + hex(stack_offset) + ' [' + str(call_output_old_size) + ' -> ' + str(call_output_new_size) + ']')
            self.set_elb(elb)
            return

        # Try with all ancestors of fn_entry. It has to be allocated at some point! TODO: unless it is malloc'd or statically allocated
        callers = self.binary.ca.code_refs(fn_start)
        for caller in callers:
            self._process(caller, src_reg, call_output_old_size, call_output_new_size)

    def get_elb(self, fn_entry, fn_exit):
        if fn_entry not in self.elbs:
            elb = ExpandLocalBuffer(self.binary, fn_entry, fn_exit)
        else:
            elb = self.elbs[fn_entry]
            
        if elb.end_vaddr != fn_exit:
            raise ValueError('Wrong end vaddr for expand local buffer: ' + hex(fn_exit) + ' ' + hex(elb.end_vaddr))
        return elb

    def set_elb(self, elb):
        if elb.start_vaddr in self.elbs:
            # Make sure fn_exit is correct
            if elb.end_vaddr != self.elbs[elb.start_vaddr].end_vaddr:
                raise ValueError('Wrong end vaddr for expand local buffer: ' + hex(fn_exit) + ' ' + hex(self.elbs[fn_entry].end_vaddr))

        self.elbs[elb.start_vaddr] = elb
        
class ExpandLocalBufferCall:

    def __init__(self, addr, reg, stack_offset, old_size, new_size):
        self.addr = addr
        self.reg = reg
        self.old_size = old_size
        self.new_size = new_size
        self.stack_offset = stack_offset
        self.diff_size = new_size - old_size

class ExpandLocalBuffer:

    def __init__(self, binary, fn_entry, fn_exit):
        self.binary = binary
        self.start_vaddr = fn_entry
        self.end_vaddr = fn_exit
        self.assembly = self.disassemble()
        self.stack_size = self.get_initial_stack_size()
        self.mod_assembly = {}
        self.loop_termination_conditions = {}
        self.force_insts = {}
        self.elb_calls = []

    # Compute a new stack offset w.r.t RSP
    # Computation is really simple: if old_offset < base_offset+original_size, new_offset = old_offset
    # Otherwise, new_offset = old_offset + (new_size - original_size)
    def new_stack_offset(self, op, stack_size):
        if not op_access_stack(op):
            return None

        # Access to stack by using BP and SP registers is fine, dont need to modify
        if op.type == X86_OP_REG and op.reg == X86_REG_RBP:
            return None
        if op.type == X86_OP_REG and op.reg == X86_REG_RSP:
            return None

        if op.type == X86_OP_MEM:
            old_offset = stack_offset(op, stack_size)

            # Assuming elb_calls is sorted
            size_change = 0
            for elbc in self.elb_calls:
                # TODO: is it < or <=??
                if old_offset < elbc.stack_offset + elbc.old_size:
                    return old_offset + size_change
                else:
                    size_change += elbc.diff_size
            return old_offset + size_change

        raise NotImplementedError("Unimplement new_stack_offset for op: " + str(op))

    def update_loop_termination_condition(self, tc):
        if tc.addr not in self.loop_termination_conditions:
            self.loop_termination_conditions[tc.addr] = tc
        else:
            Log.debug('Alrdy existed: Skipping Loop termination condition at addr: '+ hex(tc.addr))

    # Re-calculate displacement w.r.t. RBP or RSP after expanding buffer to the new size
    def compute_new_disp(self, op, current_stack_size):

        # If it's not mem type, there's no displacement/offset
        if op.type != X86_OP_MEM:
            return None, None
        # Compute new stack offset w.r.t RSP
        new_offset = self.new_stack_offset(op, current_stack_size)

        # Compute displacement w.r.t base register (either RBP or RSP)
        if new_offset is not None:
            # If its RSP, just return our new_offset
            if op.mem.base == X86_REG_RSP:
                return new_offset, op.mem.disp

            # If it's RBP, we compute displacement based on new_offset
            # E.g. if stack size is 0x50 and new offset is 0x40, disp w.r.t RBP is 0x40-0x50=-0x10,
            # then if we increase stack size to 0x60 and new offset becomes 0x40 -> our new disp w.r.t RBP is 0x40-0x60=-0x20
            if op.mem.base == X86_REG_RBP:
                return new_offset - (current_stack_size+self.total_diff()), op.mem.disp

        return None, None

    def total_diff(self):
        diff = 0
        for elbc in self.elb_calls:
            diff += elbc.new_size - elbc.old_size
        return diff


    def expand(self):
        # First increase the overall stack size
        diff = self.total_diff()
        original_stack_size = self.get_initial_stack_size()
        new_stack_size = original_stack_size + diff

        # Increase stack size in prologue
        ss_prologue, stack_prologue = self.get_stack_size_from_prologue()
        if stack_prologue is None:
            Log.warning("Stack Prologue is null")
            start_check_addr = self.start_vaddr
        else:
            self.mod_assembly[stack_prologue.address] = replace_disp(construct_asm(stack_prologue), original_stack_size, new_stack_size)
            start_check_addr = stack_prologue.address

        # Increase stack size in epilogue (this is optional e.g., O0 does not subtract it back)
        ss_epilogue, stack_epilogue = self.get_stack_size_from_epilogue()
        end_check_addr = self.end_vaddr

        if stack_prologue is not None and stack_epilogue.address != stack_prologue.address and ss_prologue == ss_epilogue:
            self.mod_assembly[stack_epilogue.address] = replace_disp(construct_asm(stack_epilogue), original_stack_size, new_stack_size)
            end_check_addr = stack_epilogue.address

        # Only consider instructions in [start_check_addr, end_check_addr]
        # Ideally, the range is the same as [prologue.address, epilogue.address] but epilogue might not exist
        current_stack_size = self.stack_size
        Log.debug("Prologue inst: "+hex(start_check_addr)+" Last inst: "+hex(end_check_addr))
        for inst in self.assembly:
            if inst.address <= start_check_addr or inst.address == end_check_addr:
                continue

            if stack_size_change(inst) != 0:
                Log.debug('StackSizeChange from: ' + str(current_stack_size) + ' to: ' + str(current_stack_size+stack_size_change(inst)) + 'by inst: ' + construct_asm(inst))
                #current_stack_size += stack_size_change(inst)


                if current_stack_size == 0:
                    Log.debug('Breaking!')
                    #break

            inst_asm = construct_asm(inst)
            if not inst_access_stack(inst) and inst.address not in self.force_insts.keys():
                if 'rbp' in inst.op_str or 'rsp' in inst.op_str:
                    Log.warning(construct_asm(inst)+' not access stack but it does!')
                    #raise ValueError(construct_asm(inst), ' not access stack but maybe it does?')
                continue

            #if 'add' in inst_asm:
            #    inst_asm = replace_disp(inst_asm, 0x108, 0x178, False)
                
            for op in inst.operands:
                new_disp, old_disp = self.compute_new_disp(op, current_stack_size)
                if new_disp > current_stack_size+sum([x.diff_size for x in self.elb_calls]):
                    Log.warning("Disp > CSS "+construct_asm(inst)+"::"+hex(new_disp)+" vs "+hex(current_stack_size))
                    #continue

                if new_disp is not None and new_disp != old_disp:
                    inst_asm = replace_disp(inst_asm, old_disp, new_disp)

            # Check for new termination condition:
            if inst.address in self.loop_termination_conditions:
                new_tc = self.loop_termination_conditions[inst.address]
                inst_asm = replace_disp(inst_asm, new_tc.before, new_tc.after, False)

            if inst.address in self.force_insts.keys():
                inst_asm = replace_disp(inst_asm, self.force_insts[inst.address]['old-desp'], self.force_insts[inst.address]['new-desp'])
                Log.warning("Force changing inst from "+construct_asm(inst)+" to "+inst_asm)
                

            # Check if inst_asm has changed
            if inst_asm != construct_asm(inst):
                self.mod_assembly[inst.address] = inst_asm
                Log.debug(hex(inst.address) + ': ' + construct_asm(inst) + '------>' + inst_asm)

        return self.mod_assembly

    def add_elb_call(self, elb_call):
        for ec in self.elb_calls:
            if ec.stack_offset == elb_call.stack_offset:
                return
            self.elb_calls.append(elb_call)
            self.elb_calls.sort(key=operator.attrgetter('stack_offset'))

    def add_call(self, call_addr, call_output_reg, call_output_old_size, call_output_new_size):
        offset, call_output_src_reg = self.get_stack_offset(call_addr, call_output_reg)
        if offset is None:
            return offset, call_output_src_reg
        # Check if offset is already in the list that will be expanded
        for elb_call in self.elb_calls:
            if elb_call.stack_offset == offset:
                if elb_call.old_size != call_output_old_size \
                   or elb_call.new_size != call_output_new_size or elb_call.reg != call_output_reg:
                    #print hex(elb_call.addr), hex(call_addr), elb_call.old_size, call_output_old_size, elb_call.new_size, call_output_new_size, elb_call.reg, call_output_reg
                    raise ValueError('Something is wrong here')
                return offset, None
            self.elb_calls.append(ExpandLocalBufferCall(call_addr, call_output_reg, offset, call_output_old_size, call_output_new_size))
            self.elb_calls.sort(key=operator.attrgetter('stack_offset'))
        return offset, call_output_src_reg

    def get_stack_offset(self, call_addr, call_output_reg):
        return self._get_stack_offset(call_addr, call_output_reg, None)

    # TODO: this is wrong, we have to account if inst changes stack size too, so cannot use self.stack_size directly!
    # TODO: has to be reversed based on CFG, not linear
    def _get_stack_offset(self, call_addr, call_output_reg, call_src_reg=None):
        for inst in reversed(self.assembly):
            if inst.address > call_addr:
                continue
            # inst ``call_output_reg" MEM/REG
            if is_dest(inst, call_output_reg):

                offset = stack_offset(inst.operands[ELB_SRC_REG], self.stack_size)
                if offset is None:
                    if inst.operands[ELB_SRC_REG].type == X86_OP_REG:
                        src_reg = inst.operands[ELB_SRC_REG].reg
                        Log.debug('Source is a register %d, recursively call!' % inst.operands[ELB_SRC_REG].reg)
                        return self._get_stack_offset(inst.address, inst.operands[ELB_SRC_REG].reg, src_reg)
                    else:
                        raise NotImplementedError("Not sure how to determine stack offset from instruction: " + construct_asm(inst))

                return offset, call_src_reg
        return None, call_src_reg

    # Return a dict containing assembly instructions that need to replace the old ones after expanding the buffer
    def expand_local_buffer(self, buffer_offset, original_size, new_size):
        # First increase the overall stack size
        diff = new_size - original_size
        original_stack_size = self.get_initial_stack_size()
        new_stack_size = original_stack_size + diff

        # Increase stack size in prologue
        ss_prologue, stack_prologue = self.get_stack_size_from_prologue()
        self.mod_assembly[stack_prologue.address] = replace_disp(construct_asm(stack_prologue), original_stack_size, new_stack_size)
        start_check_addr = stack_prologue.address

        # Increase stack size in epilogue (this is optional e.g., O0 does not subtract it back)
        ss_epilogue, stack_epilogue = self.get_stack_size_from_epilogue()
        end_check_addr = self.end_vaddr

        if stack_epilogue.address != stack_prologue.address and ss_prologue == ss_epilogue:
            self.mod_assembly[stack_epilogue.address] = replace_disp(construct_asm(stack_epilogue), original_stack_size, new_stack_size)
            end_check_addr = stack_epilogue.address

        # Only consider instructions in [start_check_addr, end_check_addr]
        # Ideally, the range is the same as [prologue.address, epilogue.address] but epilogue might not exist
        current_stack_size = self.stack_size
        for inst in self.assembly:
            if inst.address <= start_check_addr or inst.address >= end_check_addr:
                continue

            if stack_size_change(inst) != 0:
                print ('StackSizeChange from: ', current_stack_size, ' to: ', current_stack_size+stack_size_change(inst), 'by inst: ', construct_asm(inst))
                current_stack_size += stack_size_change(inst)

            inst_asm = construct_asm(inst)
            if not inst_access_stack(inst):
                if 'rbp' in inst.op_str or 'rsp' in inst.op_str:
                    raise ValueError(construct_asm(inst), ' not access stack but maybe it does?')
                continue

            for op in inst.operands:
                new_disp, old_disp = compute_new_disp(op, buffer_offset, original_size, new_size, current_stack_size)
                if new_disp is not None and new_disp != old_disp:
                    inst_asm = replace_disp(inst_asm, old_disp, new_disp)

            # Check if inst_asm has changed
            if inst_asm != construct_asm(inst):
                self.mod_assembly[inst.address] = inst_asm

        return self.mod_assembly

    def disassemble(self):
        content = self.binary.angr_proj.loader.memory.read_bytes(self.start_vaddr, self.end_vaddr - self.start_vaddr)
        self.binary.angr_proj.arch.capstone.syntax = CS_OPT_SYNTAX_ATT
        return list(self.binary.angr_proj.arch.capstone.disasm(bytearray(content), self.start_vaddr))

    def get_initial_stack_size(self):
        # Prologue always consists of sub(or add) rsp, $const (if the function uses stack)
        imm, inst = self.get_stack_size_from_prologue()
        return imm if imm is not None else 0

    def get_stack_size_from_prologue(self):
        return self._get_stack_size(self.assembly)

    def _get_stack_size(self, asm_insts):
        # Find the first instruction identifying stack setup, e.g.:
        # sub rsp, const or add rsp, const
        for inst in asm_insts:
            # Ignore changing stack size by pushing/popping
            if inst.mnemonic in ['pushq', 'popq']:
                continue
            stack_diff = stack_size_change(inst)
            if stack_diff != 0:
                return abs(stack_diff), inst

        return None, None


    def get_stack_size_from_epilogue(self):
        return self._get_stack_size(reversed(self.assembly))

