from abstract_caller_analysis import *
from alice_util import in_range
from caller_analysis import *
from alice_logger import AliceLog
import logging

Log = AliceLog['locator']
Log.setLevel(logging.DEBUG)



class AngrCallerAnalysis(AbstractCallerAnalysis):

    def __init__(self, binary, cfg=None, deepcopy=False):
        self.disassembly = None
        self.insts = None
        #self.binary = binary
        super(AngrCallerAnalysis, self).__init__(binary, deepcopy)
        self.simple_ca = CallerAnalysis(binary, deepcopy)
        if cfg is not None:
            self.cfg = cfg
        else:
            self.cfg = binary.angr_proj.analyses.CFGFast(show_progressbar=True, symbols=False)
        self.fn_start_addrs = None

    def data_refs(self, start_vaddr, end_vaddr=None):
        return self.simple_ca.data_refs(start_vaddr, end_vaddr)

    def code_refs(self, vaddr):
        # Who is calling ``vaddr"
        out = []
        for call, call_type in self.cfg.functions.callgraph.edges.items():
            caller = call[0]
            callee = call[1]
            if callee == vaddr:
                caller_start, caller_end = self.get_func_scope(caller)
                out += self.get_inst_call_addr(caller_start, caller_end, vaddr)

        return out
        #return [inst.base_vaddr for inst in self.simple_ca.search_insts([CallInst.name()], lambda x: x == vaddr)]

    def function_callers(self, fn_start):
        out = []
        for call, call_type in self.cfg.functions.callgraph.edges.items():
            caller = call[0]
            callee = call[1]
            if callee == fn_start:
                out.append(caller)

        return out

    # TODO: use angr's way of doing this (handling indirect_jumps too!)
    # Based on cfg.get_node(caller_start).successors
    def get_inst_call_addr(self, caller_start, caller_end, call_target):

        content = self.binary.angr_proj.loader.memory.read_bytes(caller_start, caller_end-caller_start)
        insns = self.binary.angr_proj.arch.capstone.disasm(bytearray(content), caller_start)
        out = []
        for inst in insns:
            i = InstructionFactory.create_instruction(inst)
            if i is not None and i.name() == 'call' and i.get_target_absolute_addr() == call_target:
                out.append(i.base_vaddr)
        return out


    def get_fn_start_addrs(self):
        out = set()
        for fn_addr in self.cfg.functions.callgraph.nodes:
            out.add(fn_addr)
        out = list(out)
        out.sort()
        return out

    def get_func_scope(self, vaddr):
        if self.fn_start_addrs is None:
            self.fn_start_addrs = self.get_fn_start_addrs()

        addr_idx = np.searchsorted(self.fn_start_addrs, vaddr, side='right')
        entry_addr = self.fn_start_addrs[addr_idx - 1]
        # exit_addr = self.cfg.functions[entry_addr].size + entry_addr
        exit_addr = entry_addr

        # Get exit point by looking at the last endpoints
        # TODO: this is WRONG, the end of function can also be a jump, not exit
        #for ep in self.cfg.functions[entry_addr].endpoints:
        #    if ep is not None and ep.addr+ep.size > exit_addr:
        #        exit_addr = ep.addr+ep.size
        exit_addr = self.fn_start_addrs[addr_idx]

        #Log.debug('AAAA: entry'+ hex(entry_addr)+' exit: '+ hex(exit_addr)+' ?? '+ hex(self.fn_start_addrs[addr_idx]))
        return entry_addr, exit_addr

