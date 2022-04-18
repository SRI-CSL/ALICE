from abstract_caller_analysis import AbstractCallerAnalysis
import numpy as np
from instruction import *
import angr

class CallerAnalysis(AbstractCallerAnalysis):

    def __init__(self, binary, deepcopy=False):
        self.disassembly = None
        self.insts = None
        #self.binary = binary
        super(CallerAnalysis, self).__init__(binary, deepcopy)
        self.gather_all_insts()

    # Detect by scanning the binary with respect to absolute addrs
    # And LEA instructions
    def data_refs(self, start_vaddr, end_vaddr=None):
        callers = []
        if end_vaddr is None:
            end_vaddr = start_vaddr

        callers += self.binary.sweep_search(xrange(start_vaddr, end_vaddr), self.binary.format)
        insts = self.search_insts([LongLeaInst.name()], lambda x: x>=start_vaddr and x<=end_vaddr)
        callers += [inst.base_vaddr for inst in insts]
        insts = self.search_insts([MovdqaInst.name()], lambda x: x>=start_vaddr and x<=end_vaddr)
        callers += [inst.base_vaddr for inst in insts]

        return callers

    def code_refs(self, vaddr):
        # return [inst.base_vaddr for inst in self.search_insts([LongLeaInst.name(), CallInst.name()], lambda x: x==vaddr)]
        return [inst.base_vaddr for inst in self.search_insts([CallInst.name()], lambda x: x==vaddr)]

    def disasm(self):
        section_name = self.binary.get_text_section_name()
        try:
            sec = self.binary.angr_proj.loader.main_object.sections_map[section_name]
        except Exception as e:
            raise SectionNotFoundException("Section " + section_name + " not found: " + str(e))
        content = self.binary.angr_proj.loader.memory.load(sec.vaddr, sec.memsize)
        self.disassembly = self.binary.angr_proj.arch.capstone.disasm(bytearray(content), sec.vaddr)

    def gather_all_insts(self):
        if self.disassembly is None:
            self.disasm()

        self.insts = []
        for inst in self.disassembly:
            vaddr = inst.address
            #if inst.address == 0x406387:
            #    raise TypeError('inst: '+inst.insn_name()+ ' '+str(inst)+' '+hex(inst.address))
            inst = InstructionFactory.create_instruction(inst)
            #if vaddr == 0x406387:
            #    raise TypeError('inst: '+str(inst)+' abs disp '+hex(inst.get_target_absolute_addr()))

            if inst is not None:
                self.insts.append(inst)


    # Filter instructions whose fun(target addr) is true
    def search_insts(self, names, fun):
        insts = []

        for inst in self.insts:
            if inst.name() in names and fun(inst.get_target_absolute_addr()):
                insts.append(inst)

        return insts

    def get_func_scope(self, vaddr):
        text_section = self.binary.get_section(self.binary.get_text_section_name())
        # insts = self.search_insts([LongLeaInst.name(), CallInst.name()], lambda x: x>=text_section.start_vaddr and x<=text_section.end_vaddr)
        insts = self.search_insts([CallInst.name()], lambda x: x>=text_section.start_vaddr and x<=text_section.end_vaddr)
        sorted_addrs = [inst.get_target_absolute_addr() for inst in insts]
        sorted_addrs.sort()
        addr_idx = np.searchsorted(sorted_addrs, vaddr)
        entry_addr = text_section.start_vaddr if addr_idx == 0 else sorted_addrs[addr_idx - 1]
        exit_addr = text_section.end_vaddr if addr_idx == len(sorted_addrs) else sorted_addrs[addr_idx]
        #print 'AAA: ', hex(sorted_addrs[addr_idx - 1]), hex(vaddr), hex(entry_addr), hex(exit_addr)
        if exit_addr == vaddr:
            entry_addr = sorted_addrs[addr_idx]
            if addr_idx + 1 >= len(sorted_addrs):
                exit_addr = text_section.end_vaddr
            else:
                exit_addr = sorted_addrs[addr_idx + 1]
        exit_addr = exit_addr - 1
        return entry_addr, exit_addr



if __name__ == "__main__":

    cda = CallerAnalysis(Binary('../testbench/bin/hash/md2.o'))

    for d in cda.insts:
        print (d.name(), hex(d.base_vaddr), hex(d.get_target_relative_addr()), hex(d.get_target_absolute_addr()))

    callers = cda.data_refs(0x400a80, 0x400b83)
    assert (set(callers) == {0x400678, 0x4009a3, 0x400705})
    callers = cda.code_refs(0x400739)
    assert (callers == [0x4008db])
