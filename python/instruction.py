from binary import *
import sys
from alice_util import parse_hex, str_to_int

class AbstractInstruction(BinaryObject):

    @staticmethod
    def get_opcode(format):
        pass

    @staticmethod
    def name():
        return "AbstractInstruction"

class CallInst(AbstractInstruction):

    @staticmethod
    def get_opcode(format):
        return parse_hex('e8', format)

    @staticmethod
    def name():
        return "call"

    def __init__(self, capstone_inst):
        # self.base_vaddr = start_vaddr
        # self.endian = endian
        # if format == "hex":
        #     self.bytes = parse_hex(str, "bytearray")
        # elif format == "bytearray":
        #     self.bytes = str
        # else:
        #     raise ValueError("Unsupported Format " + format)
        # self.target_addr = str_to_int(self.bytes[self.target_addr_byteidx():self.target_addr_byteidx()+8], "bytearray", endian)
        self.capstone = capstone_inst
        self.base_vaddr = capstone_inst.address
        self.bytesize = capstone_inst.size
        try:
            self.call_addr = int(self.capstone.op_str, 0)
        except Exception as e:
            raise TypeError("EEE")

    def get_target_relative_addr(self):
        return self.call_addr - self.base_vaddr

    def get_target_absolute_addr(self):
        #return self.base_vaddr + self.get_target_relative_addr() + self.bytesize()
        return self.call_addr

class RetInst(AbstractInstruction):

    def __init__(self, capstone_inst):
        self.base_vaddr = capstone_inst.address
        self.bytesize = capstone_inst.size

    @staticmethod
    def get_opcode(format):
        return parse_hex('c3', format)

    @staticmethod
    def name():
        return "ret"

    def get_target_relative_addr(self):
        return 0

    def get_target_absolute_addr(self):
        return 0



# Ignore the prefix, include only 64-bit, not 32-bit inst
# Start at 8d
class LongLeaInst(AbstractInstruction):

    # def __init__(self, str, start_vaddr, format, endian):
    #     self.base_vaddr = start_vaddr
    #     self.endian = endian
    #     if format == "hex":
    #         self.bytes = parse_hex(str, "bytearray")
    #     elif format == "bytearray":
    #         self.bytes = str
    #     else:
    #         raise ValueError("Unsupported Format " + format)
    #     self.target_addr = str_to_int(self.bytes[self.target_addr_byteidx():self.target_addr_byteidx()+8], "bytearray", endian)

    def __init__(self, capstone_inst):
        if capstone_inst.size != 7:
            raise TypeError('ByteSize of LongLea has to be 7 not ', capstone_inst.size)
        self.base_vaddr = capstone_inst.address
        self.disp = capstone_inst.disp
        self.bytesize = capstone_inst.size

    @staticmethod
    def get_opcode(format):
        return parse_hex('8d', format)

    @staticmethod
    def name():
        return "lea"

    def get_target_relative_addr(self):
        return self.disp

    def get_target_absolute_addr(self):
        #return self.base_vaddr + self.get_target_relative_addr() + self.bytesize()
        return self.base_vaddr + self.disp + self.bytesize

class MovdqaInst(AbstractInstruction):
    def __init__(self, capstone_inst):
        if capstone_inst.size != 8:
            raise TypeError('ByteSize of Movdqa has to be 8 not ', capstone_inst.size)
        self.base_vaddr = capstone_inst.address
        self.disp = capstone_inst.disp
        self.bytesize = capstone_inst.size

    @staticmethod
    def get_opcode(format):
        return parse_hex('66', format)

    @staticmethod
    def name():
        return "movdqa"

    def get_target_relative_addr(self):
        return self.disp

    def get_target_absolute_addr(self):
        #return self.base_vaddr + self.get_target_relative_addr() + self.bytesize()
        return self.base_vaddr + self.disp + self.bytesize




INSTRUCTION_TYPES = {'call':CallInst, 'ret':RetInst, 'lea':LongLeaInst, 'movdqa':MovdqaInst}
class InstructionFactory(object):

    MAX_INST_SIZE = 32

    @staticmethod
    #def create_instruction(inst_type, binary, start_vaddr, *kwargs):
    def create_instruction(capstone_inst):
        try:
            # cs = binary.angr_proj.arch.capstone
            # capstone_inst = None
            # for inst in cs.disasm(''.join(binary.angr_proj.loader.memory.read_bytes(start_vaddr, InstructionFactory.MAX_INST_SIZE)), start_vaddr):
            #     capstone_inst = inst
            #     break
            inst = INSTRUCTION_TYPES[capstone_inst.insn_name()]
            # if not capstone_inst or capstone_inst.size != inst.bytesize or capstone_inst.insn_name() != inst.name():
            #     return None
            #
            # out_inst = inst(str(capstone_inst.bytes), start_vaddr, "bytearray", binary.endian, *kwargs)
            return inst(capstone_inst)
        except Exception as e:
            return None

if __name__ == "__main__":


    binary = Binary('../testbench/bin/hash/sha1.o')
    d = binary.angr_proj.arch.capstone.disasm(bytearray("\x4c\x8d\x25\xce\x0d\x20\x00"), 0x40103b)
    lea = InstructionFactory.create_instruction(d.next())
    assert (lea.get_target_relative_addr() == 0x200dce)
    assert (lea.get_target_absolute_addr() == 0x601e10)

    addr = 0x47ac98
    d = binary.angr_proj.arch.capstone.disasm(bytearray("\xe8\xf7\xf9\xff\xff"), 0x400c2a)
    d = d.next()
    call = InstructionFactory.create_instruction(d)
    assert (call.get_target_absolute_addr() == 0x400626)


