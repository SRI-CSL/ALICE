import angr
import copy
from alice_util import *

# Very X86-ELF specific
# For other architecture, we need to implement the following classes

class BinaryObject:

    # Caching??

    def get_val(self, format):
        return parse_bytearray(self.get_bytearray(), format)

    def get_bytearray(self):
        return ''.join([x for x in self.bytes])

    def get_hex(self):
        return self.get_bytearray().encode("hex")


class BasicBlock(BinaryObject):

    def __init__(self, angr_bb):
        self.start_vaddr = angr_bb.addr
        self.bytesize = angr_bb.size
        self.end_vaddr = angr_bb.addr + angr_bb.size
        self.bytes = angr_bb.bytes

    def __str__(self):
        return 'BasicBlock: at [' + hex(self.start_vaddr) + ', ' + hex(self.end_vaddr) + '], hex val: ' + self.get_hex()

class SectionNotFoundException(Exception):
    pass

class Section(BinaryObject):

    def __init__(self, name, content, vaddr, bytesize):
        self.name = name
        self.bytes = content
        self.start_vaddr = vaddr
        self.bytesize = bytesize
        self.end_vaddr = vaddr+bytesize

    def contain_addr(self, addr):
        return addr >= self.start_vaddr and addr <= self.end_vaddr

    def __str__(self):
        return 'Section: ' + self.name + ' at [' + hex(self.start_vaddr) + ', ' + hex(self.end_vaddr) + ']'

# Provide angr API and other stuff related to binary
class Binary:

    def __init__(self, exec_path, load_libs=False, format="hex"):
        self.angr_proj = angr.Project(exec_path, auto_load_libs=load_libs)
        self.cache = {}
        self.arch = self.angr_proj.arch.name
        self.endian = self.angr_proj.arch.memory_endness[-2:]
        self.min_addr = self.angr_proj.loader.min_addr
        self.max_addr = self.angr_proj.loader.max_addr
        self.format = format
        self.ref_opcodes = {}
        self.ca = None

    @staticmethod
    def get_text_section_name():
        return ".text"

    @staticmethod
    def get_rodata_section_name():
        return ".rodata"

    def get_ref_inst(self, vaddr):
        out = []
        for insts in self.ref_opcodes.values():
            for inst in insts:
                if inst.get_target_absolute_addr() == vaddr:
                    out.append(inst)

        return out

    def copy(self):
        return copy.deepcopy(self)

    def get_section(self, section_name):
        if section_name in self.cache:
            return self.cache[section_name]

        try:
            sec = self.angr_proj.loader.main_object.sections_map[section_name]
        except Exception as e:
            raise SectionNotFoundException("Section " + section_name + " not found: " + str(e))

        content = self.angr_proj.loader.memory.read_bytes(sec.vaddr, sec.memsize)
        section = Section(section_name, content, sec.vaddr, sec.memsize)
        self.cache[section_name] = section
        return section

    # Return simple basic block starting from addr
    def get_bb(self, addr):
        return BasicBlock(self.angr_proj.factory.block(addr))


    # Given the addr, angr API seems to be able to find the correct end_addr of BB
    # BUT, it may not return the correct start_addr
    # Idea: we keep decrementing addr until end_addr becomes differet
    # However, there can be an error when disassembling due to var-size instructions
    # so we output "BB" as a correct basic block if:
    # At iteration (i) BB is generated and
    # Basic blocks generated at iteration (i+1), (i+2), ..., (i+thresh) have different end_addr than that of BB
    def get_accurate_bb(self, addr, thresh=10, num_tries=100):
        block = self.get_bb(addr)
        count = 0
        block_last_addr = block.end_vaddr
        out_block = block
        for cur_addr in xrange(addr - 1, max(addr - num_tries, self.min_addr), -1):
            # while addr < num_tries and addr - idx > self.binary.min_addr:
            prev_block = block
            block = self.get_bb(cur_addr)

            if block.end_vaddr != block_last_addr:
                # Now if the current address results in a different BB and prev block ends with the correct address
                # Store prev_block as an output
                # Here we increment count to reflect that how many times in a row the address ends with the correct address
                if prev_block.end_vaddr == block_last_addr:
                    out_block = prev_block
                count += 1
            else:
                # Reset the counter if the address falls back into the same BB -> error from BB generation
                count = 0
            if count >= thresh:
                break

        return out_block


    def sweep_search(self, absolute_vaddrs, str_format):
        queries = []

        for addr in absolute_vaddrs:
            query = format(addr, 'x')

            if self.endian == "LE":
                query = flip_str_endian(query)
            queries.append(parse_hex(query, str_format))

        text_section = self.get_section(self.get_text_section_name())
        text_section_val = text_section.get_val(str_format)
        answer = search(text_section_val, queries)
        caller_addrs = [ (idx_to_bytes(item, str_format)+text_section.start_vaddr) for sublist in answer.values() for item in sublist]
        return list(set(caller_addrs))


if __name__ == "__main__":
    bin = Binary('../testbench/bin/hash/sha1.o')
    print 'Binary at adddr: [' + hex(bin.min_addr) + ', ' + hex(bin.max_addr) + ']'

    text_section = bin.get_section('.text')
    rodata_section = bin.get_section('.rodata')
    print text_section.get_hex()
    print rodata_section

    addr = text_section.start_vaddr+0x100
    bb = bin.get_bb(addr)
    print bb

    acc_bb = bin.get_accurate_bb(addr)
    print acc_bb