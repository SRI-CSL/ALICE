from caller_analysis import *
from abstract_locator import AbstractLocator
from desc import *
from elf_binary import *
from alice_util import advanced_search
from alice_logger import AliceLog
import logging

Log = AliceLog['locator']
Log.setLevel(logging.DEBUG)

# ----------------- Class implementation -----------------------

class FastLocator(AbstractLocator):
    FORMAT = "bytearray"

    def get_address_locations(self, crypto_desc):
        addrs = []
        bbs, rodata_contain_ind = self._locate(crypto_desc)
        Log.debug("BBS: "+str(bbs)+' '+str(rodata_contain_ind))
        # TODO: quickfix
        #if not self.contain(crypto_desc, bbs, rodata_contain_ind):
        if not rodata_contain_ind and not bbs:
            Log.debug("Not contain")
            return []

        for bb in bbs:
            addrs.append((bb.start_vaddr+bb.end_vaddr)/2) # why divide by 2?

        if self.binary.ca is None:
            self.binary.ca = CallerAnalysis(self.binary)
        if rodata_contain_ind is not None and rodata_contain_ind:
            for rodata_const in crypto_desc.rodata_contain:
                for data_absolute_addr in rodata_contain_ind[rodata_const]:
                    Log.debug("Searching ref data: "+hex(data_absolute_addr)+' : '+hex(data_absolute_addr+idx_to_bytes(len(rodata_const), self.binary.format)))
                    data_ref_addrs = self.binary.ca.data_refs(data_absolute_addr, data_absolute_addr+idx_to_bytes(len(rodata_const), self.binary.format))
                    addrs += data_ref_addrs
        Log.debug("Find: "+str(rodata_contain_ind)+" addr refing it: "+str(addrs))
        return list(set(addrs))

    def contain(self, crypto_desc, bbs=None, rodata_contain_ind=None):
        if not bbs or not rodata_contain_ind:
            bbs, rodata_contain_ind = self._locate(crypto_desc)
        res_rodata = (len(rodata_contain_ind.keys()) == len(crypto_desc.rodata_contain))
        res_text = (not crypto_desc.text_contain or not not bbs)
        return res_text and res_rodata

    def _locate(self, crypto_desc):
        # Search in .text section
        blocks = self._locate_bb_level(self.binary.get_text_section_name(), crypto_desc.get_text_contain(self.binary.format), crypto_desc.get_text_not_contain(self.binary.format))

        # Search in .rodata section
        # No need to search in BB level since rodata section has no BB
        # Compute absolute addrs
        rodata_section = self.binary.get_section(self.binary.get_rodata_section_name())
        rodata_contain_ind = self._locate_in_section(self.binary.get_rodata_section_name(), crypto_desc.get_rodata_contain(self.binary.format))
        Log.debug("Find rodata at: "+str(rodata_contain_ind))
        for k in rodata_contain_ind:
            vals = [(idx_to_bytes(x, self.binary.format)+rodata_section.start_vaddr) for x in rodata_contain_ind[k]]
            rodata_contain_ind[k] = vals

        # Maybe rodata const is embedded in .text as in code-data interleaving
        # Again cant really do BB-level search
        # TODO: Do we even need this?
        #if not rodata_contain_ind:
        #    rodata_contain_res = __locate_section_level(self, '.text', crypto_prim.rodata_contain, crypto_prim.rodata_not_contain)
        return blocks, rodata_contain_ind

    # Return all angr basic blocks containing all elements in WL but not containing any element in BL
    def _locate_bb_level(self, section_name, whitelist, blacklist):

        out_blocks = set()

        # First, get all addresses matching any element in WL
        section = self.binary.get_section(section_name)
        answers = self._locate_in_section(section_name, whitelist)

        # If not all elts from WL are found, we exit
        if len(answers.keys()) != len(whitelist):
            return list(out_blocks)

        for const in answers.keys():
            for idx in answers[const]:
                vaddr = section.start_vaddr + idx_to_bytes(idx, self.binary.format)

                if not section.contain_addr(vaddr):
                    continue
                block = self.binary.get_accurate_bb(vaddr)

                wl_ans, bl_ans = advanced_search(block.get_val(self.binary.format), whitelist, blacklist)

                # BB contains all elts from WL but none of elts from BL
                if len(wl_ans.keys()) == len(whitelist) and len(bl_ans.keys()) == 0:
                    out_blocks.add(block)

        return list(out_blocks)

    # Return two dicts corresponding to WL and BL
    # In each dict, you can query, e.g., dict1[e] returns all virtual addresses containing element e (from WL)
    def _locate_in_section(self, section_name, const_list):
        section = self.binary.get_section(section_name)
        Log.debug("Searching section: "+section_name+" const: "+str(const_list))
        return search(section.get_val(self.binary.format), const_list)


if __name__ == "__main__":
    answ = search("abcdef012345abc", ["abc", "f0123"])
    assert (answ["abc"] == [0, 12] and answ["f0123"] == [5])
    answ1, answ2 = advanced_search("abcdef012345abc", ["abc"], ["f01"])
    assert (answ1["abc"] == [0, 12] and answ2["f01"] == [5])
    binary = Binary('../testbench/bin/hash/sha1.o')
    locator = FastLocator(binary)
    assert (locator.contain(SHA1Desc))
    assert (not locator.contain(MD2Desc))
    assert (locator.get_address_locations(SHA1Desc) == [0x400b80])

    binary = Binary('../testbench/bin/hash/md2.o')
    locator = FastLocator(binary)
    text_out, ro_out = locator._locate(MD2Desc)
    assert (text_out == [])
    assert (ro_out[MD2Desc.rodata_contain[0]] == [0x400a80])
    assert (not locator.contain(SHA1Desc))
    assert (locator.contain(MD2Desc))
    assert (locator.get_address_locations(MD2Desc) == [0x400678, 0x400705])
