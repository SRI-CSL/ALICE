import angr
import subprocess
import math
import ahocorasick
from desc import *
from alice_util import *

def add_element_to_dict(dic, key, val):
    if key in dic:
        dic[key].append(val)
    else:
        dic[key] = [val]
    return dic

def strbyte_to_strhex(data):
    return format(ord(data), '02x')

def strarr_to_hex(list_data):
    return ''.join(strbyte_to_strhex(x) for x in list_data)

# Use Aho-Corasick Algorithm (https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
# If an element from a whitelist or blacklist is in "string", return all locations (indexes) that element occurs
def contain(string, whitelist, blacklist=[]):
    ind_whitelist = {}
    ind_blacklist = {}

    if not whitelist and not blacklist:
        return ind_whitelist, ind_blacklist

    auto = ahocorasick.Automaton()

    alllist = whitelist+blacklist
    for e in alllist:
        auto.add_word(e, e)
    auto.make_automaton()

    for end_ind, e in auto.iter(string):
        start_ind = end_ind - len(e) + 1
        if e in whitelist:
            ind_whitelist = add_element_to_dict(ind_whitelist, e, start_ind)
        if e in blacklist:
            ind_blacklist = add_element_to_dict(ind_blacklist, e, start_ind)

    return ind_whitelist, ind_blacklist

class CryptoLocator:

    def __init__(self, exec_path):
        self.proj = angr.Project(exec_path, auto_load_libs = False)
        self.hex_data = {}

    def contain(self, crypto_prim):
        bbs, rodata_contain_ind = self.locate(crypto_prim)
        res_rodata = (len(rodata_contain_ind.keys()) == len(crypto_prim.rodata_contain))
        res_text = (not crypto_prim.text_contain or not not bbs)
        #for bb in bbs:
        #    print "[" + hex(bb.addr) + ", " + hex(bb.addr+bb.size) + "]"
        return res_text and res_rodata

    def arch(self):
        return self.proj.arch.name

    def endian(self):
        return self.proj.arch.memory_endness[-2:]

    def get_addrs(self, crypto_prim):
        bbs, rodata_contain_ind = self.locate(crypto_prim)
        addrs = []
        for bb in bbs:
            addrs.append(bb.addr)
        data, data_vaddr, data_size = self.get_hex_data_from_section('.text')

        
        assert (len(crypto_prim.rodata_contain) <= 1), "Not support for multiple elements of RO constants"
       
        if len(crypto_prim.rodata_contain) == 0 or len(rodata_contain_ind.keys()) != len(crypto_prim.rodata_contain):
            return addrs
        
        rodata_sec = self.proj.loader.main_object.sections_map['.rodata']

        constant = crypto_prim.rodata_contain[0]
        constant_byte_size = len(constant)/2 # One hex character is 1/2 byte (4 bit)
        constant_data_addr =[hex(x/2 + rodata_sec.vaddr) for x in rodata_contain_ind[constant]]

        print 'Const at: ', constant_data_addr

        # How many do we want to mask?
        #mask_size = 2
        mask_size = int(math.log(constant_byte_size, 16))
        masked_addr = [x[2:-mask_size] for x in constant_data_addr] # remove '0x' too
        flip_masked_addr = flip_list_endian(masked_addr)
        ro_addrs, _ = contain(data, flip_masked_addr)

        ref_addrs = []
        # Validate
        for key in flip_masked_addr:
            for idx in ro_addrs[key]:
                absolute_addr = data_vaddr+idx/2-mask_size/2
                d = self.proj.loader.memory.read_bytes(absolute_addr, (mask_size+len(key))/2)
                d = int('0x' + flip_str_endian(strarr_to_hex(d)), 0)
                for const_addr in constant_data_addr:
                    if d >= int(const_addr, 0) and d <= int(const_addr, 0) + constant_byte_size:
                        ref_addrs.append(absolute_addr)

        
        print 'Ref: ', [hex(x) for x in ref_addrs]
        
        # Now filter out
        addrs += ref_addrs
        return addrs

    def locate(self, crypto_prim):
        #if False:
            # Find plt_name in dynamic linking
            # Name matching can be inaccurate, e.g. 'des' -> 'destroy'
            #plt_out = find_plt_name(self.proj, crypto_prim.name)
            #if len(plt_out) > 0:
            #    print 'Found dynamic linking at: /hash   #    for po in plt_out:
            #        print po + ' : 0x' + str(format(self.proj.loader.main_object.plt[po], 'x'))
        
        # Search in .text section
        blocks = self.__locate_bb_level('.text', crypto_prim.text_contain, crypto_prim.text_not_contain)

        # Search in .rodata section
        # No need to search in BB level since rodata section has no BB
        rodata_contain_ind, rodata_not_contain_ind = self.__locate_section_level('.rodata', crypto_prim.rodata_contain, crypto_prim.rodata_not_contain)

        # Maybe const is embedded in .text
        # Again cant really do BB-level search
        # TODO: Do we even need this?
        #if not rodata_contain_ind:
        #    rodata_contain_res = __locate_section_level(self, '.text', crypto_prim.rodata_contain, crypto_prim.rodata_not_contain)
        return blocks, rodata_contain_ind

    def __get_bb_from_addr(self, addr, accurate=False):
        block = self.proj.factory.block(addr)
        if not accurate:
            return block

        # Given the addr, angr API seems to be able to find the correct end_addr of BB
        # BUT, it may not return the correct start_addr
        # Idea: we keep decrementing addr until end_addr becomes differet
        # However, there can be an error when disassembly so we output "BB" as a correct basic block if:
        # At iteration (i) BB is generated and 
        # Basic blocks generated at iteration (i+1), (i+2), ..., (i+thresh) have different end_addr than that of BB
        # TODO: test more!
        # TODO: maybe we should use angr_project.analyses.CFGFast() instead? Can be very slow for a large file though but maybe more accurate?
        count = 0
        thresh = 10
        correct_end_addr = block.addr+block.size
        out_block = block
        idx = 1
        # TODO: break condition?
        while True:
            prev_block = block
            block = self.proj.factory.block(addr-idx)

            if block.addr+block.size != correct_end_addr:
                # Now if the current address is in a different BB and prev (addr+1) is in the correct BB
                # Store prev_block as an output
                # Here we increment count to reflect that how many times in a row the address is outside the correct BB
                if prev_block.addr+prev_block.size == correct_end_addr:
                    out_block = prev_block
                count = count + 1
            else:
                # Reset the counter if the address falls back into the same BB -> error from BB generation
                count = 0
            if count >= thresh:
                break
            idx = idx + 1

        return out_block

    # Very expensive task for large binary
    def _generate_all_bbs(self):
        sec = self.proj.loader.main_object.sections_map['.text']
        cur_addr = sec.vaddr
        end_addr = sec.vaddr + sec.memsize
        bbs = []
        while cur_addr < end_addr:
            block = self.__get_bb_from_addr(cur_addr, False)
            if block.size <= 0:
                cur_addr += 1
            else: 
                bbs.append(block)
                cur_addr += block.size
        return bbs    

    # Return all basic blocks containing all elements in WL but not containing any element in BL
    def __locate_bb_level(self, section_name, whitelist, blacklist):
        data, data_vaddr, data_size = self.get_hex_data_from_section(section_name)
        data_idx = 0
        out_blocks = set()

        # First, get all addresses matching any element in WL
        idx, _ = contain(data, whitelist)

        # If not all elts from WL are in data, return
        if len(idx.keys()) != len(whitelist):
            return list(out_blocks)

        for key in idx:
            for loc in idx[key]:
                sec_idx = int(loc)/2
                if sec_idx > data_size:
                    continue
                block = self.__get_bb_from_addr(data_vaddr+sec_idx, True)
                bb_hex = strarr_to_hex(block.bytes)

                ind_wl, ind_bl = contain(bb_hex, whitelist, blacklist)

                # BB contains all elts from WL but none of elts from BL
                if len(ind_wl.keys()) == len(whitelist) and len(ind_bl.keys()) == 0:
                    out_blocks.add(block)

        return list(out_blocks)

    # Return two dicts corresponding to WL and BL
    # In each dict, you can query, e.g., dict1[e] returns all virtual addresses containing element e (from WL)
    def __locate_section_level(self, section_name, whitelist, blacklist):
        data, _, _ = self.get_hex_data_from_section(section_name)
        if not data:
            return {}, {}

        return contain(data, whitelist, blacklist)

    def get_hex_data_from_section(self, section_name, cached=True):
        data = ""
        try:
            sec = self.proj.loader.main_object.sections_map[section_name]
        except Exception as e:
            print e
            return data, 0, 0
        
        if sec.memsize == 0:
            return data, 0, 0

        if cached and section_name in self.hex_data:
            return self.hex_data[section_name], sec.vaddr, sec.memsize

        # TODO: Load binary in chunk to reduce memory usage
        data = self.proj.loader.memory.read_bytes(sec.vaddr, sec.memsize)
        print type(data[0]), data[0]
        data = strarr_to_hex(data)
        if cached:
            self.hex_data[section_name] = data
        return data, sec.vaddr, sec.memsize

if False:
    test_folders = ['app/curl']
    for folder in test_folders:
        exec_paths = subprocess.check_output('find ../testbench/bin/' + folder + ' -executable -type f', shell=True)
        exec_paths = [s.strip() for s in exec_paths.splitlines()]
        crypto_primitives = [AESDesc] #CurveSuiteDesc + HashSuiteDesc + BlockCipherSuiteDesc
        for idx, exec_path in enumerate(exec_paths):
            print exec_path
            cl = CryptoLocator(exec_path)
            print cl.arch()
            print '\n\nFile: ' + exec_path + ' (' + str(idx+1) + '/' + str(len(exec_paths)) + ') contains: '
            for crypto_desc in crypto_primitives:
                print crypto_desc.name + ' ? ' + ("YES" if cl.contain(crypto_desc) else "")
                print cl.get_addrs(crypto_desc)
