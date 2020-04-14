import angr
import sys
import numpy as np
from locator import *
from desc import *
from scope_template import *
from asserter import *

def signed_hex_str_to_int(addr):
    # Look for the negative output
    if addr[0].lower() == 'f':
        addr = - (0x100000000 - int('0x'+addr, 0))
    else:
        addr = int('0x'+addr, 0)
    return addr

def relative_to_absolute_addr(base_addr, relative_addr):
    return relative_addr + base_addr 


class CryptoScope:

    INVALID_ADDR = -1

    def __init__(self, exec_path):
        self.locator = CryptoLocator(exec_path)
        self.proj = angr.Project(exec_path)
        self.__call_inst_addrs = self._get_call_inst_addrs()
        self.__lea_inst_addrs = self._get_lea_inst_addrs()
        self.reset_checked_entries()

    def _get_call_opcode(self):
        return 'e8'

    def _get_ret_opcode(self):
        return 'c3'

    def _get_lea_opcode(self):
        return '8d'

    # push ebp
    # mov ebp, esp
    def _get_function_preamble(self):
        return '554889e5'

    # Entry point = Backward search till first address containing magic sequence (554889e5)
    # Exit point = Forward search till last RET before next magic sequence
    def scope2(self, addr):
        function_preamble = self._get_function_preamble()
        sec = self.proj.loader.main_object.sections_map['.text']
    
        # Backward search till addr containing magic sequence
        entry_addr = self.backward_search(addr, sec.vaddr, function_preamble)

        # Forward search till addr containing magic sequence
        exit_addr = self.forward_search(addr, sec.vaddr+sec.memsize, function_preamble)

        # Backward search till RET addr
        if exit_addr != self.INVALID_ADDR:
            exit_addr = self.backward_search(exit_addr, sec.vaddr, self._get_ret_opcode())
        return entry_addr, exit_addr

    def forward_search(self, start_addr, end_addr, search_insns):
        return self.search(start_addr, end_addr, search_insns, False)

    def backward_search(self, start_addr, end_addr, search_insns):
        return self.search(start_addr, end_addr, search_insns, True)

    # Forward/backward search till the first search_insns are found
    def search(self, start_addr, end_addr, search_insns, backward=False):
        num_insns = len(search_insns)/2
        inc = -1 if backward else 1
        for cur_addr in xrange(start_addr, end_addr, inc):
            data = self.proj.loader.memory.read_bytes(cur_addr, num_insns)
            if strarr_to_hex(data) == search_insns:
                return cur_addr
        return self.INVALID_ADDR

    # Get all addresses containing call instructions
    def _get_call_inst_addrs(self):
        call_opcode = self._get_call_opcode()
        hex_str, start_vaddr, size = self.locator.get_hex_data_from_section('.text')
        call_idx, _ = contain(hex_str, [call_opcode])
        return call_idx[call_opcode]

    # Get all addresses containing lea instructions
    def _get_lea_inst_addrs(self):
        lea_opcode = self._get_lea_opcode()
        hex_str, start_vaddr, size = self.locator.get_hex_data_from_section('.text')
        lea_idx, _ = contain(hex_str, [lea_opcode])
        return lea_idx[lea_opcode]

    # lea reg, $addr
    def _get_lea_target_relative_addr(self, hex_str, lea_opcode_idx):
        return signed_hex_str_to_int(flip_str_endian(hex_str[lea_opcode_idx+4:lea_opcode_idx+12]))

    # call $addr
    def _get_call_target_relative_addr(self, hex_str, call_opcode_idx):
        return signed_hex_str_to_int(flip_str_endian(hex_str[call_opcode_idx+2:call_opcode_idx+10]))

    # Return a list of addresses that call "callee_addr"
    def get_callers(self, callee_addr):
        caller_addrs, _ = self._get_caller_addrs(lambda x: x == callee_addr)   
        return caller_addrs 

    # Return a list of (absolute) addresses of call instructions with filter_func($dest) is True
    def _get_caller_addrs(self, filter_func):
        hex_str, start_vaddr, size = self.locator.get_hex_data_from_section('.text')
        caller_addrs = []
        callee_addrs = []
        for idx in self.__call_inst_addrs:
            relative_addr = self._get_call_target_relative_addr(hex_str, idx)
            absolute_addr = relative_to_absolute_addr(start_vaddr + int(idx)/2, relative_addr + 5)
            if filter_func(absolute_addr):
                caller_addrs.append(start_vaddr + int(idx)/2)
                callee_addrs.append(absolute_addr)
        return caller_addrs, callee_addrs

    def _get_load_effective_addrs(self, filter_func):
        hex_str, start_vaddr, size = self.locator.get_hex_data_from_section('.text')
        lea_er_addrs = []
        lea_ee_addrs = []
        for idx in self.__lea_inst_addrs:
            relative_addr = self._get_lea_target_relative_addr(hex_str, idx)
            absolute_addr = relative_to_absolute_addr(start_vaddr + int(idx)/2, relative_addr + 6) # 6 is size(lea inst)
            if filter_func(absolute_addr):
                lea_er_addrs.append(start_vaddr + int(idx)/2)
                lea_ee_addrs.append(absolute_addr)
        return lea_er_addrs, lea_ee_addrs


    # Entry point = Get a list of all destination addresses from "call $dest" instructions
    #               And select the one that is smaller than and the closest to addr
    # Exit point = Forward search till find last RET before the next "dest" retrieved from above
    #               if there's no next "dest", simply return last RET
    def scope(self, addr, refine_exit=True):
        hex_str, start_vaddr, size = self.locator.get_hex_data_from_section('.text')

        # Collect a list of called absolute addresses, i.e., all $dest from ``call $dest"
        lamb = lambda x: x<start_vaddr+size and x>start_vaddr
        _, called_absolute_addrs = self._get_caller_addrs(lamb)

        #_, lea_ee_absolute_addrs = self._get_load_effective_addrs(lamb)
        #called_absolute_addrs += lea_ee_absolute_addrs
        
        # If we were to insert addr into the sorted list,
        # entry point would be element right to the left of addr and exit point would be (element to the right - 1)
        called_absolute_addrs.sort()
        addr_idx = np.searchsorted(called_absolute_addrs, addr)
        entry_addr = start_vaddr if addr_idx == 0 else called_absolute_addrs[addr_idx-1]
        exit_addr = start_vaddr + size if addr_idx == len(called_absolute_addrs) else called_absolute_addrs[addr_idx]

        # Decrement exit point since it was the next entry point
        exit_addr = exit_addr - 1

        # Backward search till we find RET instruction so that exit address is accurate
        if refine_exit:
            self.backward_search(exit_addr, start_vaddr, self._get_ret_opcode())

        return entry_addr, exit_addr

    def reset_checked_entries(self):
        self._checked_entries = set()

    def accurate_entry_addr(self, addr, input_str, input_len, output_hexstr, output_byte_len, num_tries=2):
        asserter = CryptoAsserter(self.proj)
        entries, _ = self.generate_all_possible_entries(addr)
        entries = sorted(set(entries))
        print 'All Entries: ', [hex(x) for x in entries]
        for entry in entries:
            if asserter.assert_fn_output(entry, output_hexstr, input_str, input_len, output_byte_len):
                return entry
        #fn_entry = self._accurate_entry_addr_helper(addr, input_str, input_len, output_hexstr, output_byte_len, num_tries, asserter) 
        return None
        #return fn_entry

    # Generate all posible entry points of "addr"
    # If level is 1, return a single entry/exit point that implements the addr's function
    # Otherwise, return multiple entry/exit points that call the addr's function
    def generate_all_possible_entries(self, addr, level=2):
        assert (level > 0), "level can't be less than 1"

        # First, find entry/exit point for addr
        fn_entry, fn_exit = self.scope(addr, False)
        if fn_exit == self.INVALID_ADDR or fn_entry == self.INVALID_ADDR:
            return [], []

        if level == 1:
            return [fn_entry], [fn_exit]

        # Now find all callers to fn_entry    
        caller_addrs = self.get_callers(fn_entry)

        entries = [fn_entry]
        exits = [fn_exit]
        for caller in caller_addrs:
            fn_entry, fn_exit = self.generate_all_possible_entries(caller, level-1)
            if fn_entry and fn_exit:
                entries = entries + fn_entry
                exits = exits + fn_exit

        return entries, exits

    def _accurate_entry_addr_helper(self, addr, input_str, input_len, output_hexstr, output_byte_len, num_tries, asserter):
        if num_tries == 0:
            return self.INVALID_ADDR

        # We don't care about exit
        fn_entry, fn_exit = self.scope(addr, refine_exit=False)
        print 'FN entry: ' + hex(fn_entry) + ' [' + ' '.join(hex(x) for x in self._checked_entries) + ']'
        if fn_exit == self.INVALID_ADDR or fn_entry == self.INVALID_ADDR:
            return self.INVALID_ADDR

        # assert_fn_output is quite expensive - we don't want to check for all entry points
        # We don't want to return error if fn_entry is already checked since its decendants might not be checked yet
        if fn_entry not in self._checked_entries:
            self._checked_entries.add(fn_entry)
            if asserter.assert_fn_output(fn_entry, output_hexstr, input_str, input_len, output_byte_len):
                return fn_entry

        caller_addrs = self.get_callers(fn_entry)    
        for caller in caller_addrs:    
            self._checked_entries.add(caller)
            fn_entry = self._accurate_entry_addr_helper(caller, input_str, input_len, output_hexstr, output_byte_len, num_tries-1, asserter)
            if fn_entry != self.INVALID_ADDR:
                return fn_entry
        return self.INVALID_ADDR

    def filter_scope(self, addr, template, scope_fn, level=0):
        if level >= template.num_levels():
            return [], []

        fn_entry, fn_exit = scope_fn(addr)
        if fn_exit == self.INVALID_ADDR or fn_entry == self.INVALID_ADDR:
            return [], []
    
        if template.compare(fn_exit - fn_entry, level):
            return [fn_entry], [fn_exit]

        caller_addrs, _ = self._get_caller_addrs(lambda x: x == fn_entry)

        entries = []
        exits = []
        for caller in caller_addrs:
            fn_entry, fn_exit = self.filter_scope(caller, template, scope_fn, level+1)
            if fn_entry and fn_exit:
                entries = entries + fn_entry
                exits = exits + fn_exit

        return entries, exits
 

    # Scope based on template
    def ultimate_scope(self, addr, template, scope_fn, level=0):
        if level >= template.num_levels():
            return self.INVALID_ADDR, self.INVALID_ADDR

        fn_entry, fn_exit = scope_fn(addr)
        if fn_exit == self.INVALID_ADDR or fn_entry == self.INVALID_ADDR:
            return self.INVALID_ADDR, self.INVALID_ADDR
    
        if template.compare(fn_exit - fn_entry, level):
            return fn_entry, fn_exit

        caller_addrs, _ = self._get_caller_addrs(lambda x: x == fn_entry)

        entries = []
        exits = []
        for caller in caller_addrs:
            fn_entry, fn_exit = self.ultimate_scope(caller, template, scope_fn, level+1)
            if fn_entry != self.INVALID_ADDR and fn_exit != self.INVALID_ADDR:
                entries.append(fn_entry)
                exits.append(fn_exit)

        if len(entries) > 1:
            print 'Multiple entries/exits are found: ', entries, exits
            print 'Only return the first one!!'

        if len(entries) >= 1:
            return entries[0], exits[0]
        
        return self.INVALID_ADDR, self.INVALID_ADDR
            
if False:
    path = '../testbench/bin/hash/sha1test'
    sc = CryptoScope(path)
    bbs, _ = CryptoLocator(path).locate(SHA1Desc)
    HashTemplate = ScopeTemplate('init-update-final', ['>256', '<512'])
    for bb in bbs:
        addr = bb.addr+bb.size/2
        entry, exit = sc.ultimate_scope(addr, HashTemplate, sc.scope)
        print 'Scope: ' + hex(entry) + ' ' + hex(exit)
        entry, exit = sc.scope(addr)

        print 'Scope1: ' + hex(entry) + ' ' + hex(exit)
        entry, exit = sc.scope2(addr)
        print 'Scope2: ' + hex(entry) + ' ' + hex(exit)
        break
        entry_caller = sc._get_caller_addrs(entry)
        for ec in entry_caller:
            entry, exit = sc.scope(ec)
            print hex(ec) + ' ' + hex(entry) + ' ' + hex(exit)
        entry, exit = sc.scope2(addr)
        print 'Scope: ' + hex(entry) + ' ' + hex(exit)
