from abstract_scoper import *
from fast_locator import *
from alice_logger import AliceLog
import logging

Log = AliceLog['locator']
Log.setLevel(logging.DEBUG)


class FastScoper(AbstractScoper):


    def get_hierarchical_scopes(self, address, height=2):
        if height < 0:
            return [], []

        entry, exit = self.get_function_scope(address)
        entries = [entry]
        exits = [exit]
        if height == 0:
            return [entry], [exit]

        vaddrs = self.binary.ca.code_refs(entry)

        for vaddr in vaddrs:
            et, ex = self.get_hierarchical_scopes(vaddr, height-1)
            entries += et
            exits += ex

        return entries, exits

    # Return a bound (entry and exit points) of a function
    # that contains ``address"
    def get_function_scope(self, address):
        if self.binary.ca is None:
            self.binary.ca = CallerAnalysis(self.binary)
        return self.binary.ca.get_func_scope(address)

if __name__ == "__main__":

    binary = Binary('../testbench/bin/hash/sha1.o')
    locator = FastLocator(binary)
    addrs = locator.get_address_locations(SHA1Desc)
    scoper = FastScoper(binary)
    start, end = scoper.get_function_scope(addrs[0])
    assert (start == 0x400b3e)
    assert (end == 0x400bc2)

    entries, exits = scoper.get_hierarchical_scopes(addrs[0])
    print ([hex(x) for x in entries])

    # TODO: addressing is wrong!
    assert (set([0x400b3e, 0x400ee4]).issubset(set(entries)))

    binary = Binary('../testbench/bin/hash/md2.o')
    locator = FastLocator(binary)
    addrs = locator.get_address_locations(MD2Desc)
    scoper = FastScoper(binary)
    start, end = scoper.get_function_scope(addrs[0])
    assert (start == 0x4005d6)
    assert (end == 0x400738)

    entries, exits = scoper.get_hierarchical_scopes(addrs[0])
    assert (set(entries) == set([0x4005d6, 0x400791, 0x40081a, 0x4008b1]))

    print ('Testing Curl')

    # Wrong
    binary = Binary('../testbench/bin/app/curl')
    locator = FastLocator(binary)
    addrs = locator.get_address_locations(MD5Desc)


    print ('Gathered all address locations')
    print ([hex(x) for x in addrs])

    assert (set(addrs) == set([0x59ad12, 0x599f52, 0x4cf9bd, 0x4d00cd]))

    scoper = FastScoper(binary)
    s, e = scoper.get_function_scope(0x59ad12)
    assert (s == 0x59ace0 and e == 0x59ad2f)
    s, e = scoper.get_function_scope(0x599f52)
    assert (s == 0x599f20 and e == 0x599f6f)
    s, e = scoper.get_function_scope(0x468607)
    print (hex(s), hex(e))
    entries, exits = scoper.get_hierarchical_scopes(0x59ad12)
    assert (0x468606 in entries)
