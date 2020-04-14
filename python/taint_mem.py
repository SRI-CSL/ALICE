from itertools import groupby, count

class TaintMem(object):
    def __init__(self, addr):
        self.addr = addr
    
    def __repr__(self):
        return 'TaintMem:' + hex(self.addr)

    def __str__(self):
        return 'TaintMem:' +  hex(self.addr)

    def getTypeString(self):
        raise NotImplementedError('no')


class InputMem(TaintMem):
    def __init__(self, addr):
        super(InputMem, self).__init__(addr)

    def __repr__(self):
        return 'InputMem:' + hex(self.addr)

    def __str__(self):
        return 'InputMem:' +  hex(self.addr)

    def getTypeString(self):
        return 'Input'

class BSSMem(TaintMem):
    def __init__(self, addr):
        super(BSSMem, self).__init__(addr)

    def __repr__(self):
        return 'BSSMem:' + hex(self.addr)

    def __str__(self):
        return 'BSSMem:' +  hex(self.addr)

    def getTypeString(self):
        return 'BSS'

class DataMem(TaintMem):
    def __init__(self, addr):
        super(DataMem, self).__init__(addr)

    def __repr__(self):
        return 'DataMem:' + hex(self.addr)

    def __str__(self):
        return 'DataMem:' +  hex(self.addr)

    def getTypeString(self):
        return 'Data'

class HeapMem(TaintMem):
    def __init__(self, addr):
        super(HeapMem, self).__init__(addr)

    def __repr__(self):
        return 'HeapMem:' + hex(self.addr)

    def __str__(self):
        return 'HeapMem:' +  hex(self.addr)

    def getTypeString(self):
        return 'Heap'


class StackMem(TaintMem):

    def __init__(self, addr, fn_entry, rbp=None, rsp=None, ip=None):
        self.addr = addr
        self.rsp = rsp
        self.rbp = rbp
        self.fn_entry = fn_entry
        self.ip = ip
        super(StackMem, self).__init__(addr)

    def __repr__(self):
        try:
            return 'StackMem:' + hex(self.addr) + ' FnEntry: ' + hex(self.fn_entry) + ' IPAddr: ' + hex(self.ip) + ' RSP: ' + hex(self.rsp)
        except:
            return 'StackMem:' + hex(self.addr)


    def __str__(self):
        return self.__repr__()

    def __hash__(self):
        return hash((self.addr, self.rsp, self.rbp, self.fn_entry))

    def __eq__(self, other):
        if not isinstance(other, type(self)): return NotImplemented
        return self.addr == other.addr and self.rsp == other.rsp and self.rbp == other.rbp and self.fn_entry == other.fn_entry

    def getTypeString(self):
        return 'Stack'


class AggrMem(TaintMem):

    def __init__(self, addr, size, memType, fn_addr=None):
        self.addr = addr
        self.size = size
        self.type = memType
        self.fn_addr = fn_addr
    
    def __repr__(self):
        return 'AggrMem:' + hex(self.addr) + '-' + hex(self.addr+self.size) + ' type: ' +self.type + (' at fn: ' + hex(self.fn_addr) if self.fn_addr is not None else '')

    def __str__(self):
        return 'AggrMem:' + hex(self.addr) + '-' + hex(self.addr+self.size) + ' type: ' +self.type + (' at fn: ' + hex(self.fn_addr) if self.fn_addr is not None else '')

    def __hash__(self):
        return hash((self.addr, self.size, self.type, self.fn_addr))

    def __eq__(self, other):
        if not isinstance(other, type(self)): return NotImplemented
        return self.addr == other.addr and self.size == other.size and self.type == other.type and self.fn_addr == other.fn_addr



def aggrMem(tainted_mems, min_size=0):
    stack = []
    heap = []
    bss = []
    data = []
    inp = []
    unknown = []
    for mem in tainted_mems:
        if isinstance(mem, StackMem):
            stack.append(mem)
        elif isinstance(mem, HeapMem):
            heap.append(mem)
        elif isinstance(mem, DataMem) or isinstance(mem, BSSMem):
            data.append(mem)
        elif isinstance(mem, InputMem):
            inp.append(mem)
        else:
            unknown.append(mem)

    out = []
    out.extend(_aggrMemHelper(stack, min_size))
    out.extend(_aggrMemHelper(heap, min_size))
    out.extend(_aggrMemHelper(data, min_size))
    out.extend(_aggrMemHelper(bss, min_size))
    out.extend(_aggrMemHelper(inp, min_size))
    out.extend(_aggrMemHelper(unknown, min_size))
    return out

def _aggrMemHelper(tainted_mems, min_size):
    if len(tainted_mems) <= 0:
        return []
    
    if len(set([x.getTypeString() for x in tainted_mems])) > 1:
        raise ValueError('Input has different types')

    if isinstance(tainted_mems[0], StackMem):
        # Get the correct scope
        aggrMems = []
        tainted_mems = list(set(tainted_mems))
        tainted_mems.sort(key=lambda x: x.fn_entry)
        for fn_addr, stack_mems_all in groupby(tainted_mems, lambda x: x.fn_entry):
            #try:
            #    print 'Group by fn_entry: ', hex(fn_addr)
            #except:
            #    print 'Cant print: ', fn_addr

            stack_mems_all = list(stack_mems_all) 
            stack_mems_all.sort(key=lambda x: x.ip)
            cur_ip = stack_mems_all[0].ip
            stack_mems_big = []
            stack_mems_small = []
            for i, sm in enumerate(stack_mems_all):
                if abs(sm.ip - cur_ip) > 0x10000:
                    cur_ip = sm.ip
                    #print 'Storing SMS: ', stack_mems_small
                    stack_mems_big.append(stack_mems_small)
                    stack_mems_small = []
                stack_mems_small.append(sm)
            #print 'Storing SMS2: ', stack_mems_small
            stack_mems_big.append(stack_mems_small)

            #print 'StackMemsBig: ', stack_mems_big

            #for stack_mems in stack_mems_all:
            for stack_mems in stack_mems_big:
                stack_mems = list(stack_mems)
                stack_offsets = [(x.addr - x.rsp) for x in stack_mems]
                aggrMem = aggrFromAddrs(stack_offsets, tainted_mems[0].getTypeString(), min_size, fn_addr)
                #print
                #print 'StackMem: ', stack_mems
                #print 'Stack offset: ', [hex(x.addr) for x in stack_mems], [hex(so) for so in stack_offsets] 
                #print 'Aggr: ', [hex(am.addr) + ' - ' + hex(am.size) for am in aggrMem]
               
                aggrMems.extend(aggrMem)
        return aggrMems
    else:
        return aggrFromAddrs([x.addr for x in tainted_mems], tainted_mems[0].getTypeString(), min_size)

def aggrFromAddrs(addrs, memType, min_cont_size, fn_addr=None):
    aggrMems = []
    addrs.sort()
    group_addrs = [list(g) for k, g in groupby(addrs, key=lambda n, c=count(): n - next(c))]
    for addr in group_addrs:
        if len(addr) >= min_cont_size:
            aggrMems.append(AggrMem(addr[0], len(addr), memType, fn_addr))
    return aggrMems

    
     
if __name__ == '__main__':
    addrs = [100+x for x in range(0,20)]
    addrs.extend([300+x for x in range(0,10)])
    addrs.extend([500+x for x in range(0,16)])
    print aggrFromAddrs(addrs, 'Stack', 16)


