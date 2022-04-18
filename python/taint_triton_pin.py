#!/usr/bin/env python2
from triton import *
from pintool import *
import sys
import angr
import string

sys.path.append('/home/osboxes/oak/code/python')
from desc import *
from patch import *
from taint_mem import *
import pickle

def getMemoryString(ctx, addr):
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr+index):
        c = chr(ctx.getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s



class CallMetadata(object):

    def __init__(self, fn_addr, init_sp):
        self.fn_addr = fn_addr
        self.init_sp = init_sp

ctx = getTritonContext()
ctx.setArchitecture(ARCH.X86_64)
ctx.enableSymbolicEngine(False)
ctx.enableTaintEngine(True)
ctx.enableMode(MODE.ALIGNED_MEMORY, True)
ctx.enableMode(MODE.TAINT_THROUGH_POINTERS, True)

angr_proj = 0
text_sec = 0 
exec_level = 0

out_dir = None
file_name = None

# Dict:
#   key -> crypto
#   val -> array of PatchEntry
patched_entries = {}

call_stack = []
hash_level = 0
hash_addr = 0
taint = {}

crypto = None
patch_entry = None

def get_tainted_memory():
    return set(ctx.getTaintedMemory())

def getTaintedMem(addr, call_stack, ip):
    tmp_call_stack = call_stack

    if angr_proj.loader.main_object.sections_map['.data'].contains_addr(addr):
        # First check if its in .data section
        return DataMem(addr)
    if angr_proj.loader.main_object.sections_map['.bss'].contains_addr(addr):
        return BSSMem(addr)
    tmp_call_stack.append(CallMetadata(None, getRSP())) # Not need to account for return address
    #print [("None" if x.fn_addr is None else hex(x.fn_addr)) for x in tmp_call_stack]

    # Now differentiate between stack mem or heap mem
    #print 'Call stack size: ', len(tmp_call_stack)
    for i, _ in reversed(list(enumerate(tmp_call_stack))):
        rsp = tmp_call_stack[i].init_sp
        rbp = tmp_call_stack[i-1].init_sp
        fn_addr = tmp_call_stack[i-1].fn_addr
        #try:
        #    print 'Lvl: ', i, 'Cur rsp, rbp: ', hex(rsp), hex(rbp), hex(fn_addr)
        #except:
            #print 'Lvl: ', i, 'Cur rsp, rbp: ', hex(rsp), hex(rbp)

        if addr <= rbp and addr >= rsp:
            # Stack mem
            tmp_call_stack.pop()
            #print 'Yes rsp, rbp: ', hex(rsp), hex(rbp), hex(fn_addr)
            return StackMem(addr, fn_addr, rbp, rsp, ip)

    tmp_call_stack.pop()
    return HeapMem(addr)


prev_tainted_mem = set()

def update_taint(inst):
    global prev_tainted_mem, taint
    ip = inst.getAddress()
    # Check with previous tainted memory, if any new taint happens
    tainted_mem = get_tainted_memory()
    if len(tainted_mem - prev_tainted_mem) > 0:
        diff_mem = tainted_mem - prev_tainted_mem
        
        # Differentiate between stack memory, statically allocated memory (in data section) and dynamically allocated memory (in heap)
        new_tainted_mem = set([getTaintedMem(x, call_stack, ip) for x in diff_mem])

        for tm in new_tainted_mem:
            if isinstance(tm, StackMem):

        #if len(new_tainted_mem) > 0:
                Log.debug('New Taint: ' + str(tm) + 'at inst addr: ' + hex(ip))
                #Log.debug('New Taint: ' + str(new_tainted_mem) + 'at inst addr: ' + hex(ip))
                tm = set([tm])
                if ip not in taint:
                    taint[ip] = tm # new_tainted_mem
                else:
                    #taint[ip].update(taint[ip].union(new_tainted_mem))
                    taint[ip].update(taint[ip].union(tm))
            else:
                Log.debug('Ignoring tiant: ' + str(tm) + 'at inst addr: ' + hex(ip))
                ctx.untaintMemory(tm.addr)
    prev_tainted_mem = tainted_mem



def getRSP():
    return ctx.getConcreteRegisterValue(ctx.registers.rsp)

def check_bound(inst):
    global text_sec, ctx
    ip = inst.getAddress()
    next_ip = ctx.getRegisterAst(ctx.registers.rip).evaluate()

    # Ignore external insts
    if ip < text_sec.vaddr or ip > text_sec.vaddr + text_sec.memsize or next_ip < text_sec.vaddr or next_ip > text_sec.vaddr + text_sec.memsize:
        return False
    return True

def update_call_stack(inst):
    global call_stack
    #if 'call' in inst.getDisassembly():
    if inst.getType() == OPCODE.CALL:
        fn_addr = ctx.getRegisterAst(ctx.registers.rip).evaluate()
        call_stack.append(CallMetadata(fn_addr, getRSP()+8))
        #print 'Call at inst: ', hex(inst.getAddress()), ' CD: ', len(call_stack), ' fn_addr:', hex(fn_addr), ' Base RP: ', hex(getRSP()+8)
    #elif 'ret' in inst.getDisassembly():
    elif inst.getType() == OPCODE.RET:
        tmp = call_stack.pop()
        #print 'Ret at inst: ', hex(inst.getAddress()), ' CD: ', len(call_stack), ' pop: ', hex(tmp.fn_addr)

def is_patched_entry(inst): 
    #ip = inst.getAddress()
    # Check next instruction if its in pe
    ip = ctx.getConcreteRegisterValue(ctx.registers.rip)
    # TODO: optmize this
    for crypto in patched_entries.keys():
        for pe in patched_entries[crypto]:
            if pe.entry == ip:
                return crypto, pe
    return None, None

# Check if ip is entry of hash routine
# Get address of output buffer
# Keep track of call level
# Put a flag indicating that we are executing hash routine
def check_hash_routine_entry(inst):
    global hash_level, hash_addr, crypto, patch_entry
    c, pe = is_patched_entry(inst)
    if pe is None:
        return
    crypto = c
    patch_entry = pe
    #print 'Crypto: ', crypto
    #print 'PE: ', patch_entry
        
    if hash_level != 0:
        raise Exception("Nested hash routines?")

    hash_level = len(call_stack)
    outArg = patch_entry.get_out_index()

    Log.debug('Calling hash routine at: ' + hex(ctx.getConcreteRegisterValue(ctx.registers.rip)))
    if outArg == 1:
        hash_addr   = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    elif outArg == 2:
        hash_addr   = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    elif outArg == 3:
        hash_addr   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    else:
        raise NotImplementedError("Please implement output for outArg: " + str(outArg))
    Log.debug("outarg = "+str(outArg)+" "+hex(hash_level))
    #print 'Hash addr: ', hex(hash_addr)
    for i in range(0, crypto.digest_size):
        outputMem = MemoryAccess(hash_addr+i, 1)
        ctx.untaintMemory(outputMem)




def check_hash_routine_exit(inst):
    global hash_level
    # Check if its a return inst of hash routine (by checking call level)
    # Taint output buffer
    if hash_level > 0 and inst.getType() == OPCODE.RET and (len(call_stack)+1 == hash_level):
        #print 'Exit at: ', hex(inst.getAddress())
        Log.debug('taint mem: '+ hex(hash_addr)+ ' - '+ hex(hash_addr+crypto.digest_size))
        hash_level = 0
        for i in range(0, crypto.digest_size):
            outputMem = MemoryAccess(hash_addr+i, 1)
            ctx.taintMemory(outputMem)

tmp = 0
p = False
count = 0
def inst_cb_after(inst):
    global tmp, p, count
    ip = inst.getAddress()
    count += 1
    #if ip == 0x6a0d12:
    if ip == 0x6740eb:
        Log.debug("Forcing exit at ip: "+hex(ip))
        fini()
    #if count%100000 == 0:
    #    print count
        #fini()
    if False:
        return

        #    fini()
    
    update_taint(inst)
    update_call_stack(inst) #TODO move update_call_stack after check_bound
    if not check_bound(inst):
        return

    check_hash_routine_entry(inst)
    check_hash_routine_exit(inst)

start = False
def main_start(threadid):
    global start
    start = True
    main_fn_addr   = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    call_stack.append(CallMetadata(main_fn_addr, getRSP()+8))
    Log.debug("Main fn starts at addr: " + hex(main_fn_addr))


def fini():
    global out_dir, file_name
    Log.debug('Count: '+str(count))
    tainted_mems = []
    for k, v in taint.items():
        #print 'Taint: ', v
        tainted_mems.extend(v)

    aggr_mems = aggrMem(tainted_mems, 16)
    print
    print aggr_mems
    stack_mems = []
    for amem in aggr_mems:
        if 'Stack' in str(amem):
            Log.debug('Aggr: '+str(amem))
            print 'Aggr: '+str(amem)
            stack_mems.append(amem)

    with open(out_dir + file_name + '.scope', 'w') as f:
        f.write(str(pickle.dumps(stack_mems)))

def plt_hook(tid):
    global call_stack
    call_stack.pop()
    call_stack.pop()
    Log.debug("Exiting strlen at call stack: "+hex(len(call_stack)))

if __name__ == '__main__':

    #global out_dir, file_name

    import pickle
    print 'Starting!'
    out_dir = './out/scope/'
    with open(out_dir+'fn.out', 'r') as f:
        file_name = f.read()

    with open(out_dir+'patch_entry.out', 'r') as f:
        patch_entry = pickle.loads(f.read())
    patched_entries = patch_entry
    #patched_entries = {}
    #patched_entries = {SHA256Desc: [PatchEntry(0x460930, "out_in", None)]}

    #print 'PE: ', patch_entry

    #patched_entries = {MD5Desc: [PatchEntry(0x489b7e, "out_in", None)]}
    #patched_entries = {SHA1Desc: [PatchEntry(0x43394a, "in_inlen_out", None)]}

    exec_path = sys.argv[9]
    angr_proj = angr.Project(exec_path, auto_load_libs=False)
    text_sec = angr_proj.loader.main_object.sections_map['.text']

    startAnalysisFromEntry() #emulate(binary.entrypoint)
    #stopAnalysisFromAddress(0x47a152)
    #stopAnalysisFromAddress(0x477e83)
    #setupImageWhitelist(['libc'])

    insertCall(inst_cb_after, INSERT_POINT.AFTER)
    insertCall(fini, INSERT_POINT.FINI)
    insertCall(main_start, INSERT_POINT.ROUTINE_ENTRY, "__libc_start_main")
    insertCall(plt_hook, INSERT_POINT.ROUTINE_EXIT, "free") #--> need this for Curl_md5it

    # Run the instrumentation - Never returns
    runProgram()



