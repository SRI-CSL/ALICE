import os, sys

patchkit_path = 'build/patchkit'
for dir_name in os.listdir(patchkit_path):
    dir_path = os.path.join(patchkit_path, dir_name)
    if os.path.isdir(dir_path):
        sys.path.insert(0, dir_path)
sys.path.insert(0, '')

print("path = " + str(sys.path))

from desc import *
from patch import *
from patcher import *
from expand_local_buffer import *
from fast_locator import FastLocator
from fast_scoper import FastScoper
from asserter import *
from angr_caller_analysis import *
from alice_logger import AliceLog
import subprocess
import time
#from taint import *
from rewriter import *
from expand_static_buffer import *
import logging
import pickle, timeit
 
from triton import *
#from pintool import *

Log = AliceLog['main']
Log.setLevel(logging.DEBUG)

def _handle_timeout(signum, frame):
    raise TimeoutError('timeout')

# Execute each function w.r.t input/output so that it finds an accurate crypto function
def search_real_entry(asserter, all_entries, all_argvs, outlen):
    entries = []
    found = set()
    for arg_name, argv in all_argvs.items():
        Log.info('Function Signature: '+arg_name)

        for entry in all_entries:

            if entry in found:
                #if entry in found or entry != 0x46f810:
                continue

            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(20)
            # if asserter.assert_fn(entry, outlen, argv):
            #     found.add(entry)
            #     entries.append(PatchEntry(entry, arg_name, argv))
            # else:
            #     Log.debug("Wrong "+hex(entry))
            try:
                if asserter.assert_fn(entry, outlen, argv):
                    found.add(entry)
                    entries.append(PatchEntry(entry, arg_name, argv))
                else:
                    Log.debug("Wrong "+hex(entry))
            except Exception as e:
                Log.warning('Fn addr: ' + hex(entry) + ' Asserter Exception: ' + str(e))
            finally:
                signal.alarm(0)
    return entries

# Separate tainted mems into either stack or statically allocated memory
def separate_tainted_mems(traces, min_cont_size):
    taint_stack_mems = set()
    taint_static_mems = set()
    for trace in traces:
        cur_taint_mems = trace.get_aggr_tainted_mem(min_cont_size)
        for mem in cur_taint_mems: 
            if mem.type == 'Stack':
                taint_stack_mems.add(mem)
            elif mem.type == 'BSS' or mem.type == 'Data':
                taint_static_mems.add(mem)
    return taint_stack_mems, taint_static_mems


# Main Function of Alice
# Perform detection and replacement of crypto function from binary stored in "path"
# cryptos contains a list of crypto primitive that wants to be replaced
# For now, it replaces with SHA256 (from SHA256Patch)
def process(path, out_dir, cryptos):    
    filename, _ = os.path.splitext(os.path.basename(path))
    Log.info('Processing file: ' + filename)

    start = time.time()
    # Setup all modules
    binary = ElfBinary(path)
    binary.ca = AngrCallerAnalysis(binary)
    locator = FastLocator(binary)
    scoper = FastScoper(binary)
    patch = SHA256Patch
    rewriter = Rewriter(path)
    ebm = ExpandBufferManager(binary, scoper)
    
    new_digest_size = patch.crypto.digest_size
    old_digest_size = cryptos[0].digest_size


    ###################### Detection Phase ############################
    detect_out_name = os.path.join(out_dir, 'detect/' + filename + '.detect')

    try:
        Log.debug("Try opening file: "+detect_out_name)
        with open(detect_out_name, "r") as f:
            c = f.read()
            if c:
                patched_entries = pickle.loads(c)
                for crypto in cryptos:
                    if crypto in patched_entries:
                        for pe in patched_entries[crypto]:
                            Log.debug("Patch at: "+hex(pe.entry)+":"+pe.arg_name)
                            rewriter.add_patch(NewCryptoPatch(patch, pe.entry, pe.arg_name))
            else:
                patched_entries = {}

    except:
        Log.debug("file doesnt exist")
        # (1) Generate possbile entries for each primitive
        possible_entries = {}
        for crypto in cryptos:
            addrs = locator.get_address_locations(crypto)
            possible_entries[crypto] = []

            for addr in addrs:
                Log.debug('Addr: '+hex(int(addr)))
                entries, _ = scoper.get_hierarchical_scopes(addr)
                possible_entries[crypto] += entries

            possible_entries[crypto] = list(set(possible_entries[crypto]))

        Log.info('Possible Entries: ' + str(possible_entries))

        # (2) Find accurate entry for each primitive
        asserter = CryptoAsserter(binary.angr_proj)
        patched_entries = {}
        for crypto in possible_entries.keys():
            crypto_name = crypto.name
            output = crypto.sample_ios[0]['output']
            output_len = len(output)
            test_input = crypto.sample_ios[0]['input']
            test_input_len = crypto.sample_ios[0]['input-len']

            print("test_input = " + str(test_input) + " test_input_len = " + str(test_input_len) + " output = " + str(output))
            
            all_argvs = generate_all_possible_args(test_input, test_input_len, output)
            all_entries = list(set(possible_entries[crypto]))
            if not all_entries:
                continue

            print("size all_argvs = " + str(len(all_entries)))
            entries = search_real_entry(asserter, all_entries, all_argvs, output_len)

            if not entries:
                Log.warning('Could not find any valid entry point for ' + crypto_name + ' possibly because it is not used as a one-shot function in this binary')
                continue

            # Keep track of all functions' entry point, to be replaced/rewritten later
            for pe in entries:
                rewriter.add_patch(NewCryptoPatch(patch, pe.entry, pe.arg_name))
                Log.info('Found at: ' + hex(pe.entry) + ' Patch: ' + str(pe.arg_name))
                if crypto not in patched_entries:
                    patched_entries[crypto] = [pe]
                else:
                    patched_entries[crypto].append(pe)

        Log.warning('Detection takes: ' + str(time.time()-start))
        start = time.time()

        print ("size patched_entries = " + str(len(patched_entries)))
        print("patched_entries = " + str(patched_entries))

        d = pickle.dumps(patched_entries)
        pp = pickle.loads(d)
        for k, vv in pp.items():
            for v in vv:
                print (k, hex(v.entry), v.arg_name)

        os.makedirs(out_dir + "/detect")
        with open(detect_out_name, "wb") as f:
            #f.write(binascii.b2a_hex(d).decode()) #d
            f.write(d)
        #return


    ####################### Scoping Phase ################################

    taint_stack_mems = set()
    taint_static_mems = set()
    scope_out_dir = out_dir+'/scope/'

    if not os.path.exists(scope_out_dir):
        os.makedirs(scope_out_dir)
        
    fn = os.path.splitext(os.path.basename(detect_out_name))[0]
    with open(detect_out_name, 'rb') as f:
        r = f.read()
        print ("r = " + str(r))
        with open(scope_out_dir+'patch_entry.out', 'wb') as f2:
            f2.write(r)

    with open(scope_out_dir+'fn.out', 'w') as f:
        f.write(fn)

    print ('Running: ', fn)

    cmd = 'import os; os.system("'+triton_cmdline+'")'

    print (cmd)
    #patch_entry = pickle.loads(binascii.a2b_hex(r))
    patch_entry = pickle.loads(r)
    print ("size keys = " + str(len(patch_entry.keys())))
    if len(patch_entry.keys()) >= 1:
        pe = patch_entry[crypto][0]
        print ("Crypto: ", crypto, hex(pe.entry), pe.arg_name)

        print ('Starting!')
        out_dir = './out/scope/'
        with open(out_dir+'fn.out', 'r') as f:
            file_name = f.read()

        with open(out_dir+'patch_entry.out', 'rb') as f:
            patch_entry = pickle.loads(f.read())
        patched_entries = patch_entry

        #angr_proj = angr.Project(exec_path, auto_load_libs=False)
        text_sec = binary.angr_proj.loader.main_object.sections_map['.text']
        
        startAnalysisFromEntry()
        #stopAnalysisFromAddress(0x47a152)
        #stopAnalysisFromAddress(0x477e83)
        #setupImageWhitelist(['libc'])

        insertCall(inst_cb_after, INSERT_POINT.AFTER)
        insertCall(fini, INSERT_POINT.FINI)
        insertCall(main_start, INSERT_POINT.ROUTINE_ENTRY, "__libc_start_main")
        insertCall(plt_hook, INSERT_POINT.ROUTINE_EXIT, "free") #--> need this for Curl_md5it

        # Run the instrumentation - Never returns
        runProgram()
        
        #t = timeit.timeit(cmd, number=1)
        Log.warning('Scoping takes: ' + str(t))

    ####################### Rewriting Phase ################################

    tmp_stack_mems = set()
    file_name = os.path.join(out_dir, 'scope/' + filename + '.scope')
    if not os.path.exists(file_name):
        print ('File not exist: ', file_name)
        return

    with open(file_name) as f:
        tmp_stack_mems = set(pickle.load(f))

    for sm in tmp_stack_mems:
        taint_stack_mems.add(sm)

    out_name = os.path.join(out_dir, filename + '-patched.o')

    # Rewrite based on stack expansion
    for mem in taint_stack_mems:
        new_size = (mem.size*new_digest_size)/old_digest_size
        Log.debug("Force_insts: "+str(force_insts))
        ebm.expand_stack_mem(mem.fn_addr, mem.addr, mem.size, new_size, force_insts)
        Log.debug('Adjusting stack in fn: ' + hex(mem.fn_addr) + ' offset: ' + hex(mem.addr) + ' from size: ' + hex(mem.size) + '->' + hex(new_size))
        
    for ff in fns:
        Log.debug("XXXX Force_insts: "+str(force_insts))
        ebm.expand_stack_mem(ff[0], 0, 0, 0, force_insts, ff[1])


    # Rewrite based on expansion of statically allocated memory
    # We move the old location to a new location
    dummy = Rewriter(path)
    # First try to get a new data mapping by using a dummy rewriter
    for mem in taint_static_mems:
        new_size = (mem.size*new_digest_size)/old_digest_size
        dummy.add_patch(NewDataPatch(mem.addr, mem.size, new_size))
        rewriter.add_patch(NewDataPatch(mem.addr, mem.size, new_size))
        ebm.expand_static_mem(binary, mem.addr, mem.size, new_size)

    # Get a mapping from old address to new address
    dummy.apply_patches()
    for dp in dummy.data_patches:
        Log.debug('Mapping from old addr: ' + hex(dp.old_addr) + ' to ' + hex(dp.new_addr))
        ebm.add_data_mapping(dp.old_addr, dp.new_addr)
        
    # Now rewrite all!
    rewriter.add_patches(ebm.generate_patches())
    rewriter.apply_patches()
    rewriter.save(out_name)

    Log.warning('Rewriting takes: ' + str(time.time()-start))

    #return patched_entries, out_name


if __name__ == "__main__":
    sys.path.insert(0, './configs')
    from curl_O2 import *
    out_dir = './out'
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        process(exec_path, out_dir, CRYPTO)
    else: print("out folder exists")
