import angr
import signal
from func_args import *
from capstone.x86 import *

class TimeoutError(Exception):
    pass

def _handle_timeout(signum, frame):
    raise TimeoutError('timeout')

def print_mem(mem, start, size):
    for i in range(0, size):
        print (mem[start+i].byte)

def read_mem(mem, start,size):
    out = []
    print("I call read_mem")
    for i in range(0, size):
        out.append(format(mem[start+i].byte.concrete, b'02x'))
    return b''.join(x for x in out)

def read_byte_mem(mem, start, bytesize):
    out = []
    print("I call read_byte_mem")
    for i in range(0, bytesize):
        out.append(mem[start+i].byte.concrete)
    return bytes(out)


class CryptoAsserter:
    IN_ADDR = 0x2000
    OUT_ADDR = 0x3000
    IN_LEN = 9
    TEST_STRING = b"oakoakoak"+b"\0"

    def __init__(self, angr_proj):
        self.p = angr_proj

    def __mem_set(self, mem, start_idx, size, val):
         for i in range(0, size):
            mem[start_idx+i].byte = val

    def __mem_cpy(self, mem, start_idx, size, copy):
        print("copy = " + str(copy) + " size = " + str(size))
        for i in range(0, size):
            mem[start_idx+i].byte = copy[i]

    def assert_fn(self, fn_addr, out_bytelen, argv):
        argv_out = self.execute_fn(fn_addr, out_bytelen, argv)
       
        for arg in argv_out:
            print ("type expected output = " + str(type(arg.expected_output)))

            print ("b1 = " + str(arg.expected_output is not None))
            
            #print ("b2 = " + str(arg.output[:out_bytelen] != arg.expected_output[:out_bytelen]))
            if arg.expected_output is not None and arg.output[:out_bytelen] != arg.expected_output[:out_bytelen]:
                print ('Fn addr: ', hex(fn_addr), 'Expected Output: ', str(arg.expected_output[:out_bytelen]), ' output: ', str(arg.output[:out_bytelen]) )# arg.output[:out_bytelen].encode("hex")) # encode("hex"), # arg.expected_output[:out_bytelen].encode("hex")
                return False
        return True

    def execute_fn(self, fn_addr, out_bytelen, argv):
        fn = self._execute_fn(fn_addr, argv)
        for arg in argv:
            if arg.expected_output is not None:
                arg.output = read_byte_mem(fn.result_state.mem, arg.val, out_bytelen)
        return argv

    def get_output_reg(self, fn_addr, argv, out_idx=None):
        init_state = self.p.factory.blank_state()
        for arg in argv:
            self.fill_state(init_state, arg)

        state = self.p.factory.call_state(fn_addr, *[x.val for x in argv], base_state=init_state)

        if out_idx is None:
            for i, av in enumerate(argv):
                if av.expected_output is not None:
                    out_idx = i

        out_val = argv[out_idx].val
        if init_state.solver.eval(state.regs.rdx) == out_val:
            return X86_REG_RDX #'rdx'
        elif init_state.solver.eval(state.regs.rsi) == out_val:
            return X86_REG_RSI #'rsi'
        elif init_state.solver.eval(state.regs.rdi) == out_val:
            return X86_REG_RDI #'rdi'
        else:
            return None

    def _execute_fn(self, fn_addr, argv):
        init_state = self.p.factory.blank_state()
        for arg in argv:
            self.fill_state(init_state, arg)
        fn = self.p.factory.callable(fn_addr, base_state=init_state, concrete_only=True)
        print ("type argv = " + str(type(argv)) + " type val = " + str(type(argv[0].val)))
        fn.perform_call(*[str(x.val).encode() for x in argv])
        #self.perform_call(fn, *[x.val for x in argv])
        return fn

    def perform_call(self, fn, *args):
        state = fn._project.factory.call_state(fn._addr, *args, cc=fn._cc, base_state = fn._base_state, ret_addr = fn._deadend_addr, toc = fn._toc)
        caller = fn._project.factory.simulation_manager(state)
        #print 'SS: ', dir(caller)
        print ('Before IP: ', str(state.regs.rip))
        print ('Before RSI: ', state.regs.rsi)
        print ('Before RDI: ', state.regs.rdi)
        final_state = None
        #while '46f875' not in str(caller.active[0].regs.rip) and len(caller.active) == 1:
        #while '46f93b' not in str(caller.active[0].regs.rip) and len(caller.active) == 1:
        while '46f2e0' not in str(caller.active[0].regs.rip) and len(caller.active) == 1:
            print ('IP: ', str(caller.active[0].regs.rip))
            final_state = caller.active[0]
            caller.step()
            caller.prune()
        print ('Caller active len: ', len(caller.active))
        final_state = caller.active[0]
        print ('After IP: ', final_state.regs.rip)
        print ('Str at 0x300: ', read_mem(final_state.mem, 0x300, 16))
        print ('Str at 0x200: ', read_mem(final_state.mem, 0x200, 16))
        print ('AFter RAX: ', final_state.regs.rax)
        print ('AFter RSI: ', final_state.regs.rsi)
        print ('AFter RDI: ', final_state.regs.rdi)


        exit(1)
        return fn

    def fill_state(self, state, arg):
        if arg.type == AliceArg.TYPE_BYTE_POINTER:
            self.__mem_cpy(state.mem, arg.val, len(arg.ref_val), arg.ref_val)

    def assert_fn_output(self, fn_addr, out_hexstr, in_str=None, in_len=None, out_byte_len=None):
        output = self.get_fn_output(fn_addr, in_str, in_len, out_byte_len)
        if output is None:
            return False
        return output.upper() == out_hexstr.upper()

    def get_fn_output(self, fn_addr, in_str=None, in_len=None, out_len=None, timeout_seconds=60):
        if in_str is None:
            in_str = self.TEST_STRING
        if in_len is None:
            in_len = self.IN_LEN
        if out_len is None:
            out_len = 64
        h = self.generate_callable(fn_addr, in_str, in_len, out_len)
        
        signal.signal(signal.SIGALRM, _handle_timeout)
        signal.alarm(timeout_seconds)

        print ('Call with params: ', self.IN_ADDR, in_len, self.OUT_ADDR)
    
        try:
            h.perform_call(self.IN_ADDR, in_len, self.OUT_ADDR)
            #h.perform_call(self.OUT_ADDR, self.IN_ADDR)
            output = read_mem(h.result_state.mem, self.OUT_ADDR, out_len)
        except Exception as e:
            output = None
            print ('Fn addr: ' + hex(fn_addr) + ' Asserter Exception: ' + str(e))
        finally:
            signal.alarm(0)

        print (output)
        return output

    def generate_base_state(self, in_str, in_len, out_len):
        s = self.p.factory.blank_state()
        self.__mem_set(s.mem, self.IN_ADDR, out_len, 'a')
        self.__mem_set(s.mem, self.OUT_ADDR, out_len, 'a')
        self.__mem_cpy(s.mem, self.IN_ADDR, in_len, in_str)
        self.__mem_cpy(s.mem, self.OUT_ADDR, in_len, in_str)
        return s


    def generate_callable(self, fn_addr, in_str, in_len, out_len):
        s = self.generate_base_state(in_str, in_len, out_len)
        return self.p.factory.callable(fn_addr, base_state=s)#, concrete_only=True)

if __name__ == "__main__":

    IN_ADDR = 0x2000
    OUT_ADDR = 0x3000
    IN_LEN = 9
    TEST_STRING = "oakoakoak"
    p = angr.Project('../testbench/bin/hash/sha1.o')
    digest = '67D3B0DB4ED851391320802385BF4B3A1EF9AFEC206BBA34D5F4C7A8891EC36FC3B8750DB3BB76D969D3DDC5E01D207803EEAB426FA7E3333BFE20D4D419FE2F'
    ass = CryptoAsserter(p)

    print (ass.get_fn_output(0x400ee4, TEST_STRING, IN_LEN, 20))
    print (ass.assert_fn_output(0x400ee4, digest, TEST_STRING, IN_LEN, 20))
    exit(1)


    s = p.factory.blank_state()
    for i in range(0, 100):
        s.mem[IN_ADDR+i].char = 'a'
        s.mem[OUT_ADDR+i].char = 'b'

    for i in range(0, IN_LEN):
        s.mem[IN_ADDR+i].char = TEST_STRING[i]

    print ('Input: ' + read_mem(s.mem, IN_ADDR, IN_LEN))
    print ('Output: ' + read_mem(s.mem, OUT_ADDR, 64))

    h = p.factory.callable(0x401c18, base_state=s)
    h.perform_call(IN_ADDR, IN_LEN, OUT_ADDR)
    #print dir(h)
    #print type(h._cc)
    #print dir(h._cc)
    #print h._cc.both_args
    #print h._cc.int_args
    exit(1)

    print ('Hash val: ' + read_mem(h.result_state.mem, OUT_ADDR, 64))

    print ('67D3B0DB4ED851391320802385BF4B3A1EF9AFEC206BBA34D5F4C7A8891EC36FC3B8750DB3BB76D969D3DDC5E01D207803EEAB426FA7E3333BFE20D4D419FE2F' == read_mem(h.result_state.mem, OUT_ADDR, 64).upper())
