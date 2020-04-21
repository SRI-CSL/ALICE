# Open-source projects

ALICE builds on top of 3 open-source libraries:
1) angr (https://github.com/angr/angr) - CFG/Call graph generation and dynamic concrete execution
2) Triton (https://github.com/JonathanSalwan/Triton) - dynamic taint analysis and concolic execution
3) patchkit (https://github.com/lunixbochs/patchkit) - binary rewriting. It is installed as "patcher" module.

# File Descritpion:

The main script is alice.py. It contains the following main components:

1) fast_locator.py - return (rough) address of instruction that access crypto constant
2) fast_scoper.py - given an address, return a function (entry/exit point) that the address resides in
3) asserter.py - execute a function and determine if it returns expected output. It is used to determine routines implementing a crypto primitive.
4) taint.py - dynamic taint analysis built on top of Triton.
5) expand_local_buffer.py and expand_static_buffer.py
5.1) expand_local_buffer.py - determines which stack memory needs to be expanded and how to expand. ExpandBufferManager manages this expansion.
5.2) expand_static_buffer.py - determines which statically allocated memory needs to be expanded and how to expand.
These two files are very complicated now and really need to be refactored!
6) rewriter.py - a rewriter module, gathering all changes from 5) and create a new binary w.r.t those changes

## Sub-components:
- (angr_)caller_analysis.py - return caller locations of a given address
- desc.py - hard-coded crypto description
- taint_mem.py - contains different classes of tainted memory (stack/heap/static)
- alice_logger.py - handle how logging is done in ALICE, currently it is written to a file called "out.log"

# Installing dependencies
Please see INSTALL

# Running ALICE
1) Create a new configuration file. See how it can be done in ./configs/sha1sum_O0.py.
2) Modify Line 252 of alice.py to import your new config file.
3) Run "python alice.py"
