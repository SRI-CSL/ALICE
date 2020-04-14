#!/bin/sh
#data_addr=0x802000 #0x8028a2 #0x802896 #0xbbbbbb
#code_addr=0x802100 #0x80211e #0x802000 #0xabcdef
if [ -z "$1" ]; then data_addr=0x802000; else data_addr=$1; fi
if [ -z "$2" ]; then lib_addr=0x802100; else lib_addr=$2; fi
if [ -z "$3" ]; then entry_addr=0x803000; else entry_addr=$3; fi
if [ -z "$4" ]; then data_name="data"; else data_name=$4; fi
if [ -z "$5" ]; then lib_name="lib"; else lib_name=$5; fi
if [ -z "$6" ]; then entry_name="in_inlen_out"; else entry_name=$6; fi
echo "Generating $data_name at $data_addr and $lib_name at $lib_addr and $entry_name at $entry_addr"
gcc -g -O0 -fno-toplevel-reorder -fno-stack-protector -Wl,--section-start=.ext_mem=$lib_addr,--section-start=.ext_data=$data_addr,--section-start=.$entry_name=$entry_addr sha256.c -o sha256.o
objcopy --dump-section .ext_data=$data_name sha256.o
objcopy --dump-section .ext_mem=$lib_name sha256.o
objcopy --dump-section .$entry_name=$entry_name sha256.o
echo "Generation is complete"
