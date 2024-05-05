#!/usr/bin/env python3

import os
import subprocess
#import lief
#import elftools
#from elftools.elf.elffile import ELFFile

import argparse

parser = argparse.ArgumentParser(description='Build c file with gsym section')

parser.add_argument('input_file', type=str, help='Input file name')
parser.add_argument('-o', '--output', type=str, help='Output file name')
parser.add_argument('--cf', type=str, help='Compile flag')
parser.add_argument('--strip', action='store_true', help='Strip debug information')

args = parser.parse_args()

def PR(cmd):
    print('+',cmd)
    subprocess.check_call(cmd, shell=True)
    #os.system(cmd)

args.inp = args.input_file
args.out = args.output
args.obj = args.inp.replace('.c','.o')
args.gsym = args.inp.replace('.c','.gsym')
args.sec_name = '.gsym'

PR(f'clang -c -o {args.obj} -g {args.inp} {args.cf}')
PR(f'clang -o {args.out} -g {args.obj} {args.cf}')

gsym_size = 0

while 1:
    PR(f'llvm-gsymutil-14 --convert {args.out} -o {args.gsym}')

    n_gsym_size = os.path.getsize(args.gsym)
    print(f'Current gsym size: {hex(n_gsym_size)}')

    if n_gsym_size <= gsym_size:
        break

    ALIGN = 0x10
    gsym_size = -(-n_gsym_size // ALIGN) * ALIGN

    with open('tmp_data.bin', 'wb') as f:
        f.write(b'GSYM_DATA_START'.ljust(gsym_size,b'\0'))

    PR(f'objcopy -I binary -O default --set-section-alignment .data=8 ./tmp_data.bin {args.gsym}.o')
    PR(f'objcopy --rename-section .data={args.sec_name} {args.gsym}.o {args.gsym}.o')
    PR(f'objcopy --set-section-flags {args.sec_name}=alloc,readonly {args.gsym}.o  {args.gsym}.o')
    if args.strip:
        PR(f'strip -s {args.gsym}.o')

    print("========================================================")
    PR(f'clang -o {args.out} {args.obj} {args.gsym}.o {args.cf}')

if args.strip:
    PR(f'strip -s {args.out}')

#binary = lief.parse("./child")
#binary.header.
#seg = binary.get(lief.ELF.SEGMENT_TYPES.GNU_STACK)


with open(args.gsym,'rb') as f:
    gsym_data = f.read()

with open(args.out,'rb') as f:
    data = bytearray(f.read())
    g_start = data.index(b'GSYM_DATA_START')
    g_end = g_start + len(gsym_data)
    data = data[:g_start] + gsym_data + data[g_end:]

    # Fix stack NX
    stack_sec = data.index(b'Q\xe5td')
    data[stack_sec+4]=6

with open(args.out,'wb') as f:
    f.write(data)

if args.strip:
    #PR(f'strip -s {args.out}')
    PR(f'strip -g {args.out}')

#PR(f'cp {args.out} /s/defcon/quals/.')
#PR(f'cp {args.gsym}.o /s/defcon/quals/.')

exit(0)
