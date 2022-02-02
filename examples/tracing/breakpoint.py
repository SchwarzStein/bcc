#!/usr/bin/python

# This is an example of a hardware breakpoint on a kernel address.
# run in project examples directory with:
# sudo ./breakpoint.py"
# <0xaddress> <pid> <breakpoint_type>
# HW_BREAKPOINT_W = 2
# HW_BREAKPOINT_RW = 3

# You may need to clear the old tracepipe inputs before running the script : 
# echo > /sys/kernel/debug/tracing/trace 

# 10-Jul-2019   Aanandita Dhawan   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse

bpf_prog = """
#include <uapi/linux/ptrace.h>

int func(struct pt_regs *ctx) {
    bpf_trace_printk("Hello World, Here I accessed the address, Instr. ptr = 0x%p\\n", ctx->ip);
    return 0;
}
"""


def get_prog_arguments():
    bp_choices = ['BP_R','BP_W','BP_RW','BP_X']
    bp_values = zip(range(1,4),bp_choices)
    parser = argparse.ArgumentParser(description="Install breakpoint in process and print hello world when triggered\n")
    parser.add_argument('--symbol_addr',type=int,help='the address at which the breakpoint will be installed')
    parser.add_argument('--pid',type=int,help='the pid of target process')
    parser.add_argument('--bp_type',type=str,help='the type of breakpoint to install',choices=bp_choices)
    args = parser.parse_args()
    return (args.symbol_addr, args.pid,bp_values[args.bp_type])

(symbol_addr,pid,bp_type) = get_prog_arguments()
b = BPF(text=bpf_prog)
b.attach_breakpoint(symbol_addr, pid, "func", bp_type)

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

