#!/usr/bin/python
#
# postgresql_locks  Analyze PostgreSQL LWLock usage
#                   For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: postgresql_locks <pid> <lock_name> [sleep]
#
# Copyright 2017 Red Hat
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
import sys
import ctypes as ct
import subprocess
from time import sleep

if len(sys.argv) < 2:
    print("USAGE: postgresql_locks <lock_id> [sleep]")
    exit()

debug=1
sleep_time=int(99999999)

if len(sys.argv) == 3:
    sleep_time=int(sys.argv[2])

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(hash_lock, u32);
BPF_HASH(hash_wait, u32);
BPF_HISTOGRAM(hist_lock);
BPF_HISTOGRAM(hist_wait);
BPF_HISTOGRAM(hist_total);

int do_wait_start(struct pt_regs *ctx) {
    u64 n_addr = 0;
    u32 id = 0;

    bpf_usdt_readarg(1, ctx, &n_addr);
    bpf_probe_read(&id, sizeof(u32), (void *)n_addr);

    bpf_trace_printk("Wait start: %d\\n", id);

    if (id == REPLACE) {
        u32 key = bpf_get_current_pid_tgid();
        u64 *val = NULL;

        val = hash_wait.lookup(&key);
        if (val == NULL) {
           u64 timestamp = bpf_ktime_get_ns();
           hash_wait.insert(&key, &timestamp);
        }
    }

    return 0;
};

int do_acquire(struct pt_regs *ctx) {
    u64 n_addr = 0;
    //u64 m_addr = 0;
    u32 id = 0;
    //int mode = 0;

    bpf_usdt_readarg(1, ctx, &n_addr);
    //bpf_usdt_readarg(2, ctx, &m_addr);

    bpf_probe_read(&id, sizeof(u32), (void *)n_addr);
    //bpf_probe_read(&mode, sizeof(mode), (void *)m_addr);

    bpf_trace_printk("Acquire: %d\\n", id);

    if (id == REPLACE) {
        u64 timestamp = bpf_ktime_get_ns();
        u32 key = bpf_get_current_pid_tgid();
        u64 *lw = hash_wait.lookup(&key);

        if (lw)
            hist_wait.increment(bpf_log2l(timestamp - *lw));

        hash_lock.insert(&key, &timestamp);
    }

    return 0;
};

int do_release(struct pt_regs *ctx) {
    u64 n_addr = 0;
    u32 id = 0;

    bpf_usdt_readarg(1, ctx, &n_addr);
    bpf_probe_read(&id, sizeof(u32), (void *)n_addr);

    bpf_trace_printk("Release: %d\\n", id);

    if (id == REPLACE) {
        u32 key = bpf_get_current_pid_tgid();
        u64 *val = NULL;

        val = hash_lock.lookup(&key);
        if (val) {
           u64 timestamp = bpf_ktime_get_ns();
           u64 *lw = hash_wait.lookup(&key);

           hist_lock.increment(bpf_log2l(timestamp - *val));

           if (lw) {
              hist_total.increment(bpf_log2l(timestamp - *lw));
              hash_wait.delete(&key);
           } else {
              hist_total.increment(bpf_log2l(timestamp - *val));
           }

           hash_lock.delete(&key);
        }
    }

    return 0;
};
"""

bpf_text = bpf_text.replace('REPLACE', sys.argv[1]);

# Bug https://github.com/iovisor/bcc/issues/1106
pids = map(int, subprocess.check_output("pidof postgres".split()).split())
usdts = map(lambda pid: USDT(pid=pid), pids)
for usdt in usdts:
    usdt.enable_probe_or_bail(probe="lwlock__wait__start", fn_name="do_wait_start")
    usdt.enable_probe_or_bail(probe="lwlock__acquire", fn_name="do_acquire")
    usdt.enable_probe_or_bail(probe="lwlock__release", fn_name="do_release")
#    usdt.enable_probe_or_bail(probe="lwlock__acquire__or__wait", fn_name="do_acquire")
#    usdt.enable_probe_or_bail(probe="lwlock__condacquire", fn_name="do_acquire")

if debug:
    print("BPF")
    print(bpf_text)

bpf = BPF(text=bpf_text, usdt_contexts=usdts)

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%f %d %d %s" % (event.timestamp, event.pid, event.mode, event.name))

if (sleep_time != 99999999):
    print("Analyzing LWLock #%d usage for %d seconds" % (int(sys.argv[1]), sleep_time))
else:
    print("Analyzing LWLock #%d usage until Ctrl-C" % int(sys.argv[1]))

histlock = bpf["hist_lock"]
histwait = bpf["hist_wait"]
histtotal = bpf["hist_total"]

def print_hist(name, h):
    print(name)
    h.print_log2_hist("usec")
    print("")

while 1:
    try:
        sleep(sleep_time)
    except:
        break

print("")
print("")
print_hist("LWLock #%d: Lock time" % int(sys.argv[1]), histlock)
print_hist("LWLock #%d: Wait time" % int(sys.argv[1]), histwait)
print_hist("LWLock #%d: Total time" % int(sys.argv[1]), histtotal)
