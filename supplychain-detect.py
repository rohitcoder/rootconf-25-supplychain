from bcc import BPF
from time import strftime
import requests
import json
import base64

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char path[256];
    int event_type;
};

BPF_PERF_OUTPUT(events);

#define EVENT_OPEN  1

static void fill_common(struct data_t *data) {
    data->ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    data->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    fill_common(&data);

    bpf_probe_read_user_str(&data.path, sizeof(data.path), (void *)args->filename);
    data.event_type = EVENT_OPEN;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=prog)

print("%-18s %-6s %-6s %-16s %-10s %s" % (
    "TIME", "PID", "UID", "COMM", "EVENT", "PATH"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-18s %-6d %-6d %-16s %-10s %s" % (
        strftime("%H:%M:%S"),
        event.pid,
        event.uid,
        event.comm.decode(errors='replace'),
        "open",
        event.path.decode(errors='replace')))

b["events"].open_perf_buffer(print_event)
print("fush fasdfas")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
