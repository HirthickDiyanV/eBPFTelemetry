#!/usr/bin/python3
from bcc import BPF
from time import sleep
import os

# =========================================================
# 1. C KERNEL CODE (Aggregation, not Streaming)
# =========================================================
# Distinct logic: We use a Hash Map to count 'hits' in the kernel
# rather than sending a struct for every single write.
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// key_t: Defines what we are grouping by (Process ID + Name)
struct key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

// 'stats': A Hash Map where Key=Process, Value=Counter
BPF_HASH(stats, struct key_t, u64);

// We hook vfs_write to count frequency
int trace_write_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 zero = 0, *val;
    
    // Get PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    
    // Get Name
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // Increment the counter for this specific PID
    // If key doesn't exist, this helper creates it automatically.
    stats.increment(key);
    
    return 0;
}
"""

# =========================================================
# 2. PYTHON CONTROLLER
# =========================================================
def main():
    # Load BPF program
    b = BPF(text=bpf_source)
    
    # Explicitly attach the probe (different style than kprobe__ naming convention)
    b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
    
    print("Monitoring 'vfs_write' frequency... (Ctrl+C to stop)")

    try:
        while True:
            sleep(1) # Interval duration
            os.system('clear') # Refresh screen
            
            # Retrieve data from the kernel map
            counts = b.get_table("stats")
            
            print(f"{'PID':<10} {'PROCESS NAME':<20} {'WRITES / SEC':<15}")
            print("="*50)
            
            # Sort data: Convert map items to list, sort by value (count)
            # x[1].value accesses the u64 counter from the map
            sorted_counts = sorted(counts.items(), key=lambda x: x[1].value, reverse=True)
            
            # Display top 15 results
            for k, v in sorted_counts[:15]:
                print(f"{k.pid:<10} {k.name.decode('utf-8', 'ignore'):<20} {v.value:<15}")
            
            # CRITICAL: Clear the map to reset counters for the next second.
            # This ensures we see "Current Speed" and not "Total History".
            counts.clear()
            
    except KeyboardInterrupt:
        print("\nDetaching...")

if __name__ == "__main__":
    main()