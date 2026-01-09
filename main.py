#!/usr/bin/python3
from bcc import BPF
from time import sleep
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console, Group
from rich import box
import os

# =========================================================
# 1. BPF KERNEL CORE
# =========================================================
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

BPF_HASH(stats, struct key_t, u64);

int trace_write_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    key.pid = pid_tgid >> 32;
    bpf_get_current_comm(&key.name, sizeof(key.name));
    stats.increment(key);
    return 0;
}
"""

# =========================================================
# 2. UI HELPERS
# =========================================================
console = Console()

def generate_table(sorted_counts, max_val):
    """Creates a fresh table for the Live display"""
    # Create table with a Title included (simpler than separate panels)
    table = Table(box=box.SIMPLE, expand=True, title="[bold]Active System Writers[/bold]")
    
    table.add_column("PID", style="cyan", width=8)
    table.add_column("Process Name", style="magenta", width=20)
    table.add_column("Velocity", justify="right", width=12)
    table.add_column("Threat", justify="center", width=12)
    table.add_column("Intensity", ratio=1)

    if not sorted_counts:
        table.add_row("-", "Waiting for I/O...", "-", "🟢 IDLE", "")
        return table

    for k, v in sorted_counts:
        count = v.value
        
        # Color Logic
        if count > 1000:
            status = "🔴 RANSOMWARE?"
            row_style = "bold red"
        elif count > 100:
            status = "🟡 HIGH"
            row_style = "yellow"
        else:
            status = "🟢 NORMAL"
            row_style = "dim white"

        # Bar Logic
        bar_len = int(50 * (count / max_val))
        bar_str = "█" * bar_len
        
        table.add_row(
            str(k.pid), 
            k.name.decode('utf-8', 'ignore'), 
            f"{count:,}/s", 
            status, 
            bar_str,
            style=row_style
        )
        
    return table

# =========================================================
# 3. MAIN LOOP
# =========================================================
def main():
    print("[*] Compiling eBPF... (Please wait)")
    
    # cflags=["-w"] suppresses the compiler warnings
    b = BPF(text=bpf_source, cflags=["-w"])
    b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")

    print("[*] Starting Dashboard...")

    # Static Header
    header = Panel(
        "[bold green]eBPF RANSOMWARE SENTINEL[/bold green]\n"
        "[dim]Monitoring syscall: vfs_write | Mode: Live[/dim]",
        style="green on black"
    )

    # We use Group() to bundle the Header and Table together simply
    # auto_refresh=False gives us manual control over the update timing
    with Live(console=console, auto_refresh=False) as live:
        try:
            while True:
                # 1. Fetch Data
                counts = b.get_table("stats")
                sorted_counts = sorted(counts.items(), key=lambda x: x[1].value, reverse=True)[:15]
                counts.clear()

                # 2. Scaling Math
                max_val = sorted_counts[0][1].value if sorted_counts else 1
                
                # 3. Build UI Group
                table = generate_table(sorted_counts, max_val)
                ui_group = Group(header, table)
                
                # 4. Force Update
                live.update(ui_group, refresh=True)
                
                # 5. Wait
                sleep(0.5)
                
        except KeyboardInterrupt:
            print("\n[*] Stopping Sentinel.")

if __name__ == "__main__":
    main()
