# Bash readline monitor app

A small eBPF CO-RE tracer app that hooks into Bash's `readline()` function and emits each event as
JSON over UDP to a remote collector.  Local file logging and TCP transport have been removed –
only UDP is supported now.

This project demonstrates how to:
- Compile a BPF program (`readline_tracker.bpf.c`) against the kernel’s BTF (`vmlinux.h`).
- Generate a libbpf skeleton header (`readline_tracker.skel.h`).
- Build a standalone, static user‑space loader (`readline_loader`) that attaches the BPF program to Bash.

```
Usage: sudo ./readline_loader --config <file>
Configuration file example (one per line, format key=value):
    exp-domain=1.1.1.1:8888    # IP and port of UDP collector
```

*Kernel version 4.12 and upper*

# Architecture

![image](https://github.com/user-attachments/assets/24f6ed1d-7a7b-4558-a6fb-ab5531c0f135)

