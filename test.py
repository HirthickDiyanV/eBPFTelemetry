import os

# Open a file for writing (raw file descriptor)
fd = os.open("ransomware_dummy_file.dat", os.O_WRONLY | os.O_CREAT)

print("Process ID:", os.getpid())
print("Generating massive syscalls... (Ctrl+C to stop)")

try:
    # Infinite loop of writing 64 bytes (simulating encryption chunks)
    while True:
        os.write(fd, b"A" * 64)
except KeyboardInterrupt:
    os.close(fd)
    print("\nStopped.")