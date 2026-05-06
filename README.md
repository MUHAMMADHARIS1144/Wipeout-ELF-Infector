[README.md](https://github.com/user-attachments/files/27438758/README.md)
# WIPEOUT 🦠 - ELF64 File Infector & Wiper

**Course**: Computer Organization and Assembly Language (COAL)
**Author**: Muhammad Haris
**Institution**: Air University
**Semester**: 3rd Semester

> ⚠️ **DISCLAIMER:** This project is created strictly for **educational and academic purposes**. It demonstrates advanced system-level programming and understanding of executable file formats. Do not run this on a host machine without isolation (use a Virtual Machine or Container). The author is not responsible for any accidental data loss.

## 📖 Overview

**WIPEOUT** is an advanced Assembly Language (x86_64) program that functions as a background file infector and wiper for Linux ELF64 executables. Built using the Flat Assembler (FASM), this project bypasses standard C libraries (like glibc) and interacts directly with the Linux kernel via raw system calls (`syscall`). 

It demonstrates deep knowledge of process control, directory traversal, memory mapping, and binary format manipulation.

## ✨ Features

- **Daemonization (Stealth Mode)**: The process detaches from the terminal using `SYS_FORK` and `SYS_SETSID` to run invisibly in the background.
- **Delayed Execution**: Implements a 30-second delay (`SYS_NANOSLEEP`) to evade immediate detection.
- **Recursive Directory Traversal**: Scans the current directory and all subdirectories using `SYS_GETDENTS64`.
- **ELF64 Infection**: Identifies valid 64-bit Executable and Linkable Format (ELF) files and safely maps them into memory (`SYS_MMAP`).
- **Binary Prepender**: Modifies the ELF headers and entry points, injecting its payload at the beginning while preserving the original host code. 
- **Wiper Mechanism**: Tracks up to 1,000 infected victim files and systematically wipes (deletes) them from the disk (`SYS_UNLINK`).

## 🛠️ Technical Stack & Concepts

- **Language**: x86_64 Assembly Language
- **Assembler**: FASM (Flat Assembler)
- **Target OS**: Linux
- **Key Concepts Learned**:
  - Raw Linux Syscalls (`SYS_FORK`, `SYS_GETDENTS64`, `SYS_MMAP`, etc.)
  - ELF structure (Headers, Program Headers, Segments)
  - Memory Management & File I/O in Assembly
  - Process control & background daemon creation

## 🚀 How to Compile and Run (Sandbox Only!)

**WARNING:** Please run this only inside a safely isolated Virtual Machine (VM) or a Docker container.

### Prerequisites
- Linux OS (Ubuntu, Kali, etc.)
- FASM installed (`sudo apt install fasm`)

### Compilation
```bash
fasm WIPEOUT.asm
chmod +x WIPEOUT
```

### Execution Test
1. Compile the dummy `task.c` files to create targets:
   ```bash
   gcc task.c -o task
   ```
2. Run WIPEOUT:
   ```bash
   ./WIPEOUT
   ```
3. The program will fork into the background. Wait 30 seconds.
4. You will notice that the `task` executables in the directory (and subdirectories) have been infected and subsequently deleted!

## 🎓 Acknowledgements
This project was completed as part of the COAL lab coursework at Air University. It serves as an exploration of low-level system mechanics, emphasizing how operating systems manage files, memory, and executable formats.
