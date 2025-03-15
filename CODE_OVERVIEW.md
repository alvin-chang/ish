# iSH Code Overview

This document provides an overview of the iSH codebase structure and organization.

## Project Overview

iSH is an x86 Linux emulator that runs on iOS devices, enabling a Linux shell environment on iOS. The project consists of several key components:

1. **x86 CPU Emulator**: Emulates x86 instructions on ARM processors
2. **Linux Kernel Emulation**: Implements Linux system calls and kernel functionality
3. **Filesystem Layer**: Provides real and virtual filesystem access
4. **UI Components**: iOS application UI for interacting with the shell

## Directory Structure

### Core Components

- `/app` - iOS application code
- `/emu` - x86 emulation core
- `/kernel` - Linux kernel emulation
- `/fs` - Filesystem implementation
- `/vdso` - Virtual dynamic shared object implementation

### Supporting Components

- `/tools` - Development and build tools
- `/tests` - Test suites
- `/deps` - External dependencies
- `/util` - Utility functions and macros
- `/asbestos` - Sandbox escape detection

### Platform-Specific

- `/platform` - Platform-specific code
- `/linux` - Linux-specific code

## Key Files

- `main.c` - Main entry point
- `xX_main_Xx.h` - Core initialization
- `misc.h` - Common utilities and types
- `debug.h` - Debugging infrastructure

## Code Organization

### CPU Emulation (`/emu`)

The CPU emulation code in the `/emu` directory handles the core x86 instruction emulation:

- `cpu.h` - CPU state and register definitions
- `decode.h` - x86 instruction decoder
- `float80.h/c` - x87 FPU emulation
- `modrm.h` - ModR/M byte handling
- `tlb.h/c` - Translation Lookaside Buffer implementation
- `vec.h/c` - Vector instruction emulation

### Kernel Emulation (`/kernel`)

The kernel emulation code implements Linux system calls and kernel functionality:

- `calls.h/c` - System call implementation
- `fs.h/c` - Filesystem operations
- `task.h/c` - Process/task management
- `exec.c` - Program execution
- `signal.h/c` - Signal handling
- `memory.h/c` - Memory management

### Filesystem (`/fs`)

The filesystem code provides access to real and virtual filesystems:

- `real.c` - Real filesystem access
- `fake.c` - Virtual filesystem implementation
- `proc.c` - Proc filesystem (/proc)
- `devices.c` - Device filesystem handling

## Building and Running

The project uses the Meson build system (see `meson.build`). See the main README.md for build instructions.

## Debugging

The project includes a comprehensive debugging system:

- Debug channels for different components
- Debug output control macros
- Error handling facilities

To enable debugging, define `DEBUG_all=1` or specific debug channels like `DEBUG_strace=1`.

## Development Workflow

1. Understand the target x86 Linux behavior
2. Implement emulation in the appropriate layer
3. Test against real Linux systems
4. Add iOS integration as needed

## Key Concepts

- **Emulation vs. Virtualization**: iSH is an emulator, not a virtual machine
- **System Call Translation**: Translates x86 Linux system calls to iOS system calls
- **User Mode**: Runs in user mode without kernel privileges
- **Sandboxing**: Respects iOS sandbox limitations 