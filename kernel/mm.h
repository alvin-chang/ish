/**
 * iSH - Process Memory Management
 *
 * This header defines the process memory management layer for the Linux emulation.
 * It builds upon the lower-level memory.h functionality to implement process-specific
 * concepts like the heap (brk), memory-mapped regions, and executable memory layouts.
 */

#ifndef KERNEL_MM_H
#define KERNEL_MM_H

#include "kernel/memory.h"
#include "misc.h"

/**
 * Process memory management structure
 * 
 * Represents a complete process address space including memory mappings,
 * heap, stack, and executable memory regions. Each process has its own mm
 * structure, but threads within the same process share an mm structure.
 * 
 * Uses mem.lock instead of having a lock of its own for synchronization.
 */
struct mm {
    /** Reference count for this memory context */
    atomic_uint refcount;
    
    /** Low-level memory management structure */
    struct mem mem;

    /**
     * Virtual Dynamic Shared Object memory address (immutable)
     * Used for fast system calls without kernel transitions
     */
    addr_t vdso;
    
    /** Initial program break address (immutable) */
    addr_t start_brk;
    
    /** Current program break address (heap end) */
    addr_t brk;

    /* 
     * Process memory layout information for /proc filesystem
     * These fields track various segments of the program in memory
     */
    
    /** Start of command line arguments area */
    addr_t argv_start;
    
    /** End of command line arguments area */
    addr_t argv_end;
    
    /** Start of environment variables area */
    addr_t env_start;
    
    /** End of environment variables area */
    addr_t env_end;
    
    /** Start of auxiliary vector area */
    addr_t auxv_start;
    
    /** End of auxiliary vector area */
    addr_t auxv_end;
    
    /** Stack base address */
    addr_t stack_start;
    
    /** File descriptor of the executed program */
    struct fd *exefile;
};

/**
 * Create a new address space for a process
 *
 * Initializes a new memory context with default values.
 * The returned mm structure has a reference count of 1.
 *
 * @return New mm structure or NULL on failure
 */
struct mm *mm_new(void);

/**
 * Clone an address space using copy-on-write
 *
 * This is used during process forking to create an identical
 * copy of the parent's address space, but with copy-on-write
 * semantics for efficiency.
 *
 * @param mm Source address space to copy
 * @return New mm structure or NULL on failure
 */
struct mm *mm_copy(struct mm *mm);

/**
 * Increment the reference count of an address space
 *
 * Used when multiple threads share the same address space
 * or when a reference to the mm is stored elsewhere.
 *
 * @param mm Address space to retain
 */
void mm_retain(struct mm *mem);

/**
 * Decrement the reference count of an address space
 *
 * When the reference count reaches zero, all resources
 * associated with the address space are freed.
 *
 * @param mm Address space to release
 */
void mm_release(struct mm *mem);

#endif
