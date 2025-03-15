/**
 * iSH - Memory Management System
 *
 * This header defines the memory management subsystem for the Linux emulation layer.
 * It implements virtual memory address translation, page tables, and memory mapping
 * functionality similar to the Linux kernel's memory management.
 */

#ifndef MEMORY_H
#define MEMORY_H

#include <stdatomic.h>
#include <unistd.h>
#include <stdbool.h>
#include "emu/mmu.h"
#include "util/list.h"
#include "util/sync.h"
#include "misc.h"

/**
 * Memory management structure
 * 
 * Represents a complete address space with page tables and an MMU
 * for address translation. This is the low-level memory management
 * structure used by the mm structure for process memory contexts.
 */
struct mem {
    /** 
     * Two-level page directory
     * First level is a pointer array of MEM_PGDIR_SIZE entries
     * Second level is arrays of page table entries
     */
    struct pt_entry **pgdir;
    
    /** Number of allocated page directories in pgdir */
    int pgdir_used;

    /** Memory Management Unit for address translation */
    struct mmu mmu;

    /** 
     * Write-read lock for memory operations
     * Write lock required for mapping/unmapping
     * Read lock required for address translation
     */
    wrlock_t lock;
};

/** Size of each page directory (1024 entries) */
#define MEM_PGDIR_SIZE (1 << 10)

/**
 * Initialize a memory management structure
 *
 * @param mem Memory structure to initialize
 */
void mem_init(struct mem *mem);

/**
 * Clean up and free resources used by a memory structure
 *
 * @param mem Memory structure to destroy
 */
void mem_destroy(struct mem *mem);

/**
 * Get the page table entry for a specific page
 *
 * @param mem Memory structure
 * @param page Page number to look up
 * @return Pointer to page table entry or NULL if not mapped
 */
struct pt_entry *mem_pt(struct mem *mem, page_t page);

/**
 * Advance to the next mapped page
 * 
 * Increments *page, but skips over unallocated page directories.
 * Designed to be used as the increment in a for loop to traverse mappings.
 *
 * @param mem Memory structure
 * @param page Pointer to page number (will be updated)
 */
void mem_next_page(struct mem *mem, page_t *page);

/** Round byte count down to page boundary */
#define BYTES_ROUND_DOWN(bytes) (PAGE(bytes) << PAGE_BITS)

/** Round byte count up to page boundary */
#define BYTES_ROUND_UP(bytes) (PAGE_ROUND_UP(bytes) << PAGE_BITS)

/** Enable/disable memory leak debugging */
#define LEAK_DEBUG 0

/**
 * Memory data structure
 * 
 * Represents the actual physical memory backing a mapping.
 * Multiple page table entries can reference the same data structure
 * (e.g., for shared memory or copy-on-write pages).
 */
struct data {
    /** Pointer to actual memory (immutable) */
    void *data;
    
    /** Size of the memory region in bytes (immutable) */
    size_t size;
    
    /** Reference count for this data structure */
    atomic_uint refcount;

    /* Fields for /proc/pid/maps display */
    /** File descriptor if this is a file mapping */
    struct fd *fd;
    
    /** Offset within file for file mappings */
    size_t file_offset;
    
    /** Name for special mappings (e.g., "[stack]") */
    const char *name;
    
#if LEAK_DEBUG
    /** Process ID that created this mapping (for debugging) */
    int pid;
    
    /** Destination address where this data was mapped (for debugging) */
    addr_t dest;
#endif
};

/**
 * Page table entry structure
 * 
 * Maps a virtual page to physical memory with specific access permissions.
 */
struct pt_entry {
    /** Data structure containing the actual memory */
    struct data *data;
    
    /** Offset within the data structure */
    size_t offset;
    
    /** Access flags (P_READ, P_WRITE, etc.) */
    unsigned flags;
    
    /** Linked list entries for managing memory blocks */
    struct list blocks[2];
};

/* Page flags for pt_entry.flags */

/** Read permission flag (currently ignored) */
#define P_READ (1 << 0)

/** Write permission flag */
#define P_WRITE (1 << 1)

/** 
 * Execute permission flag (currently ignored)
 * Undefined P_EXEC from darwin sys/proc.h to avoid conflicts
 */
#undef P_EXEC
#define P_EXEC (1 << 2)

/** Combined read/write/execute permissions */
#define P_RWX (P_READ | P_WRITE | P_EXEC)

/** Stack growth direction flag */
#define P_GROWSDOWN (1 << 3)

/** Copy-on-write flag */
#define P_COW (1 << 4)

/** Check if a page is writable */
#define P_WRITABLE(flags) (flags & P_WRITE && !(flags & P_COW))

/** Page was created with pt_map_nothing (anonymous mapping) */
#define P_ANONYMOUS (1 << 6)

/** 
 * Page was created with MAP_SHARED flag
 * Should not use copy-on-write
 */
#define P_SHARED (1 << 7)

/**
 * Check if a memory range is unmapped
 *
 * @param mem Memory structure
 * @param start Starting page number
 * @param pages Number of pages to check
 * @return true if the entire range is unmapped
 */
bool pt_is_hole(struct mem *mem, page_t start, pages_t pages);

/**
 * Find an unmapped memory region of sufficient size
 *
 * @param mem Memory structure
 * @param size Size of the region to find in pages
 * @return Starting page number or BAD_PAGE if no suitable hole found
 */
page_t pt_find_hole(struct mem *mem, pages_t size);

/**
 * Map physical memory into virtual address space
 *
 * Maps memory + offset into virtual memory, unmapping any existing mappings
 * in the target range. Takes ownership of the memory pointer, which will be
 * freed with munmap() when the mapping is removed.
 *
 * @param mem Memory structure
 * @param start Starting page number
 * @param pages Number of pages to map
 * @param memory Physical memory to map (must be page-aligned)
 * @param offset Offset within the memory
 * @param flags Access flags
 * @return 0 on success or negative error code
 */
int pt_map(struct mem *mem, page_t start, pages_t pages, void *memory, size_t offset, unsigned flags);

/**
 * Create an anonymous memory mapping
 *
 * @param mem Memory structure
 * @param page Starting page number
 * @param pages Number of pages to map
 * @param flags Access flags
 * @return 0 on success or negative error code
 */
int pt_map_nothing(struct mem *mem, page_t page, pages_t pages, unsigned flags);

/**
 * Unmap a range of virtual memory
 *
 * @param mem Memory structure
 * @param start Starting page number
 * @param pages Number of pages to unmap
 * @return 0 on success or -1 if any part of the range isn't mapped
 */
int pt_unmap(struct mem *mem, page_t start, pages_t pages);

/**
 * Unmap a range of virtual memory, ignoring unmapped pages
 *
 * Like pt_unmap but doesn't care if part of the range isn't mapped.
 *
 * @param mem Memory structure
 * @param start Starting page number
 * @param pages Number of pages to unmap
 * @return 0 on success
 */
int pt_unmap_always(struct mem *mem, page_t start, pages_t pages);

/**
 * Change access permissions on a range of memory
 *
 * @param mem Memory structure
 * @param start Starting page number
 * @param pages Number of pages to modify
 * @param flags New access flags
 * @return 0 on success or negative error code
 */
int pt_set_flags(struct mem *mem, page_t start, pages_t pages, int flags);

/**
 * Copy pages from source to destination memory using copy-on-write
 *
 * This is used during process forking to efficiently share memory
 * between parent and child until one of them writes to it.
 *
 * @param src Source memory structure
 * @param dst Destination memory structure
 * @param start Starting page number
 * @param pages Number of pages to copy
 * @return 0 on success or negative error code
 */
int pt_copy_on_write(struct mem *src, struct mem *dst, page_t start, page_t pages);

/**
 * Translate virtual address to physical memory pointer
 *
 * Must call with mem read-locked.
 *
 * @param mem Memory structure
 * @param addr Virtual address to translate
 * @param type Access type (MEM_READ, MEM_WRITE, MEM_WRITE_PTRACE)
 * @return Pointer to physical memory or NULL on error
 */
void *mem_ptr(struct mem *mem, addr_t addr, int type);

/**
 * Get the reason for a segmentation fault
 *
 * @param mem Memory structure
 * @param addr Virtual address that caused the fault
 * @return Reason code (typically _EFAULT)
 */
int mem_segv_reason(struct mem *mem, addr_t addr);

/**
 * Host system's actual page size
 * May differ from emulated PAGE_SIZE
 */
extern size_t real_page_size;

#endif
