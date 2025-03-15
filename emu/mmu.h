/**
 * iSH - Memory Management Unit (MMU) Implementation
 *
 * This header defines the MMU interface for the x86 emulator.
 * The MMU handles virtual-to-physical address translation and memory access permissions.
 */

#ifndef EMU_CPU_MEM_H
#define EMU_CPU_MEM_H

#include "misc.h"

/**
 * Page number type (virtual address >> 12)
 * Represents the top 20 bits of a 32-bit address
 */
typedef dword_t page_t;

/**
 * Special value indicating an invalid page
 */
#define BAD_PAGE 0x10000

#ifndef __KERNEL__
/**
 * Page size and addressing constants
 */
#define PAGE_BITS 12                  // Number of bits in page offset (log2 of page size)
#undef PAGE_SIZE                      // Undefine to avoid conflict with system headers
#define PAGE_SIZE (1 << PAGE_BITS)    // Page size in bytes (4 KB)
#define PAGE(addr) ((addr) >> PAGE_BITS) // Extract page number from address
#define PGOFFSET(addr) ((addr) & (PAGE_SIZE - 1)) // Extract offset within page

/**
 * Type for tracking sets of pages
 */
typedef dword_t pages_t;

/**
 * Round up to the next page boundary
 * IMPORTANT: bytes MUST be unsigned for correct overflow behavior to zero
 */
#define PAGE_ROUND_UP(bytes) (PAGE((bytes) + PAGE_SIZE - 1))

/**
 * Maximum number of memory pages in the virtual address space
 * 2^20 pages = 4 GB address space (32-bit)
 */
#define MEM_PAGES (1 << 20)
#endif

/**
 * Memory Management Unit structure
 * Provides the interface for memory address translation
 */
struct mmu {
    struct mmu_ops *ops;      // Operations table for memory access
    struct asbestos *asbestos; // Sandbox escape detection mechanism
    uint64_t changes;         // Counter incremented on memory mapping changes
};

/**
 * Memory access types
 */
#define MEM_READ 0           // Read access
#define MEM_WRITE 1          // Write access
#define MEM_WRITE_PTRACE 2   // Write access from debugger/ptrace (special permissions)

/**
 * MMU operations table
 * Provides function pointers for memory operations
 */
struct mmu_ops {
    /**
     * Translate a virtual address to a physical memory pointer
     *
     * @param mmu MMU context
     * @param addr Virtual address to translate
     * @param type Access type (MEM_READ, MEM_WRITE, or MEM_WRITE_PTRACE)
     * @return Pointer to physical memory or NULL on error
     *         (page fault, permission error, etc.)
     */
    void *(*translate)(struct mmu *mmu, addr_t addr, int type);
};

/**
 * Translate a virtual address to a physical memory pointer
 * Convenience wrapper for the translate operation
 *
 * @param mmu MMU context
 * @param addr Virtual address to translate
 * @param type Access type (MEM_READ, MEM_WRITE, or MEM_WRITE_PTRACE)
 * @return Pointer to physical memory or NULL on error
 */
static inline void *mmu_translate(struct mmu *mmu, addr_t addr, int type) {
    return mmu->ops->translate(mmu, addr, type);
}

#endif /* EMU_CPU_MEM_H */