/**
 * iSH - Translation Lookaside Buffer (TLB) Implementation
 *
 * This header defines the TLB structure and memory access functions for the x86 emulator.
 * The TLB caches virtual-to-physical address translations to speed up memory operations.
 */

#ifndef TLB_H
#define TLB_H

#include <string.h>
#include "emu/mmu.h"
#include "debug.h"

/**
 * TLB Entry structure
 * Each entry maps a virtual page to physical memory
 */
struct tlb_entry {
    page_t page;                 // Virtual page address (for read access)
    page_t page_if_writable;     // Virtual page address (for write access, 0 if read-only)
    uintptr_t data_minus_addr;   // Physical address minus virtual address for quick translation
};

// TLB size configuration (must be power of 2)
#define TLB_BITS 10
#define TLB_SIZE (1 << TLB_BITS)

/**
 * Translation Lookaside Buffer structure
 * Caches virtual-to-physical address translations for faster memory access
 */
struct tlb {
    struct mmu *mmu;          // Memory Management Unit for handling TLB misses
    page_t dirty_page;        // Most recently written page (for optimization)
    unsigned mem_changes;     // Counter of memory changes for detecting modifications
    
    // Address that caused a page fault (populated by various TLB functions)
    addr_t segfault_addr;
    
    // TLB entry cache
    struct tlb_entry entries[TLB_SIZE];
};

/**
 * Calculate TLB index for a given address
 * Uses hash function to distribute addresses across the TLB
 * 
 * @param addr Virtual memory address
 * @return TLB index (0 to TLB_SIZE-1)
 */
#define TLB_INDEX(addr) (((addr >> PAGE_BITS) & (TLB_SIZE - 1)) ^ (addr >> (PAGE_BITS + TLB_BITS)))

/**
 * Extract page address (4KB aligned) from full address
 * 
 * @param addr Virtual memory address
 * @return Page-aligned address (lowest 12 bits cleared)
 */
#define TLB_PAGE(addr) (addr & 0xfffff000)

/**
 * Special value to indicate an empty/invalid TLB entry
 */
#define TLB_PAGE_EMPTY 1

/**
 * Initialize or refresh a TLB with a new MMU
 * 
 * @param tlb TLB to initialize or refresh
 * @param mmu Memory Management Unit to associate with the TLB
 */
void tlb_refresh(struct tlb *tlb, struct mmu *mmu);

/**
 * Free resources associated with a TLB
 * 
 * @param tlb TLB to free
 */
void tlb_free(struct tlb *tlb);

/**
 * Flush (invalidate) all entries in the TLB
 * Called when memory mappings change
 * 
 * @param tlb TLB to flush
 */
void tlb_flush(struct tlb *tlb);

/**
 * Handle a TLB miss by updating the TLB cache
 * Called when an address is not found in the TLB
 * 
 * @param tlb TLB to update
 * @param addr Virtual address that caused the miss
 * @param type Access type (MEM_READ or MEM_WRITE)
 * @return Pointer to physical memory or NULL on error
 */
void *tlb_handle_miss(struct tlb *tlb, addr_t addr, int type);

/**
 * Get a pointer to physical memory for reading
 * Fast path for memory reads
 * 
 * @param tlb TLB for address translation
 * @param addr Virtual address to read
 * @return Pointer to physical memory or NULL on error
 */
forceinline __no_instrument void *__tlb_read_ptr(struct tlb *tlb, addr_t addr) {
    // Get TLB entry for this address
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    
    // Check if address is in cache (TLB hit)
    if (entry.page == TLB_PAGE(addr)) {
        // Calculate physical address using stored offset
        void *address = (void *) (entry.data_minus_addr + addr);
        posit(address != NULL);
        return address;
    }
    
    // TLB miss - handle it
    return tlb_handle_miss(tlb, addr, MEM_READ);
}

/**
 * Handle memory reads that cross page boundaries
 * 
 * @param tlb TLB for address translation
 * @param addr Starting virtual address
 * @param out Buffer to store read data
 * @param size Number of bytes to read
 * @return true on success, false on error
 */
bool __tlb_read_cross_page(struct tlb *tlb, addr_t addr, char *out, unsigned size);

/**
 * Read memory from a virtual address
 * Main interface for memory reads
 * 
 * @param tlb TLB for address translation
 * @param addr Virtual address to read from
 * @param out Buffer to store read data
 * @param size Number of bytes to read
 * @return true on success, false on error (page fault)
 */
forceinline __no_instrument bool tlb_read(struct tlb *tlb, addr_t addr, void *out, unsigned size) {
    // Check if read crosses page boundary
    if (PGOFFSET(addr) > PAGE_SIZE - size)
        return __tlb_read_cross_page(tlb, addr, out, size);
    
    // Get pointer to physical memory
    void *ptr = __tlb_read_ptr(tlb, addr);
    if (ptr == NULL)
        return false;
    
    // Copy data to output buffer
    memcpy(out, ptr, size);
    return true;
}

/**
 * Get a pointer to physical memory for writing
 * Fast path for memory writes
 * 
 * @param tlb TLB for address translation
 * @param addr Virtual address to write to
 * @return Pointer to physical memory or NULL on error (write protection)
 */
forceinline __no_instrument void *__tlb_write_ptr(struct tlb *tlb, addr_t addr) {
    // Get TLB entry for this address
    struct tlb_entry entry = tlb->entries[TLB_INDEX(addr)];
    
    // Check if address is in cache and is writable (TLB hit)
    if (entry.page_if_writable == TLB_PAGE(addr)) {
        // Mark page as dirty
        tlb->dirty_page = TLB_PAGE(addr);
        
        // Calculate physical address using stored offset
        void *address = (void *) (entry.data_minus_addr + addr);
        posit(address != NULL);
        return address;
    }
    
    // TLB miss or page not writable - handle it
    return tlb_handle_miss(tlb, addr, MEM_WRITE);
}

/**
 * Handle memory writes that cross page boundaries
 * 
 * @param tlb TLB for address translation
 * @param addr Starting virtual address
 * @param value Data to write
 * @param size Number of bytes to write
 * @return true on success, false on error
 */
bool __tlb_write_cross_page(struct tlb *tlb, addr_t addr, const char *value, unsigned size);

/**
 * Write memory to a virtual address
 * Main interface for memory writes
 * 
 * @param tlb TLB for address translation
 * @param addr Virtual address to write to
 * @param value Data to write
 * @param size Number of bytes to write
 * @return true on success, false on error (page fault or write protection)
 */
forceinline __no_instrument bool tlb_write(struct tlb *tlb, addr_t addr, const void *value, unsigned size) {
    // Check if write crosses page boundary
    if (PGOFFSET(addr) > PAGE_SIZE - size)
        return __tlb_write_cross_page(tlb, addr, value, size);
    
    // Get pointer to physical memory
    void *ptr = __tlb_write_ptr(tlb, addr);
    if (ptr == NULL)
        return false;
    
    // Copy data to memory
    memcpy(ptr, value, size);
    return true;
}

#endif /* TLB_H */
