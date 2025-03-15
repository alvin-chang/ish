/**
 * iSH - x86 CPU Emulation
 *
 * This header defines the CPU state and operations for the x86 emulator.
 * It includes register and flag definitions, FPU state, and helper functions
 * for CPU operations.
 */
#ifndef EMU_H
#define EMU_H

#include "misc.h"
#include "emu/mmu.h"
#include "emu/float80.h"

#ifdef __KERNEL__
#include <linux/stddef.h>
#else
#include <stddef.h>
#endif

struct cpu_state;
struct tlb;

/**
 * Execute CPU instructions until an interrupt or signal occurs
 *
 * @param cpu The CPU state
 * @param tlb Translation Lookaside Buffer for memory access
 * @return Status code indicating reason for stopping execution
 */
int cpu_run_to_interrupt(struct cpu_state *cpu, struct tlb *tlb);

/**
 * Signal the CPU to stop execution at next instruction boundary
 *
 * @param cpu The CPU state to interrupt
 */
void cpu_poke(struct cpu_state *cpu);

/**
 * MMX register representation (64-bit)
 * Can be accessed as a 64-bit value or two 32-bit values
 */
union mm_reg {
    qword_t qw;      // 64-bit access
    dword_t dw[2];   // 32-bit access (2 dwords)
};

/**
 * SSE/XMM register representation (128-bit)
 * Can be accessed in various formats (byte, word, dword, float, etc.)
 */
union xmm_reg {
    unsigned __int128 u128;  // 128-bit integer access
    qword_t qw[2];           // As two 64-bit integers
    uint32_t u32[4];         // As four 32-bit integers
    uint16_t u16[8];         // As eight 16-bit integers
    uint8_t u8[16];          // As sixteen 8-bit integers
    float f32[4];            // As four 32-bit floats
    double f64[2];           // As two 64-bit doubles
};
static_assert(sizeof(union xmm_reg) == 16, "xmm_reg size");
static_assert(sizeof(union mm_reg) == 8, "mm_reg size");

/**
 * Complete state of an emulated x86 CPU
 * Contains all registers, flags, and associated state information
 */
struct cpu_state {
    struct mmu *mmu;     // Memory Management Unit
    long cycle;          // Current CPU cycle count

    /* ==== General Purpose Registers ==== */
    // Define register unions to handle different register sizes (e.g., eax vs ax)
    // _REG for registers without low/high byte access
    // _REGX for registers with low/high byte access
#define _REG(n) \
    union { \
        dword_t e##n;    /* 32-bit register (e.g., esp) */ \
        word_t n;        /* 16-bit register (e.g., sp) */ \
    }
#define _REGX(n) \
    union { \
        dword_t e##n##x; /* 32-bit register (e.g., eax) */ \
        word_t n##x;     /* 16-bit register (e.g., ax) */ \
        struct { \
            byte_t n##l; /* Low byte (e.g., al) */ \
            byte_t n##h; /* High byte (e.g., ah) */ \
        }; \
    }

    // Main register block with both individual register
    // access and array access for efficient indexing
    union {
        struct {
            _REGX(a);    // EAX/AX/AH/AL - Accumulator
            _REGX(c);    // ECX/CX/CH/CL - Counter
            _REGX(d);    // EDX/DX/DH/DL - Data
            _REGX(b);    // EBX/BX/BH/BL - Base
            _REG(sp);    // ESP/SP - Stack Pointer
            _REG(bp);    // EBP/BP - Base Pointer
            _REG(si);    // ESI/SI - Source Index
            _REG(di);    // EDI/DI - Destination Index
        };
        dword_t regs[8]; // Array access to all 8 general registers
    };
#undef REGX
#undef REG

    dword_t eip;         // Instruction Pointer

    /* ==== CPU Flags ==== */
    union {
        dword_t eflags;  // Full 32-bit flags register
        struct {
            // Individual flag bits
            bitfield cf_bit:1;  // Carry Flag bit
            bitfield pad1_1:1;  // Reserved (always 1)
            bitfield pf:1;      // Parity Flag
            bitfield pad2_0:1;  // Reserved (always 0)
            bitfield af:1;      // Auxiliary Carry Flag
            bitfield pad3_0:1;  // Reserved (always 0)
            bitfield zf:1;      // Zero Flag
            bitfield sf:1;      // Sign Flag
            bitfield tf:1;      // Trap Flag
            bitfield if_:1;     // Interrupt Enable Flag
            bitfield df:1;      // Direction Flag
            bitfield of_bit:1;  // Overflow Flag bit
            bitfield iopl:2;    // I/O Privilege Level
        };
        // Flag masks for assembly code access
#define PF_FLAG (1 << 2)
#define AF_FLAG (1 << 4)
#define ZF_FLAG (1 << 6)
#define SF_FLAG (1 << 7)
#define DF_FLAG (1 << 10)
    };
    // Direction flag offset for string operations
    dword_t df_offset;   // Set to +/- size based on DF
    
    // Separate storage for CF and OF flags for performance
    byte_t cf;           // Carry Flag
    byte_t of;           // Overflow Flag
    
    /* ==== Lazy Flag Evaluation Support ==== */
    // Store operands and result for deferred flag calculation
    dword_t res, op1, op2;
    union {
        struct {
            // Flags for deferred evaluation
            bitfield pf_res:1;  // Calculate PF from result
            bitfield zf_res:1;  // Calculate ZF from result
            bitfield sf_res:1;  // Calculate SF from result
            bitfield af_ops:1;  // Calculate AF from operands
        };
        // Flag masks for assembly code access
#define PF_RES (1 << 0)
#define ZF_RES (1 << 1)
#define SF_RES (1 << 2)
#define AF_OPS (1 << 3)
        byte_t flags_res;
    };

    /* ==== SIMD Registers ==== */
    union mm_reg mm[8];   // 8 MMX registers (MM0-MM7)
    union xmm_reg xmm[8]; // 8 XMM registers (XMM0-XMM7)

    /* ==== FPU State ==== */
    float80 fp[8];        // 8 FPU registers (ST0-ST7)
    
    // FPU Status Word
    union {
        word_t fsw;       // Full status word
        struct {
            // FPU status flags
            bitfield ie:1;   // Invalid operation exception
            bitfield de:1;   // Denormalized operand exception
            bitfield ze:1;   // Divide by zero exception
            bitfield oe:1;   // Overflow exception
            bitfield ue:1;   // Underflow exception
            bitfield pe:1;   // Precision exception
            bitfield stf:1;  // Stack fault
            bitfield es:1;   // Error summary status
            bitfield c0:1;   // Condition code 0
            bitfield c1:1;   // Condition code 1
            bitfield c2:1;   // Condition code 2
            unsigned top:3;  // Register stack pointer (0-7)
            bitfield c3:1;   // Condition code 3
            bitfield b:1;    // FPU busy
        };
    };
    
    // FPU Control Word
    union {
        word_t fcw;       // Full control word
        struct {
            // Exception mask bits (1 = masked/ignored)
            bitfield im:1;   // Invalid operation mask
            bitfield dm:1;   // Denormal operand mask
            bitfield zm:1;   // Divide by zero mask
            bitfield om:1;   // Overflow mask
            bitfield um:1;   // Underflow mask
            bitfield pm:1;   // Precision mask
            bitfield pad4:2; // Reserved
            bitfield pc:2;   // Precision control
            bitfield rc:2;   // Rounding control
            bitfield y:1;    // Infinity control (obsolete)
        };
    };

    /* ==== Thread-Local Storage ==== */
    word_t gs;            // GS segment register
    addr_t tls_ptr;       // Thread-local storage pointer

    /* ==== Exception Handling ==== */
    addr_t segfault_addr; // Address that caused page fault
    bool segfault_was_write; // Whether fault was from write operation

    dword_t trapno;       // Trap/exception number
    
    /* ==== CPU Control ==== */
    // For signaling the CPU to stop execution
    bool *poked_ptr;      // Pointer to poked flag (for atomic access)
    bool _poked;          // Private copy of poked flag
};

// Verify struct member offsets for access optimization
#define CPU_OFFSET(field) offsetof(struct cpu_state, field)

// Ensure register array layout matches individual registers
static_assert(CPU_OFFSET(eax) == CPU_OFFSET(regs[0]), "register order");
static_assert(CPU_OFFSET(ecx) == CPU_OFFSET(regs[1]), "register order");
static_assert(CPU_OFFSET(edx) == CPU_OFFSET(regs[2]), "register order");
static_assert(CPU_OFFSET(ebx) == CPU_OFFSET(regs[3]), "register order");
static_assert(CPU_OFFSET(esp) == CPU_OFFSET(regs[4]), "register order");
static_assert(CPU_OFFSET(ebp) == CPU_OFFSET(regs[5]), "register order");
static_assert(CPU_OFFSET(esi) == CPU_OFFSET(regs[6]), "register order");
static_assert(CPU_OFFSET(edi) == CPU_OFFSET(regs[7]), "register order");

// Size check to prevent overflow in vector operations
static_assert(sizeof(struct cpu_state) < 0xffff, "cpu struct is too big for vector gadgets");

/* ==== Flag Access Macros ==== */
// These macros implement lazy flag evaluation for better performance
// Each flag can be stored directly or computed from operation results

// Zero Flag - result is zero
#define ZF (cpu->zf_res ? cpu->res == 0 : cpu->zf)
// Sign Flag - result is negative (highest bit set)
#define SF (cpu->sf_res ? (int32_t) cpu->res < 0 : cpu->sf)
// Carry Flag - unsigned overflow occurred
#define CF (cpu->cf)
// Overflow Flag - signed overflow occurred
#define OF (cpu->of)
// Parity Flag - number of 1 bits in low byte is even
#define PF (cpu->pf_res ? !__builtin_parity(cpu->res & 0xff) : cpu->pf)
// Auxiliary Flag - carry from bit 3 to bit 4
#define AF (cpu->af_ops ? ((cpu->op1 ^ cpu->op2 ^ cpu->res) >> 4) & 1 : cpu->af)

/**
 * Collapse all lazily-evaluated flags into their direct representations
 * Call this before saving EFLAGS or when flag computation becomes too complex
 *
 * @param cpu CPU state to update
 */
static inline void collapse_flags(struct cpu_state *cpu) {
    // Compute lazily-evaluated flags and store them directly
    cpu->zf = ZF;
    cpu->sf = SF;
    cpu->pf = PF;
    // Clear lazy evaluation flags
    cpu->zf_res = cpu->sf_res = cpu->pf_res = 0;
    // Store CF and OF in EFLAGS register
    cpu->of_bit = cpu->of;
    cpu->cf_bit = cpu->cf;
    // Compute and store AF
    cpu->af = AF;
    cpu->af_ops = 0;
    // Set reserved bits to required values
    cpu->pad1_1 = 1;
    cpu->pad2_0 = cpu->pad3_0 = 0;
    // Ensure IF is set (interrupts enabled)
    cpu->if_ = 1;
}

/**
 * Expand flags from EFLAGS register into direct representations
 * Call this after loading EFLAGS from memory
 *
 * @param cpu CPU state to update
 */
static inline void expand_flags(struct cpu_state *cpu) {
    // Copy flags from EFLAGS register to separate storage
    cpu->of = cpu->of_bit;
    cpu->cf = cpu->cf_bit;
    // Clear lazy evaluation flags
    cpu->zf_res = cpu->sf_res = cpu->pf_res = cpu->af_ops = 0;
}

/**
 * Enumeration of x86 32-bit general purpose registers
 * Used for register addressing in instructions
 */
enum reg32 {
    reg_eax = 0, reg_ecx, reg_edx, reg_ebx, reg_esp, reg_ebp, reg_esi, reg_edi, reg_count,
    reg_none = reg_count, // Special value indicating no register
};

/**
 * Get string name of register for debugging and tracing
 *
 * @param reg Register number
 * @return String name of the register (e.g., "eax")
 */
static inline const char *reg32_name(enum reg32 reg) {
    switch (reg) {
        case reg_eax: return "eax";
        case reg_ecx: return "ecx";
        case reg_edx: return "edx";
        case reg_ebx: return "ebx";
        case reg_esp: return "esp";
        case reg_ebp: return "ebp";
        case reg_esi: return "esi";
        case reg_edi: return "edi";
        default: return "?";
    }
}

#endif /* EMU_H */
