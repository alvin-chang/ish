/**
 * iSH - Utility Macros and Type Definitions
 *
 * This header provides common utility macros and type definitions used throughout
 * the iSH project. It includes preprocessor utilities, compiler-specific features,
 * and type definitions for the emulated x86 environment.
 */

#ifndef MISC_H
#define MISC_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <assert.h>
#include <sys/types.h>
#include <stdnoreturn.h>
#include <stdbool.h>
#include <stdint.h>
#endif

/* ==== Preprocessor Utility Macros ==== */

/**
 * Concatenate two tokens
 */
#define glue(a, b) _glue(a, b)
#define _glue(a, b) a##b

/**
 * Concatenate three tokens
 */
#define glue3(a,b,c) glue(a, glue(b, c))

/**
 * Concatenate four tokens
 */
#define glue4(a,b,c,d) glue(a, glue3(b, c, d))

/**
 * Convert token to string
 */
#define str(x) _str(x)
#define _str(x) #x

/* ==== Compiler Feature Detection ==== */

/**
 * Check if using GCC of specified version or higher
 */
#define is_gcc(version) (__GNUC__ >= version)

/**
 * Check if compiler has a specific attribute
 */
#if !defined(__has_attribute)
#define has_attribute(x) 0
#else
#define has_attribute __has_attribute
#endif

/**
 * Check if compiler has a specific feature
 */
#if !defined(__has_feature)
#define has_feature(x) 0
#else
#define has_feature __has_feature
#endif

/* ==== Keyword/Attribute Definitions ==== */

/**
 * Type for bit fields
 */
#define bitfield unsigned int

/**
 * Force function to be inlined
 */
#define forceinline inline __attribute__((always_inline))

/**
 * Assert or assume a condition (depends on build type)
 */
#if defined(NDEBUG) || defined(__KERNEL__)
#define posit __builtin_assume
#else
#define posit assert
#endif

/**
 * Mark a function as requiring return value checking
 */
#define must_check __attribute__((warn_unused_result))

#ifndef __KERNEL__
/**
 * Mark a branch as unlikely for optimization purposes
 */
#define unlikely(x) __builtin_expect((x), 0)

/**
 * Type check a variable
 */
#define typecheck(type, x) ({type _x = x; x;})

/**
 * Get containing struct pointer from member pointer
 */
#define container_of(ptr, type, member) \
    ((type *) ((char *) (ptr) - offsetof(type, member)))

/**
 * Mark a fallthrough in a switch statement
 */
#if has_attribute(fallthrough)
#define fallthrough __attribute__((fallthrough))
#else
#define fallthrough
#endif
#endif

/**
 * Disable various sanitizer instrumentations for a function
 */
#if has_attribute(no_sanitize)
#define __no_instrument_msan
#if defined(__has_feature)
#if has_feature(memory_sanitizer)
#undef __no_instrument_msan
#define __no_instrument_msan __attribute__((no_sanitize("memory"))
#endif
#endif
#define __no_instrument __attribute__((no_sanitize("address", "thread", "undefined", "leak"))) __no_instrument_msan
#else
#define __no_instrument
#endif

/**
 * Mark strncpy as safe to avoid certain compiler warnings
 */
#if has_attribute(nonstring)
#define __strncpy_safe __attribute__((nonstring))
#else
#define __strncpy_safe
#endif

/**
 * Initialize a variable to zero
 */
#define zero_init(type) ((type[1]){}[0])

/**
 * Type punning (reinterpret cast)
 */
#define pun(type, x) (((union {typeof(x) _; type a;}) (x)).a)

/**
 * Mark a variable as unused to avoid warnings
 */
#define UNUSED(x) UNUSED_##x __attribute__((unused))

/**
 * Force compiler to use specified variables
 */
static inline void __use(int dummy __attribute__((unused)), ...) {}
#define use(...) __use(0, ##__VA_ARGS__)

/**
 * Read the time-stamp counter on different architectures
 */
#if defined(__x86_64__)
#define rdtsc() ({ \
        uint32_t low, high; \
        __asm__ volatile("rdtsc" : "=a" (high), "=d" (low)); \
        ((uint64_t) high) << 32 | low; \
    })
#elif defined(__arm64__) || defined(__aarch64__)
#define rdtsc() ({ \
        uint64_t tsc; \
        __asm__ volatile("mrs %0, PMCCNTR_EL0" : "=r" (tsc)); \
        tsc; \
    })
#endif

#ifndef __KERNEL__
/**
 * Calculate the number of elements in a statically-allocated array
 */
#define array_size(arr) (sizeof(arr)/sizeof((arr)[0]))
#endif

/* ==== Type Definitions ==== */

/**
 * Architecture-specific basic types for the emulated environment
 */
typedef int64_t sqword_t;   // Signed 64-bit integer
typedef uint64_t qword_t;   // Unsigned 64-bit integer
typedef uint32_t dword_t;   // Unsigned 32-bit integer (double word)
typedef int32_t sdword_t;   // Signed 32-bit integer
typedef uint16_t word_t;    // Unsigned 16-bit integer (word)
typedef uint8_t byte_t;     // Unsigned 8-bit integer (byte)

/**
 * Architecture-specific address and integer types
 */
typedef dword_t addr_t;     // Address type (32-bit for x86)
typedef dword_t uint_t;     // Unsigned integer type
typedef sdword_t int_t;     // Signed integer type

/**
 * Linux kernel system call types for the emulated environment
 */
typedef sdword_t pid_t_;    // Process ID
typedef dword_t uid_t_;     // User ID
typedef word_t mode_t_;     // File permissions
typedef sqword_t off_t_;    // File offset
typedef dword_t time_t_;    // Time value
typedef dword_t clock_t_;   // Clock ticks

/**
 * Macro to generate uint/sint types with specific bit width
 */
#define uint(size) glue3(uint,size,_t)
#define sint(size) glue3(int,size,_t)

#ifndef __KERNEL__
/**
 * Macros for error pointer handling
 */
#define ERR_PTR(err) (void *) (intptr_t) (err)
#define PTR_ERR(ptr) (intptr_t) (ptr)
#define IS_ERR(ptr) ((uintptr_t) (ptr) > (uintptr_t) -0xfff)
#endif

#endif
