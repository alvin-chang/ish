/**
 * iSH - Debugging and Logging Utilities
 *
 * This header provides macros and functions for debugging, logging, and error handling
 * throughout the iSH project. It establishes a consistent debug output mechanism with
 * various verbosity levels and specialized debug channels.
 */

#ifndef UTIL_DEBUG_H
#define UTIL_DEBUG_H
#include <stdio.h>
#include <stdlib.h>

/**
 * Print kernel-style debug messages with formatting
 * 
 * @param msg Format string for the message
 * @param ... Format arguments
 */
void ish_printk(const char *msg, ...);

/**
 * Print kernel-style debug messages with va_list arguments
 * 
 * @param msg Format string for the message
 * @param args Variable argument list
 */
void ish_vprintk(const char *msg, va_list args);

// Replace standard printk with our implementation
#undef printk
#define printk ish_printk

/* ==== Debug Channel Configuration ==== */

/**
 * Master switch for all debug output
 * Set to 1 to enable all debug channels by default
 */
#ifndef DEBUG_all
#define DEBUG_all 0
#endif

/**
 * Enable/disable verbose debugging (general purpose messages)
 */
#ifndef DEBUG_verbose
#define DEBUG_verbose DEBUG_all
#endif

/**
 * Enable/disable instruction debugging (CPU instruction tracing)
 */
#ifndef DEBUG_instr
#define DEBUG_instr DEBUG_all
#endif

/**
 * Enable/disable debug-specific messages
 */
#ifndef DEBUG_debug
#define DEBUG_debug DEBUG_all
#endif

/**
 * Enable/disable system call tracing
 */
#ifndef DEBUG_strace
#define DEBUG_strace DEBUG_all
#endif

/**
 * Enable/disable memory operation debugging
 */
#ifndef DEBUG_memory
#define DEBUG_memory DEBUG_all
#endif

/* ==== Debug Channel Macros ==== */

/**
 * Configure trace macros based on enabled debug channels
 */
#if DEBUG_verbose
#define TRACE_verbose TRACE__
#else
#define TRACE_verbose TRACE__NOP
#endif

#if DEBUG_instr
#define TRACE_instr TRACE__
#else
#define TRACE_instr TRACE__NOP
#endif

#if DEBUG_debug
#define TRACE_debug TRACE__
#else
#define TRACE_debug TRACE__NOP
#endif

#if DEBUG_strace
#define TRACE_strace TRACE__
#else
#define TRACE_strace TRACE__NOP
#endif

#if DEBUG_memory
#define TRACE_memory TRACE__
#else
#define TRACE_memory TRACE__NOP
#endif

/**
 * Handle log overrides - allows forcing debug output even when disabled
 */
#ifdef LOG_OVERRIDE
extern int log_override;
#define TRACE__NOP(msg, ...) if (log_override) { TRACE__(msg, ##__VA_ARGS__); }
#else
#define TRACE__NOP(msg, ...) use(__VA_ARGS__)
#endif

/**
 * Low-level trace function that outputs debug messages
 */
#define TRACE__(msg, ...) printk(msg, ##__VA_ARGS__)

/**
 * Generic trace macros with channel selection
 */
#define TRACE_(chan, msg, ...) glue(TRACE_, chan)(msg, ##__VA_ARGS__)
#define TRACE(msg, ...) TRACE_(DEFAULT_CHANNEL, msg, ##__VA_ARGS__)

/**
 * Default debug channel if not specified
 */
#ifndef DEFAULT_CHANNEL
#define DEFAULT_CHANNEL verbose
#endif

/* ==== Error and Warning Utilities ==== */

/**
 * Mark unimplemented code (causes program termination)
 */
#define TODO(msg, ...) die("TODO: " msg, ##__VA_ARGS__)

/**
 * Mark code that needs fixing (just prints a warning)
 */
#define FIXME(msg, ...) printk("FIXME " msg "\n", ##__VA_ARGS__)

/**
 * Exit with error message from perror
 */
#define ERRNO_DIE(msg) { perror(msg); abort(); }

/**
 * Custom die handler function pointer
 * Can be set to override the default die behavior
 */
extern void (*die_handler)(const char *msg);

/**
 * Terminate program with error message
 * 
 * @param msg Format string for error message
 * @param ... Format arguments
 */
_Noreturn void die(const char *msg, ...);

/**
 * Shorthand for system call tracing
 */
#define STRACE(msg, ...) TRACE_(strace, msg, ##__VA_ARGS__)

/* ==== Debugging Breakpoints ==== */

/**
 * Insert a programmatic breakpoint for debuggers
 * Uses architecture-specific debug trap instructions
 */
#if defined(__i386__) || defined(__x86_64__)
#define debugger __asm__("int3")
#else
#include <signal.h>
#define debugger raise(SIGTRAP)
#endif

#endif /* UTIL_DEBUG_H */