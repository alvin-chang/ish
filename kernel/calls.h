/**
 * iSH - Linux System Call Interface
 *
 * This header defines the system call interface for the Linux emulation layer.
 * It includes system call implementations, user memory access functions, and 
 * process management routines.
 */

#ifndef CALLS_H
#define CALLS_H

#include "kernel/task.h"
#include "kernel/errno.h"
#include "fs/fd.h"
#include "fs/dev.h"
#include "kernel/fs.h"
#include "misc.h"

#include "kernel/signal.h"
#include "fs/sock.h"
#include "kernel/time.h"
#include "kernel/resource.h"
#include "kernel/ptrace.h"

/**
 * Handle CPU interrupt
 * Called when the emulated CPU generates an interrupt
 *
 * @param interrupt Interrupt number
 */
void handle_interrupt(int interrupt);

/* ==== User Memory Access Functions ==== */
/* 
 * These functions safely access memory in the emulated process's address space
 * They check permissions and handle page faults appropriately
 */

/**
 * Read data from user memory into kernel buffer
 *
 * @param addr User space address to read from
 * @param buf Kernel buffer to read into
 * @param count Number of bytes to read
 * @return 0 on success, negative error code on failure
 */
int must_check user_read(addr_t addr, void *buf, size_t count);

/**
 * Write data from kernel buffer to user memory
 *
 * @param addr User space address to write to
 * @param buf Kernel buffer to write from
 * @param count Number of bytes to write
 * @return 0 on success, negative error code on failure
 */
int must_check user_write(addr_t addr, const void *buf, size_t count);

/**
 * Read data from a specific task's user memory into kernel buffer
 *
 * @param task Target task
 * @param addr User space address to read from
 * @param buf Kernel buffer to read into
 * @param count Number of bytes to read
 * @return 0 on success, negative error code on failure
 */
int must_check user_read_task(struct task *task, addr_t addr, void *buf, size_t count);

/**
 * Write data from kernel buffer to a specific task's user memory
 *
 * @param task Target task
 * @param addr User space address to write to
 * @param buf Kernel buffer to write from
 * @param count Number of bytes to write
 * @return 0 on success, negative error code on failure
 */
int must_check user_write_task(struct task *task, addr_t addr, const void *buf, size_t count);

/**
 * Write data to a task's memory when using ptrace
 * Has special permissions for debugger access
 *
 * @param task Target task
 * @param addr User space address to write to
 * @param buf Kernel buffer to write from
 * @param count Number of bytes to write
 * @return 0 on success, negative error code on failure
 */
int must_check user_write_task_ptrace(struct task *task, addr_t addr, const void *buf, size_t count);

/**
 * Read a null-terminated string from user memory
 *
 * @param addr User space address of string
 * @param buf Kernel buffer to read into
 * @param max Maximum number of bytes to read
 * @return 0 on success, negative error code on failure
 */
int must_check user_read_string(addr_t addr, char *buf, size_t max);

/**
 * Write a null-terminated string to user memory
 *
 * @param addr User space address to write to
 * @param buf Kernel buffer containing null-terminated string
 * @return 0 on success, negative error code on failure
 */
int must_check user_write_string(addr_t addr, const char *buf);

/**
 * Read a single value from user memory
 *
 * @param addr User space address to read from
 * @param var Variable to store the read value
 * @return 0 on success, negative error code on failure
 */
#define user_get(addr, var) user_read(addr, &(var), sizeof(var))

/**
 * Write a single value to user memory
 *
 * @param addr User space address to write to
 * @param var Variable containing the value to write
 * @return 0 on success, negative error code on failure
 */
#define user_put(addr, var) user_write(addr, &(var), sizeof(var))

/**
 * Read a single value from a specific task's user memory
 */
#define user_get_task(task, addr, var) user_read_task(task, addr, &(var), sizeof(var))

/**
 * Write a single value to a specific task's user memory
 */
#define user_put_task(task, addr, var) user_write_task(task, addr, &(var), sizeof(var))

/* ==== Process Lifecycle System Calls ==== */

/**
 * Create a new process by cloning the current one
 * Implements the clone() system call
 *
 * @param flags Clone flags (CLONE_*)
 * @param stack Stack pointer for new process
 * @param ptid Pointer to store process ID at
 * @param tls Thread local storage pointer
 * @param ctid Pointer to store thread ID at
 * @return New process ID to parent, 0 to child, negative error code on failure
 */
dword_t sys_clone(dword_t flags, addr_t stack, addr_t ptid, addr_t tls, addr_t ctid);

/**
 * Create a new process by forking the current one
 * Implements the fork() system call
 *
 * @return New process ID to parent, 0 to child, negative error code on failure
 */
dword_t sys_fork(void);

/**
 * Create a new process by forking, but share memory until exec
 * Implements the vfork() system call
 *
 * @return New process ID to parent, 0 to child, negative error code on failure
 */
dword_t sys_vfork(void);

/**
 * Replace current process with a new program
 * Implements the execve() system call
 *
 * @param file Path to executable file
 * @param argv Array of argument strings
 * @param envp Array of environment strings
 * @return Does not return on success, negative error code on failure
 */
dword_t sys_execve(addr_t file, addr_t argv, addr_t envp);

/**
 * Internal implementation of execve with C string parameters
 *
 * @param file Path to executable file
 * @param argc Number of arguments
 * @param argv Array of argument strings
 * @param envp Array of environment strings
 * @return 0 on success, negative error code on failure
 */
int do_execve(const char *file, size_t argc, const char *argv, const char *envp);

/**
 * Exit the current process
 * Implements the exit() system call
 *
 * @param status Exit status
 * @return Does not return
 */
dword_t sys_exit(dword_t status);

/**
 * Internal implementation of process exit
 *
 * @param status Exit status
 */
noreturn void do_exit(int status);

/**
 * Exit all threads in the current process
 *
 * @param status Exit status
 */
noreturn void do_exit_group(int status);

/**
 * Exit all threads in the current process
 * Implements the exit_group() system call
 *
 * @param status Exit status
 * @return Does not return
 */
dword_t sys_exit_group(dword_t status);

/**
 * Wait for child process to change state
 * Implements the wait4() system call
 *
 * @param pid Process ID to wait for (-1 for any)
 * @param status_addr Address to store exit status
 * @param options Wait options
 * @param rusage_addr Address to store resource usage
 * @return Process ID of terminated child, negative error code on failure
 */
dword_t sys_wait4(pid_t_ pid, addr_t status_addr, dword_t options, addr_t rusage_addr);

/**
 * Wait for process matching specified criteria to change state
 * Implements the waitid() system call
 *
 * @param idtype Type of ID (P_PID, P_PGID, etc.)
 * @param id Process ID to wait for
 * @param info_addr Address to store process information
 * @param options Wait options
 * @return 0 on success, negative error code on failure
 */
dword_t sys_waitid(int_t idtype, pid_t_ id, addr_t info_addr, int_t options);

/**
 * Wait for child process to change state (older interface)
 * Implements the waitpid() system call
 *
 * @param pid Process ID to wait for
 * @param status_addr Address to store exit status
 * @param options Wait options
 * @return Process ID of terminated child, negative error code on failure
 */
dword_t sys_waitpid(pid_t_ pid, addr_t status_addr, dword_t options);

/* ==== Memory Management System Calls ==== */

/**
 * Change program break (end of data segment)
 * Implements the brk() system call
 *
 * @param new_brk New program break address
 * @return Current program break on success
 */
addr_t sys_brk(addr_t new_brk);

/* Memory mapping flags */
#define MMAP_SHARED 0x1      // Share changes with other processes
#define MMAP_PRIVATE 0x2     // Changes are private to this process
#define MMAP_FIXED 0x10      // Interpret addr exactly
#define MMAP_ANONYMOUS 0x20  // Don't use a file

/**
 * Map files or devices into memory (older interface)
 * Implements the mmap() system call
 *
 * @param args_addr Address of mmap arguments structure
 * @return Mapped memory address on success, MAP_FAILED on failure
 */
addr_t sys_mmap(addr_t args_addr);

/**
 * Map files or devices into memory
 * Implements the mmap2() system call
 *
 * @param addr Suggested address for mapping
 * @param len Length of mapping
 * @param prot Memory protection flags
 * @param flags Mapping flags
 * @param fd_no File descriptor to map
 * @param offset Offset in file (in pages)
 * @return Mapped memory address on success, MAP_FAILED on failure
 */
addr_t sys_mmap2(addr_t addr, dword_t len, dword_t prot, dword_t flags, fd_t fd_no, dword_t offset);

/**
 * Unmap memory pages
 * Implements the munmap() system call
 *
 * @param addr Start address to unmap
 * @param len Length to unmap
 * @return 0 on success, negative error code on failure
 */
int_t sys_munmap(addr_t addr, uint_t len);

/**
 * Change memory protection
 * Implements the mprotect() system call
 *
 * @param addr Start address to change protection
 * @param len Length to change
 * @param prot New protection flags
 * @return 0 on success, negative error code on failure
 */
int_t sys_mprotect(addr_t addr, uint_t len, int_t prot);

/**
 * Remap a memory mapping
 * Implements the mremap() system call
 *
 * @param addr Start address to remap
 * @param old_len Old mapping length
 * @param new_len New mapping length
 * @param flags Remapping flags
 * @return New mapping address on success, MAP_FAILED on failure
 */
int_t sys_mremap(addr_t addr, dword_t old_len, dword_t new_len, dword_t flags);

/**
 * Give advice about memory usage patterns
 * Implements the madvise() system call
 *
 * @param addr Start address
 * @param len Length
 * @param advice Advice to give
 * @return 0 on success, negative error code on failure
 */
dword_t sys_madvise(addr_t addr, dword_t len, dword_t advice);

/**
 * Set memory policy for a memory range
 * Implements the mbind() system call
 *
 * @param addr Start address
 * @param len Length
 * @param mode Policy mode
 * @param nodemask Bitmask of NUMA nodes
 * @param maxnode Maximum node in nodemask
 * @param flags Flags
 * @return 0 on success, negative error code on failure
 */
dword_t sys_mbind(addr_t addr, dword_t len, int_t mode, addr_t nodemask, dword_t maxnode, uint_t flags);

/**
 * Lock memory pages
 * Implements the mlock() system call
 *
 * @param addr Start address
 * @param len Length
 * @return 0 on success, negative error code on failure
 */
int_t sys_mlock(addr_t addr, dword_t len);

/**
 * Synchronize memory with physical storage
 * Implements the msync() system call
 *
 * @param addr Start address
 * @param len Length
 * @param flags Sync flags
 * @return 0 on success, negative error code on failure
 */
int_t sys_msync(addr_t addr, dword_t len, int_t flags);

/* ==== File Operation System Calls ==== */

/* File locking constants */
#define LOCK_SH_ 1  // Shared lock
#define LOCK_EX_ 2  // Exclusive lock
#define LOCK_NB_ 4  // Non-blocking operation
#define LOCK_UN_ 8  // Unlock

/**
 * IO vector structure for vectored I/O operations
 */
struct iovec_ {
    addr_t base;   // Memory address
    uint_t len;    // Length in bytes
};

/**
 * Read from a file descriptor
 * Implements the read() system call
 *
 * @param fd_no File descriptor
 * @param buf_addr Buffer address
 * @param size Number of bytes to read
 * @return Number of bytes read on success, negative error code on failure
 */
dword_t sys_read(fd_t fd_no, addr_t buf_addr, dword_t size);

/**
 * Read data into multiple buffers
 * Implements the readv() system call
 *
 * @param fd_no File descriptor
 * @param iovec_addr Array of iovec structures
 * @param iovec_count Number of iovec structures
 * @return Number of bytes read on success, negative error code on failure
 */
dword_t sys_readv(fd_t fd_no, addr_t iovec_addr, dword_t iovec_count);

/**
 * Write to a file descriptor
 * Implements the write() system call
 *
 * @param fd_no File descriptor
 * @param buf_addr Buffer address
 * @param size Number of bytes to write
 * @return Number of bytes written on success, negative error code on failure
 */
dword_t sys_write(fd_t fd_no, addr_t buf_addr, dword_t size);

/**
 * Write data from multiple buffers
 * Implements the writev() system call
 *
 * @param fd_no File descriptor
 * @param iovec_addr Array of iovec structures
 * @param iovec_count Number of iovec structures
 * @return Number of bytes written on success, negative error code on failure
 */
dword_t sys_writev(fd_t fd_no, addr_t iovec_addr, dword_t iovec_count);

/**
 * Reposition file offset (64-bit)
 * Implements the _llseek() system call
 *
 * @param f File descriptor
 * @param off_high High 32 bits of offset
 * @param off_low Low 32 bits of offset
 * @param res_addr Address to store result
 * @param whence Position from which to calculate offset
 * @return 0 on success, negative error code on failure
 */
dword_t sys__llseek(fd_t f, dword_t off_high, dword_t off_low, addr_t res_addr, dword_t whence);

/**
 * Reposition file offset (32-bit)
 * Implements the lseek() system call
 *
 * @param f File descriptor
 * @param off Offset
 * @param whence Position from which to calculate offset
 * @return New file position on success, negative error code on failure
 */
dword_t sys_lseek(fd_t f, dword_t off, dword_t whence);

/**
 * Read from a file descriptor at a given offset
 * Implements the pread() system call
 *
 * @param f File descriptor
 * @param buf_addr Buffer address
 * @param buf_size Number of bytes to read
 * @param off Offset in file
 * @return Number of bytes read on success, negative error code on failure
 */
dword_t sys_pread(fd_t f, addr_t buf_addr, dword_t buf_size, off_t_ off);

/**
 * Write to a file descriptor at a given offset
 * Implements the pwrite() system call
 *
 * @param f File descriptor
 * @param buf_addr Buffer address
 * @param size Number of bytes to write
 * @param off Offset in file
 * @return Number of bytes written on success, negative error code on failure
 */
dword_t sys_pwrite(fd_t f, addr_t buf_addr, dword_t size, off_t_ off);

/**
 * Control device
 * Implements the ioctl() system call
 *
 * @param f File descriptor
 * @param cmd Command code
 * @param arg Command-specific argument
 * @return Command-specific return value
 */
dword_t sys_ioctl(fd_t f, dword_t cmd, dword_t arg);

/**
 * Manipulate file descriptor
 * Implements the fcntl() system call
 *
 * @param f File descriptor
 * @param cmd Command code
 * @param arg Command-specific argument
 * @return Command-specific return value
 */
dword_t sys_fcntl(fd_t f, dword_t cmd, dword_t arg);

/**
 * Manipulate file descriptor (32-bit specific)
 * Implements the fcntl32() system call
 *
 * @param fd File descriptor
 * @param cmd Command code
 * @param arg Command-specific argument
 * @return Command-specific return value
 */
dword_t sys_fcntl32(fd_t fd, dword_t cmd, dword_t arg);

/**
 * Duplicate a file descriptor
 * Implements the dup() system call
 *
 * @param fd File descriptor to duplicate
 * @return New file descriptor on success, negative error code on failure
 */
dword_t sys_dup(fd_t fd);

/**
 * Duplicate a file descriptor to a specific number
 * Implements the dup2() system call
 *
 * @param fd File descriptor to duplicate
 * @param new_fd Desired new file descriptor
 * @return New file descriptor on success, negative error code on failure
 */
dword_t sys_dup2(fd_t fd, fd_t new_fd);

/**
 * Duplicate a file descriptor to a specific number with flags
 * Implements the dup3() system call
 *
 * @param f File descriptor to duplicate
 * @param new_f Desired new file descriptor
 * @param flags Duplication flags
 * @return New file descriptor on success, negative error code on failure
 */
dword_t sys_dup3(fd_t f, fd_t new_f, int_t flags);

/**
 * Close a file descriptor
 * Implements the close() system call
 *
 * @param fd File descriptor to close
 * @return 0 on success, negative error code on failure
 */
dword_t sys_close(fd_t fd);

/**
 * Synchronize a file's in-core state with storage device
 * Implements the fsync() system call
 *
 * @param f File descriptor
 * @return 0 on success, negative error code on failure
 */
dword_t sys_fsync(fd_t f);

/**
 * Apply or remove an advisory lock on an open file
 * Implements the flock() system call
 *
 * @param fd File descriptor
 * @param operation Lock operation
 * @return 0 on success, negative error code on failure
 */
dword_t sys_flock(fd_t fd, dword_t operation);

/**
 * Create a pipe
 * Implements the pipe() system call
 *
 * @param pipe_addr Address to store pipe file descriptors
 * @return 0 on success, negative error code on failure
 */
int_t sys_pipe(addr_t pipe_addr);

/**
 * Create a pipe with flags
 * Implements the pipe2() system call
 *
 * @param pipe_addr Address to store pipe file descriptors
 * @param flags Pipe flags
 * @return 0 on success, negative error code on failure
 */
int_t sys_pipe2(addr_t pipe_addr, int_t flags);

/**
 * Structure for poll() and related system calls
 */
struct pollfd_ {
    fd_t fd;         // File descriptor to poll
    word_t events;    // Events to check for
    word_t revents;   // Events that occurred
};

/**
 * Wait for events on multiple file descriptors
 * Implements the poll() system call
 *
 * @param fds Array of pollfd structures
 * @param nfds Number of file descriptors
 * @param timeout Timeout in milliseconds
 * @return Number of file descriptors with events, 0 on timeout, negative error code on failure
 */
dword_t sys_poll(addr_t fds, dword_t nfds, int_t timeout);

/**
 * Monitor multiple file descriptors for events
 * Implements the select() system call
 *
 * @param nfds Highest-numbered file descriptor plus 1
 * @param readfds_addr Set of descriptors to check for reading
 * @param writefds_addr Set of descriptors to check for writing
 * @param exceptfds_addr Set of descriptors to check for exceptions
 * @param timeout_addr Timeout structure
 * @return Number of file descriptors with events, 0 on timeout, negative error code on failure
 */
dword_t sys_select(fd_t nfds, addr_t readfds_addr, addr_t writefds_addr, addr_t exceptfds_addr, addr_t timeout_addr);

/**
 * Monitor multiple file descriptors for events with signal mask
 * Implements the pselect() system call
 *
 * @param nfds Highest-numbered file descriptor plus 1
 * @param readfds_addr Set of descriptors to check for reading
 * @param writefds_addr Set of descriptors to check for writing
 * @param exceptfds_addr Set of descriptors to check for exceptions
 * @param timeout_addr Timeout structure
 * @param sigmask_addr Signal mask to use during pselect()
 * @return Number of file descriptors with events, 0 on timeout, negative error code on failure
 */
dword_t sys_pselect(fd_t nfds, addr_t readfds_addr, addr_t writefds_addr, addr_t exceptfds_addr, addr_t timeout_addr, addr_t sigmask_addr);

/**
 * Poll multiple file descriptors with signal mask
 * Implements the ppoll() system call
 *
 * @param fds Array of pollfd structures
 * @param nfds Number of file descriptors
 * @param timeout_addr Timeout structure
 * @param sigmask_addr Signal mask to use during ppoll()
 * @param sigsetsize Size of signal mask
 * @return Number of file descriptors with events, 0 on timeout, negative error code on failure
 */
dword_t sys_ppoll(addr_t fds, dword_t nfds, addr_t timeout_addr, addr_t sigmask_addr, dword_t sigsetsize);

/**
 * Create an epoll instance
 * Implements the epoll_create() system call
 *
 * @param flags Creation flags
 * @return File descriptor for the new epoll instance, negative error code on failure
 */
fd_t sys_epoll_create(int_t flags);

/**
 * Create an epoll instance (older interface)
 * Implements the epoll_create() system call with no flags parameter
 *
 * @return File descriptor for the new epoll instance, negative error code on failure
 */
fd_t sys_epoll_create0(void);

int_t sys_epoll_ctl(fd_t epoll, int_t op, fd_t fd, addr_t event_addr);
int_t sys_epoll_wait(fd_t epoll, addr_t events_addr, int_t max_events, int_t timeout);
int_t sys_epoll_pwait(fd_t epoll_f, addr_t events_addr, int_t max_events, int_t timeout, addr_t sigmask_addr, dword_t sigsetsize);

int_t sys_eventfd2(uint_t initval, int_t flags);
int_t sys_eventfd(uint_t initval);

// file management
fd_t sys_open(addr_t path_addr, dword_t flags, mode_t_ mode);
fd_t sys_openat(fd_t at, addr_t path_addr, dword_t flags, mode_t_ mode);
dword_t sys_close(fd_t fd);
dword_t sys_link(addr_t src_addr, addr_t dst_addr);
dword_t sys_linkat(fd_t src_at_f, addr_t src_addr, fd_t dst_at_f, addr_t dst_addr);
dword_t sys_unlink(addr_t path_addr);
dword_t sys_unlinkat(fd_t at_f, addr_t path_addr, int_t flags);
dword_t sys_rmdir(addr_t path_addr);
dword_t sys_rename(addr_t src_addr, addr_t dst_addr);
dword_t sys_renameat(fd_t src_at_f, addr_t src_addr, fd_t dst_at_f, addr_t dst_addr);
dword_t sys_renameat2(fd_t src_at_f, addr_t src_addr, fd_t dst_at_f, addr_t dst_addr, int_t flags);
dword_t sys_symlink(addr_t target_addr, addr_t link_addr);
dword_t sys_symlinkat(addr_t target_addr, fd_t at_f, addr_t link_addr);
dword_t sys_mknod(addr_t path_addr, mode_t_ mode, dev_t_ dev);
dword_t sys_mknodat(fd_t at_f, addr_t path_addr, mode_t_ mode, dev_t_ dev);
dword_t sys_access(addr_t path_addr, dword_t mode);
dword_t sys_faccessat(fd_t at_f, addr_t path, mode_t_ mode, dword_t flags);
dword_t sys_readlink(addr_t path, addr_t buf, dword_t bufsize);
dword_t sys_readlinkat(fd_t at_f, addr_t path, addr_t buf, dword_t bufsize);
int_t sys_getdents(fd_t f, addr_t dirents, dword_t count);
int_t sys_getdents64(fd_t f, addr_t dirents, dword_t count);
dword_t sys_stat64(addr_t path_addr, addr_t statbuf_addr);
dword_t sys_lstat64(addr_t path_addr, addr_t statbuf_addr);
dword_t sys_fstat64(fd_t fd_no, addr_t statbuf_addr);
dword_t sys_fstatat64(fd_t at, addr_t path_addr, addr_t statbuf_addr, dword_t flags);
dword_t sys_fchmod(fd_t f, dword_t mode);
dword_t sys_fchmodat(fd_t at_f, addr_t path_addr, dword_t mode);
dword_t sys_chmod(addr_t path_addr, dword_t mode);
dword_t sys_fchown32(fd_t f, dword_t owner, dword_t group);
dword_t sys_fchownat(fd_t at_f, addr_t path_addr, dword_t owner, dword_t group, int flags);
dword_t sys_chown32(addr_t path_addr, uid_t_ owner, uid_t_ group);
dword_t sys_lchown(addr_t path_addr, uid_t_ owner, uid_t_ group);
dword_t sys_truncate64(addr_t path_addr, dword_t size_low, dword_t size_high);
dword_t sys_ftruncate64(fd_t f, dword_t size_low, dword_t size_high);
dword_t sys_fallocate(fd_t f, dword_t mode, dword_t offset_low, dword_t offset_high, dword_t len_low, dword_t len_high);
dword_t sys_mkdir(addr_t path_addr, mode_t_ mode);
dword_t sys_mkdirat(fd_t at_f, addr_t path_addr, mode_t_ mode);
dword_t sys_utimensat(fd_t at_f, addr_t path_addr, addr_t times_addr, dword_t flags);
dword_t sys_utimes(addr_t path_addr, addr_t times_addr);
dword_t sys_utime(addr_t path_addr, addr_t times_addr);
dword_t sys_times( addr_t tbuf);
dword_t sys_umask(dword_t mask);

dword_t sys_sendfile(fd_t out_fd, fd_t in_fd, addr_t offset_addr, dword_t count);
dword_t sys_sendfile64(fd_t out_fd, fd_t in_fd, addr_t offset_addr, dword_t count);
dword_t sys_splice(fd_t in_fd, addr_t in_off_addr, fd_t out_fd, addr_t out_off_addr, dword_t count, dword_t flags);
dword_t sys_copy_file_range(fd_t in_fd, addr_t in_off, fd_t out_fd, addr_t out_off, dword_t len, uint_t flags);

dword_t sys_statfs(addr_t path_addr, addr_t buf_addr);
dword_t sys_statfs64(addr_t path_addr, dword_t buf_size, addr_t buf_addr);
dword_t sys_fstatfs(fd_t f, addr_t buf_addr);
dword_t sys_fstatfs64(fd_t f, addr_t buf_addr);
dword_t sys_statx(fd_t at_f, addr_t path_addr, int_t flags, uint_t mask, addr_t statx_addr);

#define MS_READONLY_ (1 << 0)
#define MS_NOSUID_ (1 << 1)
#define MS_NODEV_ (1 << 2)
#define MS_NOEXEC_ (1 << 3)
#define MS_SILENT_ (1 << 15)
dword_t sys_mount(addr_t source_addr, addr_t target_addr, addr_t type_addr, dword_t flags, addr_t data_addr);
dword_t sys_umount2(addr_t target_addr, dword_t flags);

dword_t sys_xattr_stub(addr_t path_addr, addr_t name_addr, addr_t value_addr, dword_t size, dword_t flags);

// process information
pid_t_ sys_getpid(void);
pid_t_ sys_gettid(void);
pid_t_ sys_getppid(void);
pid_t_ sys_getpgid(pid_t_ pid);
dword_t sys_setpgid(pid_t_ pid, pid_t_ pgid);
pid_t_ sys_getpgrp(void);
dword_t sys_setpgrp(void);
uid_t_ sys_getuid32(void);
uid_t_ sys_getuid(void);
int_t sys_setuid(uid_t uid);
uid_t_ sys_geteuid32(void);
uid_t_ sys_geteuid(void);
int_t sys_setgid(uid_t gid);
uid_t_ sys_getgid32(void);
uid_t_ sys_getgid(void);
uid_t_ sys_getegid32(void);
uid_t_ sys_getegid(void);
dword_t sys_setresuid(uid_t_ ruid, uid_t_ euid, uid_t_ suid);
dword_t sys_setresgid(uid_t_ rgid, uid_t_ egid, uid_t_ sgid);
int_t sys_setreuid(uid_t_ ruid, uid_t_ euid);
int_t sys_setregid(uid_t_ rgid, uid_t_ egid);
int_t sys_getresuid(addr_t ruid_addr, addr_t euid_addr, addr_t suid_addr);
int_t sys_getresgid(addr_t rgid_addr, addr_t egid_addr, addr_t sgid_addr);
int_t sys_getgroups(dword_t size, addr_t list);
int_t sys_setgroups(dword_t size, addr_t list);
int_t sys_capget(addr_t header_addr, addr_t data_addr);
int_t sys_capset(addr_t header_addr, addr_t data_addr);
dword_t sys_getcwd(addr_t buf_addr, dword_t size);
dword_t sys_chdir(addr_t path_addr);
dword_t sys_chroot(addr_t path_addr);
dword_t sys_fchdir(fd_t f);
int_t sys_personality(dword_t pers);
int task_set_thread_area(struct task *task, addr_t u_info);
int sys_set_thread_area(addr_t u_info);
int sys_set_tid_address(addr_t blahblahblah);
dword_t sys_setsid(void);
dword_t sys_getsid(void);

int_t sys_sched_yield(void);
int_t sys_prctl(dword_t option, uint_t arg2, uint_t arg3, uint_t arg4, uint_t arg5);
int_t sys_arch_prctl(int_t code, addr_t addr);
int_t sys_reboot(int_t magic, int_t magic2, int_t cmd);

// system information
#define UNAME_LENGTH 65
struct uname {
    char system[UNAME_LENGTH];   // Linux
    char hostname[UNAME_LENGTH]; // my-compotar
    char release[UNAME_LENGTH];  // 1.2.3-ish
    char version[UNAME_LENGTH];  // SUPER AWESOME
    char arch[UNAME_LENGTH];     // i686
    char domain[UNAME_LENGTH];   // lol
};
void do_uname(struct uname *uts);
dword_t sys_uname(addr_t uts_addr);
dword_t sys_sethostname(addr_t hostname_addr, dword_t hostname_len);

struct sys_info {
    dword_t uptime;
    dword_t loads[3];
    dword_t totalram;
    dword_t freeram;
    dword_t sharedram;
    dword_t bufferram;
    dword_t totalswap;
    dword_t freeswap;
    word_t procs;
    dword_t totalhigh;
    dword_t freehigh;
    dword_t mem_unit;
    char pad;
};
dword_t sys_sysinfo(addr_t info_addr);

// futexes
dword_t sys_futex(addr_t uaddr, dword_t op, dword_t val, addr_t timeout_or_val2, addr_t uaddr2, dword_t val3);
int_t sys_set_robust_list(addr_t robust_list, dword_t len);
int_t sys_get_robust_list(pid_t_ pid, addr_t robust_list_ptr, addr_t len_ptr);

// misc
dword_t sys_getrandom(addr_t buf_addr, dword_t len, dword_t flags);
int_t sys_syslog(int_t type, addr_t buf_addr, int_t len);
int_t sys_ipc(uint_t call, int_t first, int_t second, int_t third, addr_t ptr, int_t fifth);

typedef int (*syscall_t)(dword_t, dword_t, dword_t, dword_t, dword_t, dword_t);

#endif
