/**
 * iSH - File Descriptor Implementation
 *
 * This header defines the file descriptor system used in the Linux emulation layer.
 * It provides abstractions for various file types (regular files, directories, sockets, etc.)
 * and implements the file descriptor table used by processes.
 */

#ifndef FD_H
#define FD_H
#include <dirent.h>
#include "kernel/memory.h"
#include "util/list.h"
#include "util/sync.h"
#include "util/bits.h"
#include "fs/stat.h"
#include "fs/proc.h"
#include "fs/sockrestart.h"

// FIXME almost everything that uses the structs in this file does so without any kind of sane locking

/**
 * Core file descriptor structure
 * 
 * Represents an open file descriptor in the emulated system.
 * Can represent regular files, directories, pipes, sockets, and special devices.
 */
struct fd {
    /** Reference count for tracking usage and proper cleanup */
    atomic_uint refcount;
    
    /** File descriptor flags (O_APPEND, O_NONBLOCK, etc.) */
    unsigned flags;
    
    /** File type (S_IFREG, S_IFDIR, S_IFSOCK, etc.) - cannot change after creation */
    mode_t_ type;
    
    /** Function table for file operations */
    const struct fd_ops *ops;
    
    /** List of poll monitors watching this fd */
    struct list poll_fds;
    
    /** Lock for poll operations */
    lock_t poll_lock;
    
    /** Current file position (for lseek) */
    unsigned long offset;

    /**
     * File descriptor type-specific data
     * Union to save memory as each fd only needs one of these structures
     */
    union {
        /** TTY (terminal) specific data */
        struct {
            /** Pointer to TTY structure */
            struct tty *tty;
            
            /** Linked list of other fds pointing to the same TTY (locked by the TTY) */
            struct list tty_other_fds;
        };
        
        /** epoll instance data */
        struct {
            /** Pointer to poll structure */
            struct poll *poll;
        } epollfd;
        
        /** eventfd specific data */
        struct {
            /** Current counter value */
            uint64_t val;
        } eventfd;
        
        /** timerfd specific data */
        struct {
            /** Pointer to timer structure */
            struct timer *timer;
            
            /** Number of timer expirations */
            uint64_t expirations;
        } timerfd;
        
        /** Socket specific data */
        struct {
            /** Socket domain (AF_INET, AF_UNIX, etc.) */
            int domain;
            
            /** Socket type (SOCK_STREAM, SOCK_DGRAM, etc.) */
            int type;
            
            /** Socket protocol */
            int protocol;

            /** 
             * Unix domain socket naming - these fields are used to maintain
             * strong references to keep the socket alive while there is a listener
             */
            struct inode_data *unix_name_inode;      /** Inode for named Unix socket */
            struct unix_abstract *unix_name_abstract; /** Abstract namespace socket */
            uint8_t unix_name_len;                   /** Length of socket name */
            char unix_name[108];                     /** Socket name/path */
            
            /** Connected peer socket (locked by peer_lock for simplicity) */
            struct fd *unix_peer;
            
            /** Condition variable signaled when a peer connects */
            cond_t unix_got_peer;
            
            /** Queue of file descriptors being passed via SCM_RIGHTS (locked by fd->lock) */
            struct list unix_scm;
            
            /** Credentials for socket peer */
            struct ucred_ {
                pid_t_ pid;    /** Process ID */
                uid_t_ uid;    /** User ID */
                uid_t_ gid;    /** Group ID */
            } unix_cred;
        } socket;

        /** 
         * Clipboard integration for iOS paste support
         * See app/Pasteboard.m for implementation details 
         */
        struct {
            /** UIPasteboard.changeCount - tracks clipboard changes */
            uint64_t generation;
            
            /** Buffer for clipboard data */
            void* buffer;
            
            /** Buffer capacity */
            size_t buffer_cap;
            
            /** Actual data length in buffer */
            size_t buffer_len;
        } clipboard;

        /** 
         * Generic data pointer for custom file types
         * Can store any type-specific data 
         */
        void *data;
    };
    
    /**
     * Filesystem-specific data
     * Varies depending on the filesystem type
     */
    union {
        /** procfs-specific data */
        struct {
            /** Entry in the proc filesystem */
            struct proc_entry entry;
            
            /** Current index in directory */
            unsigned dir_index;
            
            /** Proc data for this file */
            struct proc_data data;
        } proc;
        
        /** devpts-specific data (pseudo terminals) */
        struct {
            /** PTY number */
            int num;
        } devpts;
        
        /** tmpfs-specific data */
        struct {
            /** Directory entry in tmpfs */
            struct tmp_dirent *dirent;
            
            /** Current position in directory */
            struct tmp_dirent *dir_pos;
        } tmpfs;
        
        /** Generic filesystem-specific data */
        void *fs_data;
    };

    /** Mount point this file belongs to */
    struct mount *mount;
    
    /** 
     * Real file descriptor (on host system)
     * Seeks on this fd require the lock
     * TODO: Consider making a special lock just for that
     */
    int real_fd;
    
    /** Directory stream for directory fds */
    DIR *dir;
    
    /** Inode data for this file */
    struct inode_data *inode;
    
    /** 
     * Emulated inode number 
     * Used for filesystems that don't have real inodes
     */
    ino_t fake_inode;
    
    /** 
     * File statistics
     * Used for ad-hoc filesystems that don't have backing storage
     */
    struct statbuf stat;
    
    /** Socket restart information */
    struct fd_sockrestart sockrestart;

    /** Lock for fd operations */
    lock_t lock;
    
    /** Condition variable for blocking operations */
    cond_t cond;
};

typedef sdword_t fd_t;
#define AT_FDCWD_ -100

/**
 * Create a new file descriptor
 *
 * @param ops File operations table for the new fd
 * @return Newly created file descriptor or NULL on failure
 */
struct fd *fd_create(const struct fd_ops *ops);

/**
 * Increase the reference count of a file descriptor
 *
 * @param fd File descriptor to retain
 * @return The same file descriptor
 */
struct fd *fd_retain(struct fd *fd);

/**
 * Close and release a file descriptor
 * Decrements reference count and frees if it reaches zero
 *
 * @param fd File descriptor to close
 * @return 0 on success, negative error code on failure
 */
int fd_close(struct fd *fd);

/**
 * Get flags of a file descriptor (O_APPEND, O_NONBLOCK, etc.)
 *
 * @param fd File descriptor
 * @return Flags or negative error code
 */
int fd_getflags(struct fd *fd);

/**
 * Set flags on a file descriptor
 *
 * @param fd File descriptor
 * @param flags New flags to set
 * @return 0 on success, negative error code on failure
 */
int fd_setflags(struct fd *fd, int flags);

#define NAME_MAX 255
/**
 * Directory entry structure
 * Used when reading directories
 */
struct dir_entry {
    /** Inode number */
    qword_t inode;
    
    /** File name (null-terminated) */
    char name[NAME_MAX + 1];
};

#define LSEEK_SET 0
#define LSEEK_CUR 1
#define LSEEK_END 2

/**
 * File descriptor operations table
 * Defines the behavior of different file types
 */
struct fd_ops {
    /* ==== File Operations ==== */
    
    /**
     * Read from a file descriptor
     * Required for files, may be NULL for some file types
     */
    ssize_t (*read)(struct fd *fd, void *buf, size_t bufsize);
    
    /**
     * Write to a file descriptor
     * Required for files, may be NULL for some file types
     */
    ssize_t (*write)(struct fd *fd, const void *buf, size_t bufsize);
    
    /**
     * Read from a file descriptor at specific offset
     * Similar to read() but doesn't change file position
     */
    ssize_t (*pread)(struct fd *fd, void *buf, size_t bufsize, off_t off);
    
    /**
     * Write to a file descriptor at specific offset
     * Similar to write() but doesn't change file position
     */
    ssize_t (*pwrite)(struct fd *fd, const void *buf, size_t bufsize, off_t off);
    
    /**
     * Change file position
     * Implements lseek() system call
     */
    off_t_ (*lseek)(struct fd *fd, off_t_ off, int whence);

    /* ==== Directory Operations ==== */
    
    /**
     * Read a directory entry
     * Required for directories
     *
     * @param fd File descriptor (must be a directory)
     * @param entry Pointer to store the directory entry
     * @return 0 on success, negative error code or 1 at end of directory
     */
    int (*readdir)(struct fd *fd, struct dir_entry *entry);
    
    /**
     * Return current position in directory stream
     * Optional, fd->offset will be used if NULL
     *
     * @param fd File descriptor (must be a directory)
     * @return Opaque value representing current position
     */
    unsigned long (*telldir)(struct fd *fd);
    
    /**
     * Seek to position in directory stream
     * Optional, fd->offset will be used if NULL
     *
     * @param fd File descriptor (must be a directory)
     * @param ptr Position value from telldir()
     */
    void (*seekdir)(struct fd *fd, unsigned long ptr);

    /* ==== Memory Mapping ==== */
    
    /**
     * Memory map a file
     * Implements mmap() system call
     *
     * @param fd File descriptor to map
     * @param mem Memory structure to map into
     * @param start Start address in pages
     * @param pages Number of pages to map
     * @param offset Offset within file
     * @param prot Memory protection flags
     * @param flags Mapping flags
     * @return 0 on success, negative error code on failure
     */
    int (*mmap)(struct fd *fd, struct mem *mem, page_t start, pages_t pages, off_t offset, int prot, int flags);

    /* ==== Polling and I/O Control ==== */
    
    /**
     * Poll file descriptor for events
     * Returns a bitmask of operations that won't block
     *
     * @param fd File descriptor to poll
     * @return Bitmask of available operations
     */
    int (*poll)(struct fd *fd);

    /**
     * Get required buffer size for ioctl command
     *
     * @param cmd Ioctl command code
     * @return Size needed for ioctl buffer, 0 if arg isn't a pointer, -1 for invalid command
     */
    ssize_t (*ioctl_size)(int cmd);
    
    /**
     * Perform device-specific I/O control
     * Implements ioctl() system call
     *
     * @param fd File descriptor
     * @param cmd Command code
     * @param arg Command-specific argument
     * @return 0 on success, negative error code on failure
     */
    int (*ioctl)(struct fd *fd, int cmd, void *arg);

    /* ==== Miscellaneous Operations ==== */
    
    /**
     * Synchronize file with storage device
     * Implements fsync() system call
     *
     * @param fd File descriptor to sync
     * @return 0 on success, negative error code on failure
     */
    int (*fsync)(struct fd *fd);
    
    /**
     * Close a file descriptor
     * Called when the fd is being released
     *
     * @param fd File descriptor to close
     * @return 0 on success, negative error code on failure
     */
    int (*close)(struct fd *fd);

    /**
     * Get file descriptor flags
     * Implements F_GETFL for fcntl()
     *
     * @param fd File descriptor
     * @return Flags or negative error code
     */
    int (*getflags)(struct fd *fd);
    
    /**
     * Set file descriptor flags
     * Implements F_SETFL for fcntl()
     *
     * @param fd File descriptor
     * @param arg New flags
     * @return 0 on success, negative error code on failure
     */
    int (*setflags)(struct fd *fd, dword_t arg);
};

/**
 * File descriptor table
 * Represents the collection of open file descriptors for a process
 */
struct fdtable {
    /** Reference count for sharing between threads */
    atomic_uint refcount;
    
    /** Size of the file descriptor table */
    unsigned size;
    
    /** Array of file descriptor pointers */
    struct fd **files;
    
    /** Bitmap of close-on-exec flags */
    bits_t *cloexec;
    
    /** Lock for table modifications */
    lock_t lock;
};

/**
 * Create a new file descriptor table
 *
 * @param size Initial size of the table
 * @return New file descriptor table or NULL on failure
 */
struct fdtable *fdtable_new(int size);

/**
 * Decrease reference count on a file descriptor table
 * Frees the table if count reaches zero
 *
 * @param table File descriptor table
 */
void fdtable_release(struct fdtable *table);

/**
 * Create a copy of a file descriptor table
 * Used when forking processes
 *
 * @param table File descriptor table to copy
 * @return New copy of the table or NULL on failure
 */
struct fdtable *fdtable_copy(struct fdtable *table);

/**
 * Free a file descriptor table and all contained file descriptors
 *
 * @param table File descriptor table to free
 */
void fdtable_free(struct fdtable *table);

/**
 * Close file descriptors marked with FD_CLOEXEC
 * Called during execve()
 *
 * @param table File descriptor table
 */
void fdtable_do_cloexec(struct fdtable *table);

/**
 * Get a file descriptor from a table
 *
 * @param table File descriptor table
 * @param f File descriptor number
 * @return File descriptor structure or NULL if not found
 */
struct fd *fdtable_get(struct fdtable *table, fd_t f);

/**
 * Get a file descriptor from the current process
 *
 * @param f File descriptor number
 * @return File descriptor structure or NULL if not found
 */
struct fd *f_get(fd_t f);

/**
 * Install a file descriptor into the current process's table
 *
 * @param fd File descriptor structure
 * @param flags Descriptor flags (e.g., FD_CLOEXEC)
 * @return Assigned file descriptor number or negative error code
 */
fd_t f_install(struct fd *fd, int flags);

/**
 * Close a file descriptor in the current process
 *
 * @param f File descriptor number
 * @return 0 on success, negative error code on failure
 */
int f_close(fd_t f);

#endif
