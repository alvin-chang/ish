/**
 * iSH - Filesystem Implementation
 *
 * This header defines the filesystem architecture for the Linux emulation layer.
 * It implements a VFS (Virtual File System) layer that can support multiple filesystems
 * such as realfs (host filesystem), procfs (process information), devpts (pseudo terminals),
 * and tmpfs (in-memory filesystem).
 */

#ifndef FS_H
#define FS_H

#include "misc.h"
#include "util/list.h"
#include "fs/stat.h"
#include "fs/dev.h"
#include "fs/fake-db.h"
#include "fs/fix_path.h"
#include "kernel/memory.h"
#include <dirent.h>
#include <sqlite3.h>

/**
 * Filesystem information structure
 * 
 * Contains per-process filesystem context including current directory,
 * root directory, and permission information.
 */
struct fs_info {
    /** Reference count for tracking usage */
    atomic_uint refcount;
    
    /** Default umask for new files */
    mode_t_ umask;
    
    /** Current working directory */
    struct fd *pwd;
    
    /** Root directory (for chroot) */
    struct fd *root;
    
    /** Lock for filesystem operations */
    lock_t lock;
};

/**
 * Create a new filesystem context
 *
 * @return New fs_info structure or NULL on failure
 */
struct fs_info *fs_info_new(void);

/**
 * Create a copy of a filesystem context
 * Used during process forking
 *
 * @param fs Source filesystem context
 * @return New copy with increased references to pwd and root
 */
struct fs_info *fs_info_copy(struct fs_info *fs);

/**
 * Release a reference to a filesystem context
 * Frees the structure if reference count reaches zero
 *
 * @param fs Filesystem context to release
 */
void fs_info_release(struct fs_info *fs);

/**
 * Change current working directory
 *
 * @param fs Filesystem context to update
 * @param pwd New working directory
 */
void fs_chdir(struct fs_info *fs, struct fd *pwd);

/** Maximum path length in bytes (including null terminator) */
#define MAX_PATH 4096

/** Maximum filename length in bytes (including null terminator) */
#define MAX_NAME 256

/**
 * File attribute structure
 * 
 * Used for setting specific file attributes without
 * having to provide a complete stat structure
 */
struct attr {
    /** Type of attribute to set */
    enum attr_type {
        attr_uid,   /** User ID */
        attr_gid,   /** Group ID */
        attr_mode,  /** File mode/permissions */
        attr_size,  /** File size (for truncate) */
    } type;
    
    /** Attribute value */
    union {
        uid_t_ uid;
        uid_t_ gid;
        mode_t_ mode;
        off_t_ size;
    };
};

/**
 * Helper macro to create an attribute structure
 *
 * @param _type Attribute type (uid, gid, mode, size)
 * @param thing Value to set
 * @return Initialized attribute structure
 */
#define make_attr(_type, thing) \
    ((struct attr) {.type = attr_##_type, ._type = thing})

/** Follow symbolic links in path operations */
#define AT_SYMLINK_NOFOLLOW_ 0x100

/** If path is empty, operate on dirfd itself */
#define AT_EMPTY_PATH_ 0x1000

/**
 * Open a file using generic path resolution
 *
 * @param path File path
 * @param flags Open flags (O_RDONLY, O_WRONLY, etc.)
 * @param mode Create mode if O_CREAT is specified
 * @return New file descriptor or NULL with error code
 */
struct fd *generic_open(const char *path, int flags, int mode);

/**
 * Open a file relative to a directory file descriptor
 *
 * @param at Directory file descriptor or AT_FDCWD_
 * @param path File path relative to at
 * @param flags Open flags
 * @param mode Create mode
 * @return New file descriptor or NULL with error code
 */
struct fd *generic_openat(struct fd *at, const char *path, int flags, int mode);

/**
 * Get the absolute path of a file descriptor
 *
 * @param fd File descriptor
 * @param buf Buffer to store path (at least MAX_PATH bytes)
 * @return 0 on success or negative error code
 */
int generic_getpath(struct fd *fd, char *buf);

/**
 * Create a hard link
 *
 * @param src_at Source directory fd
 * @param src_raw Source path
 * @param dst_at Destination directory fd
 * @param dst_raw Destination path
 * @return 0 on success or negative error code
 */
int generic_linkat(struct fd *src_at, const char *src_raw, struct fd *dst_at, const char *dst_raw);

/**
 * Delete a file
 *
 * @param at Directory fd
 * @param path Path to unlink
 * @return 0 on success or negative error code
 */
int generic_unlinkat(struct fd *at, const char *path);

/**
 * Delete a directory
 *
 * @param at Directory fd
 * @param path Path to rmdir
 * @return 0 on success or negative error code
 */
int generic_rmdirat(struct fd *at, const char *path);

/**
 * Rename a file or directory
 *
 * @param src_at Source directory fd
 * @param src Source path
 * @param dst_at Destination directory fd
 * @param dst Destination path
 * @return 0 on success or negative error code
 */
int generic_renameat(struct fd *src_at, const char *src, struct fd *dst_at, const char *dst);

/**
 * Create a symbolic link
 *
 * @param target Link target
 * @param at Directory fd
 * @param link Path to create link at
 * @return 0 on success or negative error code
 */
int generic_symlinkat(const char *target, struct fd *at, const char *link);

/**
 * Create a special file
 *
 * @param at Directory fd
 * @param path File path
 * @param mode File mode and type
 * @param dev Device identifier (for device files)
 * @return 0 on success or negative error code
 */
int generic_mknodat(struct fd *at, const char *path, mode_t_ mode, dev_t_ dev);

/**
 * Generic seek implementation for file descriptors
 *
 * @param fd File descriptor
 * @param off Offset
 * @param whence Base position (LSEEK_SET, LSEEK_CUR, LSEEK_END)
 * @param size Current file size (for LSEEK_END)
 * @return New position or negative error code
 */
int generic_seek(struct fd *fd, off_t_ off, int whence, size_t size);

/** Access permission bits: read */
#define AC_R 4
/** Access permission bits: write */
#define AC_W 2
/** Access permission bits: execute */
#define AC_X 1
/** Access permission bits: check existence only */
#define AC_F 0

/**
 * Check if a file can be accessed with given permissions
 *
 * @param dirfd Directory fd
 * @param path Path to check
 * @param mode Access mode (AC_R, AC_W, AC_X, or combination)
 * @return 0 if accessible or negative error code
 */
int generic_accessat(struct fd *dirfd, const char *path, int mode);

/**
 * Get file status
 *
 * @param at Directory fd
 * @param path Path to stat
 * @param stat Buffer to store status
 * @param follow_links Whether to follow symbolic links
 * @return 0 on success or negative error code
 */
int generic_statat(struct fd *at, const char *path, struct statbuf *stat, bool follow_links);

/**
 * Set file attributes
 *
 * @param at Directory fd
 * @param path File path
 * @param attr Attribute to set
 * @param follow_links Whether to follow symbolic links
 * @return 0 on success or negative error code
 */
int generic_setattrat(struct fd *at, const char *path, struct attr attr, bool follow_links);

/**
 * Set file timestamps
 *
 * @param at Directory fd
 * @param path File path
 * @param atime Access time
 * @param mtime Modification time
 * @param follow_links Whether to follow symbolic links
 * @return 0 on success or negative error code
 */
int generic_utime(struct fd *at, const char *path, struct timespec atime, struct timespec mtime, bool follow_links);

/**
 * Read the target of a symbolic link
 *
 * @param at Directory fd
 * @param path Link path
 * @param buf Buffer to store target
 * @param bufsize Size of buffer
 * @return Number of bytes read or negative error code
 */
ssize_t generic_readlinkat(struct fd *at, const char *path, char *buf, size_t bufsize);

/**
 * Create a directory
 *
 * @param at Directory fd
 * @param path Path to create
 * @param mode Directory permissions
 * @return 0 on success or negative error code
 */
int generic_mkdirat(struct fd *at, const char *path, mode_t_ mode);

/**
 * Check if a process has permission to access a file
 *
 * @param stat File status
 * @param check Access mode to check
 * @return 0 if accessible or negative error code
 */
int access_check(struct statbuf *stat, int check);

/**
 * Mount point structure
 * 
 * Represents a mounted filesystem in the VFS layer
 */
struct mount {
    /** Mount point path */
    const char *point;
    
    /** Source path or device */
    const char *source;
    
    /** Mount options string */
    const char *info;
    
    /** Mount flags (MS_READONLY, etc.) */
    int flags;
    
    /** Filesystem operations */
    const struct fs_ops *fs;
    
    /** Reference count */
    unsigned refcount;
    
    /** Entry in global mounts list */
    struct list mounts;

    /** Host file descriptor for filesystem root */
    int root_fd;
    
    /** Filesystem-specific data */
    union {
        /** Generic data pointer */
        void *data;
        
        /** Fake filesystem database */
        struct fakefs_db fakefs;
    };
};

/** Lock for mount table operations */
extern lock_t mounts_lock;

/**
 * Find mount point for a path
 * Returns a reference that must be released with mount_release
 *
 * @param path Path to find mount for
 * @return Mount point or NULL if not found
 */
struct mount *mount_find(char *path);

/**
 * Increase reference count of a mount
 *
 * @param mount Mount point to retain
 */
void mount_retain(struct mount *mount);

/**
 * Decrease reference count of a mount
 * May free the mount if reference count reaches zero
 *
 * @param mount Mount point to release
 */
void mount_release(struct mount *mount);

/**
 * Mount a filesystem
 * Must hold mounts_lock while calling
 *
 * @param fs Filesystem operations
 * @param source Source path or device
 * @param point Mount point path
 * @param info Mount options
 * @param flags Mount flags
 * @return 0 on success or negative error code
 */
int do_mount(const struct fs_ops *fs, const char *source, const char *point, const char *info, int flags);

/**
 * Unmount a filesystem
 * Must hold mounts_lock while calling
 *
 * @param point Mount point path
 * @return 0 on success or negative error code
 */
int do_umount(const char *point);

/**
 * Remove a mount point
 * Must hold mounts_lock while calling
 *
 * @param mount Mount to remove
 * @return 0 on success or negative error code
 */
int mount_remove(struct mount *mount);

/** Global list of mount points */
extern struct list mounts;

/**
 * Check if a mount option flag is set
 *
 * @param info Mount options string
 * @param flag Flag to check for
 * @return true if flag is present
 */
bool mount_param_flag(const char *info, const char *flag);

/** File open mode mask */
#define O_ACCMODE_ 3
/** Open for reading only */
#define O_RDONLY_ 0
/** Open for writing only */
#define O_WRONLY_ (1 << 0)
/** Open for reading and writing */
#define O_RDWR_ (1 << 1)
/** Create file if it doesn't exist */
#define O_CREAT_ (1 << 6)
/** Fail if file exists and O_CREAT is set */
#define O_EXCL_ (1 << 7)
/** Don't make this terminal the controlling terminal */
#define O_NOCTTY_ (1 << 8)
/** Truncate file to zero length */
#define O_TRUNC_ (1 << 9)
/** Append to file */
#define O_APPEND_ (1 << 10)
/** Non-blocking mode */
#define O_NONBLOCK_ (1 << 11)
/** Must be a directory */
#define O_DIRECTORY_ (1 << 16)
/** Close on exec flag */
#define O_CLOEXEC_ (1 << 19)

/** Generic ioctl: get number of bytes available to read */
#define FIONREAD_ 0x541b
/** Generic ioctl: set/clear non-blocking flag */
#define FIONBIO_ 0x5421
/** Generic ioctl: clear close-on-exec flag */
#define FIONCLEX_ 0x5450
/** Generic ioctl: set close-on-exec flag */
#define FIOCLEX_ 0x5451

/**
 * Filesystem operations structure
 * 
 * Defines the operations for a filesystem type.
 * All operations are optional unless otherwise specified.
 */
struct fs_ops {
    /** Filesystem name */
    const char *name;
    
    /** Filesystem magic number (for statfs) */
    int magic;

    /** 
     * Mount a filesystem instance
     * Called during mount() system call
     */
    int (*mount)(struct mount *mount);
    
    /**
     * Unmount a filesystem instance
     * Called during umount() system call
     */
    int (*umount)(struct mount *mount);
    
    /**
     * Get filesystem statistics
     * Called during statfs() system call
     */
    int (*statfs)(struct mount *mount, struct statfsbuf *stat);

    /**
     * Open a file (required)
     * Called during open() system call
     */
    struct fd *(*open)(struct mount *mount, const char *path, int flags, int mode);
    
    /**
     * Read a symbolic link
     * Called during readlink() system call
     */
    ssize_t (*readlink)(struct mount *mount, const char *path, char *buf, size_t bufsize);

    /* These return _EPERM if not present */
    /**
     * Create a hard link
     * Called during link() system call
     */
    int (*link)(struct mount *mount, const char *src, const char *dst);
    
    /**
     * Unlink (delete) a file
     * Called during unlink() system call
     */
    int (*unlink)(struct mount *mount, const char *path);
    
    /**
     * Remove a directory
     * Called during rmdir() system call
     */
    int (*rmdir)(struct mount *mount, const char *path);
    
    /**
     * Rename a file or directory
     * Called during rename() system call
     */
    int (*rename)(struct mount *mount, const char *src, const char *dst);
    
    /**
     * Create a symbolic link
     * Called during symlink() system call
     */
    int (*symlink)(struct mount *mount, const char *target, const char *link);
    
    /**
     * Create a special file
     * Called during mknod() system call
     */
    int (*mknod)(struct mount *mount, const char *path, mode_t_ mode, dev_t_ dev);
    
    /**
     * Create a directory
     * Called during mkdir() system call
     */
    int (*mkdir)(struct mount *mount, const char *path, mode_t_ mode);

    /**
     * Close a file
     * 
     * There's a close function in both the fs and fd to handle device files
     * where, for instance, there's a real_fd needed for getpath and also a tty
     * reference, and both need to be released when the fd is closed.
     * If they are the same function, it will only be called once.
     */
    int (*close)(struct fd *fd);

    /**
     * Get file status (required)
     * Called during stat() system call
     */
    int (*stat)(struct mount *mount, const char *path, struct statbuf *stat);
    
    /**
     * Get open file status (required)
     * Called during fstat() system call
     */
    int (*fstat)(struct fd *fd, struct statbuf *stat);
    
    /**
     * Set file attributes
     * Called during chmod(), chown(), etc.
     */
    int (*setattr)(struct mount *mount, const char *path, struct attr attr);
    
    /**
     * Set open file attributes
     * Called during fchmod(), fchown(), etc.
     */
    int (*fsetattr)(struct fd *fd, struct attr attr);
    
    /**
     * Set file timestamps
     * Called during utimes() system call
     */
    int (*utime)(struct mount *mount, const char *path, struct timespec atime, struct timespec mtime);
    
    /**
     * Get file path (required)
     * Returns the path of the file descriptor, null terminated
     * buf must be at least MAX_PATH+1 bytes
     */
    int (*getpath)(struct fd *fd, char *buf);

    /**
     * Apply or release advisory lock
     * Called during flock() system call
     */
    int (*flock)(struct fd *fd, int operation);

    /**
     * Called when all references to an inode_data for this
     * filesystem go away.
     */
    void (*inode_orphaned)(struct mount *mount, ino_t inode);
};

/**
 * Find mount point for a path and modify the path to be relative to mount
 *
 * @param path Path to find mount for (modified in-place)
 * @return Mount point or NULL if not found
 */
struct mount *find_mount_and_trim_path(char *path);

/**
 * Create an ad-hoc file descriptor
 * Used for special files that don't correspond to filesystem objects
 *
 * @param ops File operations
 * @return New file descriptor or NULL on failure
 */
struct fd *adhoc_fd_create(const struct fd_ops *ops);

/**
 * Check if a file descriptor is an ad-hoc fd
 * Used for special cases in macOS file handling
 *
 * @param fd File descriptor to check
 * @return true if fd is an ad-hoc fd
 */
bool is_adhoc_fd(struct fd *fd);

/* Registered filesystems */
/** Process information filesystem */
extern const struct fs_ops procfs;

/** FakeFS (database-backed) filesystem */
extern const struct fs_ops fakefs;

/** Pseudo-terminal slave devices filesystem */
extern const struct fs_ops devptsfs;

/** In-memory temporary filesystem */
extern const struct fs_ops tmpfs;

/**
 * Register a new filesystem type
 * Called during initialization to set up available filesystems
 *
 * @param fs Filesystem operations
 */
void fs_register(const struct fs_ops *fs);

#endif
