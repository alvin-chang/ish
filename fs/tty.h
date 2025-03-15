/**
 * iSH - Terminal (TTY) Implementation
 *
 * This header defines the terminal (TTY) subsystem for the Linux emulation layer.
 * It implements terminal devices, including pseudo-terminals (PTYs), and provides
 * the interface for terminal-related operations such as line discipline, control codes,
 * and window sizing.
 */

#ifndef TTY_H
#define TTY_H

#include "kernel/fs.h"
#include "fs/dev.h"

/**
 * Terminal window size structure
 * Represents the dimensions of a terminal window
 */
struct winsize_ {
    /** Number of rows (characters) */
    word_t row;
    
    /** Number of columns (characters) */
    word_t col;
    
    /** Width in pixels (may not be used) */
    word_t xpixel;
    
    /** Height in pixels (may not be used) */
    word_t ypixel;
};

/**
 * Terminal I/O settings structure
 * Based on the Linux kernel termios structure
 * Controls terminal behavior like echo, line buffering, etc.
 */
struct termios_ {
    /** Input mode flags */
    dword_t iflags;
    
    /** Output mode flags */
    dword_t oflags;
    
    /** Control mode flags */
    dword_t cflags;
    
    /** Local mode flags */
    dword_t lflags;
    
    /** Line discipline */
    byte_t line;
    
    /** Control characters (VINTR, VEOF, etc.) */
    byte_t cc[19];
};

/* Special character indices in termios.c_cc[] */
/** Interrupt character (typically Ctrl-C) */
#define VINTR_ 0
/** Quit character (typically Ctrl-\) */
#define VQUIT_ 1
/** Erase character (typically backspace) */
#define VERASE_ 2
/** Kill character (erase current line) */
#define VKILL_ 3
/** End-of-file character (typically Ctrl-D) */
#define VEOF_ 4
/** Time value for read timeout */
#define VTIME_ 5
/** Minimum number of characters for read */
#define VMIN_ 6
/** Switch character (unused) */
#define VSWTC_ 7
/** Start flow control (typically Ctrl-Q) */
#define VSTART_ 8
/** Stop flow control (typically Ctrl-S) */
#define VSTOP_ 9
/** Suspend character (typically Ctrl-Z) */
#define VSUSP_ 10
/** End-of-line character */
#define VEOL_ 11
/** Reprint current line (typically Ctrl-R) */
#define VREPRINT_ 12
/** Discard output (typically Ctrl-O) */
#define VDISCARD_ 13
/** Word erase character (typically Ctrl-W) */
#define VWERASE_ 14
/** Literal next character (typically Ctrl-V) */
#define VLNEXT_ 15
/** Alternate end-of-line character */
#define VEOL2_ 16

/* Local mode flags (c_lflag) */
/** Enable signals (INTR, QUIT, etc.) */
#define ISIG_ (1 << 0)
/** Enable canonical mode (line-by-line input) */
#define ICANON_ (1 << 1)
/** Echo input characters */
#define ECHO_ (1 << 3)
/** Echo erase character as BS-SP-BS */
#define ECHOE_ (1 << 4)
/** Echo kill character (newline) */
#define ECHOK_ (1 << 5)
/** Echo kill with all chars on new line */
#define ECHOKE_ (1 << 6)
/** Don't flush after signals */
#define NOFLSH_ (1 << 7)
/** Echo control characters as ^X */
#define ECHOCTL_ (1 << 9)
/** Enable implementation-defined input processing */
#define IEXTEN_ (1 << 15)

/* Input mode flags (c_iflag) */
/** Map NL to CR on input */
#define INLCR_ (1 << 6)
/** Ignore CR on input */
#define IGNCR_ (1 << 7)
/** Map CR to NL on input */
#define ICRNL_ (1 << 8)
/** Enable start/stop flow control */
#define IXON_ (1 << 10)

/* Output mode flags (c_oflag) */
/** Enable implementation-defined output processing */
#define OPOST_ (1 << 0)
/** Map NL to CR-NL on output */
#define ONLCR_ (1 << 2)
/** Map CR to NL on output */
#define OCRNL_ (1 << 3)
/** Don't output CR at column 0 */
#define ONOCR_ (1 << 4)
/** Don't output CR */
#define ONLRET_ (1 << 5)

/* TTY ioctl commands */
/** Get termios struct */
#define TCGETS_ 0x5401
/** Set termios struct immediately */
#define TCSETS_ 0x5402
/** Set termios struct after output drained */
#define TCSETSW_ 0x5403
/** Set termios struct after flushing queue */
#define TCSETSF_ 0x5404
/** Flush TTY buffer */
#define TCFLSH_ 0x540b
/** Make this TTY the controlling TTY */
#define TIOCSCTTY_ 0x540e
/** Get foreground process group */
#define TIOCGPGRP_ 0x540f
/** Set foreground process group */
#define TIOCSPGRP_ 0x5410
/** Get window size */
#define TIOCGWINSZ_ 0x5413
/** Set window size */
#define TIOCSWINSZ_ 0x5414
/** Enable/disable packet mode */
#define TIOCPKT_ 0x5420
/** Get PTY number */
#define TIOCGPTN_ 0x80045430
/** Lock/unlock PTY */
#define TIOCSPTLCK_ 0x40045431
/** Get packet mode state */
#define TIOCGPKT_ 0x80045438

/* TTY flush constants */
/** Flush received data */
#define TCIFLUSH_ 0
/** Flush written data */
#define TCOFLUSH_ 1
/** Flush both received and written data */
#define TCIOFLUSH_ 2

/**
 * TTY driver structure
 * Represents a class of TTY devices (e.g., ptys, serial)
 */
struct tty_driver {
    /** Operations for this TTY driver */
    const struct tty_driver_ops *ops;
    
    /** Major device number */
    int major;
    
    /** Array of TTY instances for this driver */
    struct tty **ttys;
    
    /** Maximum number of TTYs for this driver */
    unsigned limit;
};

/**
 * Define a new TTY driver with given parameters
 *
 * @param name Name of the driver
 * @param driver_ops Driver operations structure
 * @param _major Major device number
 * @param size Maximum number of TTY devices for this driver
 */
#define DEFINE_TTY_DRIVER(name, driver_ops, _major, size) \
    static struct tty *name##_ttys[size]; \
    struct tty_driver name = {.ops = driver_ops, .major = _major, .ttys = name##_ttys, .limit = size}

/**
 * TTY driver operations structure
 * Defines the behavior for a class of TTY devices
 */
struct tty_driver_ops {
    /** Initialize a new TTY instance */
    int (*init)(struct tty *tty);
    
    /** Open a TTY device */
    int (*open)(struct tty *tty);
    
    /** Close a TTY device */
    int (*close)(struct tty *tty);
    
    /** Write data to a TTY device */
    int (*write)(struct tty *tty, const void *buf, size_t len, bool blocking);
    
    /** Handle TTY-specific ioctl commands */
    int (*ioctl)(struct tty *tty, int cmd, void *arg);
    
    /** Clean up resources when a TTY is deallocated */
    void (*cleanup)(struct tty *tty);
};

/** Array of TTY drivers indexed by major device number */
extern struct tty_driver *tty_drivers[256];

/** Driver for real terminal access */
extern struct tty_driver real_tty_driver;

/**
 * TTY instance structure
 * Represents a specific terminal device
 */
struct tty {
    /** Reference count */
    unsigned refcount;
    
    /** Driver for this TTY */
    struct tty_driver *driver;
    
    /** Whether the TTY has been hung up */
    bool hung_up;
    
    /** Whether the TTY has ever been opened */
    bool ever_opened;

    /** Size of TTY input buffer */
#define TTY_BUF_SIZE 4096
    
    /** Input buffer */
    char buf[TTY_BUF_SIZE];
    
    /**
     * Input flags buffer
     * A flag is a marker indicating the end of a canonical mode input. Flags
     * are created by EOL and EOF characters. You can't backspace past a flag.
     */
    bool buf_flag[TTY_BUF_SIZE];
    
    /** Current amount of data in buffer */
    size_t bufsize;
    
    /** Packet mode flags (for PTYs) */
    uint8_t packet_flags;
    
    /** Condition variable for producers (writers to the TTY) */
    cond_t produced;
    
    /** Condition variable for consumers (readers from the TTY) */
    cond_t consumed;

    /** Window size */
    struct winsize_ winsize;
    
    /** Terminal I/O settings */
    struct termios_ termios;
    
    /** Device type */
    int type;
    
    /** Device number */
    int num;

    /** Session ID that owns this TTY */
    pid_t_ session;
    
    /** Foreground process group */
    pid_t_ fg_group;

    /** List of file descriptors open to this TTY */
    struct list fds;
    
    /** Lock for fd list (maintains lock order) */
    lock_t fds_lock;

    /** 
     * Main TTY lock 
     * This never nests with itself, except in pty_is_half_closed_master
     */
    lock_t lock;

    /** Driver-specific data */
    union {
        /** Thread handle for real TTY driver */
        pthread_t thread;
        
        /** Pseudo-terminal specific data */
        struct {
            /** Pointer to other side of the PTY (master/slave) */
            struct tty *other;
            
            /** Permissions for slave PTY device */
            mode_t_ perms;
            
            /** Owner user ID */
            uid_t_ uid;
            
            /** Owner group ID */
            uid_t_ gid;
            
            /** Whether PTY is locked */
            bool locked;
            
            /** Whether packet mode is enabled */
            bool packet_mode;
        } pty;
        
        /** Generic data pointer for other drivers */
        void *data;
    };
};

/**
 * Write input data to a TTY
 *
 * @param tty TTY to write to
 * @param input Input data
 * @param len Length of input data
 * @param blocking Whether to block if buffer is full
 * @return Number of bytes written or negative error code
 *         May return _EINTR if blocking and interrupted
 *         May return _EAGAIN if non-blocking and buffer is full
 */
ssize_t tty_input(struct tty *tty, const char *input, size_t len, bool blocking);

/**
 * Update the window size of a TTY
 *
 * @param tty TTY to update
 * @param winsize New window size
 */
void tty_set_winsize(struct tty *tty, struct winsize_ winsize);

/**
 * Hang up a TTY, causing SIGHUP to be sent to its process group
 *
 * @param tty TTY to hang up
 */
void tty_hangup(struct tty *tty);

/**
 * Get an existing TTY instance by driver, type, and number
 *
 * @param driver TTY driver
 * @param type Device type
 * @param num Device number
 * @return TTY instance or NULL if not found
 */
struct tty *tty_get(struct tty_driver *driver, int type, int num);

/**
 * Allocate a new TTY instance
 *
 * @param driver TTY driver
 * @param type Device type
 * @param num Device number
 * @return New TTY instance or NULL on error
 */
struct tty *tty_alloc(struct tty_driver *driver, int type, int num);

/**
 * Open a TTY device
 *
 * @param tty TTY to open
 * @param fd File descriptor to associate with TTY
 * @return 0 on success or negative error code
 */
int tty_open(struct tty *tty, struct fd *fd);

/** Global lock for TTY allocation and management */
extern lock_t ttys_lock;

/**
 * Release a reference to a TTY
 * Must be called with ttys_lock held
 *
 * @param tty TTY to release
 */
void tty_release(struct tty *tty);

/** Device operations for TTY devices */
extern struct dev_ops tty_dev;

/** Device operations for PTMX (PTY master multiplexer) device */
extern struct dev_ops ptmx_dev;

/**
 * Open a new PTY master device
 *
 * @param fd File descriptor to associate with the PTY master
 * @return 0 on success or negative error code
 */
int ptmx_open(struct fd *fd);

/**
 * Open a fake PTY (for unit testing or special purposes)
 * Should call with a driver declared without DEFINE_TTY_DRIVER,
 * as it overwrites the ttys field.
 *
 * @param driver TTY driver to use
 * @return New TTY instance
 */
struct tty *pty_open_fake(struct tty_driver *driver);

#endif /* TTY_H */
