/**
 * iSH - Task Management System
 *
 * This header defines the task (process/thread) management system for the Linux emulation layer.
 * It implements the process and thread model, including process groups, sessions, and signals.
 */

#ifndef TASK_H
#define TASK_H

#include <pthread.h>
#include "emu/cpu.h"
#include "kernel/mm.h"
#include "kernel/fs.h"
#include "kernel/signal.h"
#include "kernel/resource.h"
#include "fs/sockrestart.h"
#include "util/list.h"
#include "util/timer.h"
#include "util/sync.h"

/**
 * Task structure - represents a process or thread in the emulated system
 *
 * In Linux terminology, a "task" can refer to either a process or a thread.
 * Each task has its own virtual CPU state and resources, but can share memory
 * and file descriptors with other tasks in the same thread group.
 *
 * Note: Fields marked as immutable should not be changed after initialization.
 * Fields with locking requirements specify which lock must be held to access them.
 */
// everything here is private to the thread executing this task and needs no
// locking, unless otherwise specified
struct task {
    /** CPU state for this task */
    struct cpu_state cpu;
    
    /** Memory management context (locked by general_lock) */
    struct mm *mm; 
    
    /** Pointer to mm.mem for convenience */
    struct mem *mem; 
    
    /** Host thread executing this task */
    pthread_t thread;
    
    /** Host thread ID */
    uint64_t threadid;

    /** Thread group this task belongs to (immutable) */
    struct tgroup *group; 
    
    /** Linked list entry in thread group */
    struct list group_links;
    
    /** Process ID and thread group ID (immutable) */
    pid_t_ pid, tgid; 
    
    /** Real user and group IDs */
    uid_t_ uid, gid;
    
    /** Effective user and group IDs (used for permission checking) */
    uid_t_ euid, egid;
    
    /** Saved user and group IDs (for seteuid) */
    uid_t_ suid, sgid;
    
    /** Maximum number of supplementary groups */
#define MAX_GROUPS 32
    
    /** Number of supplementary groups */
    unsigned ngroups;
    
    /** List of supplementary groups */
    uid_t_ groups[MAX_GROUPS];
    
    /** Process name (locked by general_lock) */
    char comm[16] __strncpy_safe; 
    
    /** Flag for setsid() edge case handling */
    bool did_exec; 

    /** File descriptor table */
    struct fdtable *files;
    
    /** Filesystem information (root, cwd, umask) */
    struct fs_info *fs;

    /** Signal handlers (locked by sighand->lock) */
    struct sighand *sighand;
    
    /** Blocked signals */
    sigset_t_ blocked;
    
    /** Pending signals for this task */
    sigset_t_ pending;
    
    /** Signals being waited for by sigtimedwait */
    sigset_t_ waiting; 
    
    /** Signal queue */
    struct list queue;
    
    /** Condition for pause() system call */
    cond_t pause; 
    
    /** Saved signal mask (private) */
    sigset_t_ saved_mask;
    
    /** Flag indicating if saved_mask is valid */
    bool has_saved_mask;

    /** Process tracing (ptrace) state */
    struct {
        /** Lock for ptrace operations */
        lock_t lock;
        
        /** Condition variable for ptrace events */
        cond_t cond;

        /** Whether this task is being traced */
        bool traced;
        
        /** Whether task is stopped by ptrace */
        bool stopped;
        
        /** Signal to be delivered when continuing */
        int signal;
        
        /** Signal information */
        struct siginfo_ info;
        
        /** Ptrace event type */
        int trap_event;
    } ptrace;

    /** Parent task (locked by pids_lock) */
    struct task *parent;
    
    /** List of child tasks (locked by pids_lock) */
    struct list children;
    
    /** Link in parent's children list (locked by pids_lock) */
    struct list siblings;

    /** futex address to clear on task exit (for CLONE_CHILD_CLEARTID) */
    addr_t clear_tid;
    
    /** Pointer to list of robust futexes */
    addr_t robust_list;

    /** Exit code (locked by pids_lock) */
    dword_t exit_code;
    
    /** Whether task is a zombie (locked by pids_lock) */
    bool zombie;
    
    /** Whether task is in the process of exiting (locked by pids_lock) */
    bool exiting;

    /** vfork() coordination structure (allocated on parent's stack) */
    struct vfork_info {
        /** Whether child has exec'd or exited */
        bool done;
        
        /** Condition variable for parent to wait on */
        cond_t cond;
        
        /** Lock for condition variable */
        lock_t lock;
    } *vfork;
    
    /** Signal to send to parent on exit (from clone flags) */
    int exit_signal;

    /** 
     * General lock for fields not covered by other locks
     * Specifically protects: comm, mm
     */
    lock_t general_lock;

    /** Socket restart information for interrupted socket calls */
    struct task_sockrestart sockrestart;

    /** 
     * Current condition/lock for blocking syscalls
     * Used to wake up task when signal arrives
     */
    cond_t *waiting_cond;
    lock_t *waiting_lock;
    lock_t waiting_cond_lock;
};

/**
 * Thread-local variable containing the currently executing task
 * Always gives the process that is currently executing
 */
extern __thread struct task *current;

/**
 * Set memory management context for a task
 *
 * @param task Task to update
 * @param mm New memory management context
 */
static inline void task_set_mm(struct task *task, struct mm *mm) {
    task->mm = mm;
    task->mem = &task->mm->mem;
    task->cpu.mmu = &task->mem->mmu;
}

/**
 * Create a new task
 *
 * Creates a new process, initializes most fields from the parent. Specify
 * parent as NULL to create the init process.
 *
 * @param parent Parent task or NULL for init
 * @return New task or NULL if out of memory
 */
struct task *task_create_(struct task *parent);

/**
 * Destroy a task
 *
 * Removes the task from the process table and frees resources.
 * Must be called with pids_lock held.
 *
 * @param task Task to destroy
 */
void task_destroy(struct task *task);

/**
 * Notify parent that vfork child has exec'd or exited
 *
 * @param task Task that called vfork (child)
 */
void vfork_notify(struct task *task);

/**
 * Create a new session and set the process group
 *
 * Implements the setsid() system call.
 *
 * @param task Task to set as session leader
 * @return New session ID or negative error code
 */
pid_t_ task_setsid(struct task *task);

/**
 * Remove a task from its session
 *
 * @param task Task to remove from session
 */
void task_leave_session(struct task *task);

/**
 * POSIX timer structure
 * Represents a timer created with timer_create()
 */
struct posix_timer {
    /** Underlying timer object */
    struct timer *timer;
    
    /** Timer ID returned to userspace */
    int_t timer_id;
    
    /** Thread group this timer belongs to */
    struct tgroup *tgroup;
    
    /** Thread to deliver signal to, or 0 for any */
    pid_t_ thread_pid;
    
    /** Signal to deliver on timer expiration */
    int_t signal;
    
    /** Signal value/payload */
    union sigval_ sig_value;
};

/**
 * Thread group structure
 *
 * In Linux, a thread group is a collection of tasks that share resources
 * and represent a single process from the user's perspective.
 */
struct tgroup {
    /** List of tasks in this group (locked by pids_lock) */
    struct list threads;
    
    /** Leader task (main thread, immutable) */
    struct task *leader;
    
    /** Resource usage statistics */
    struct rusage_ rusage;

    /** Session ID and process group ID (locked by pids_lock) */
    pid_t_ sid, pgid;
    
    /** List entry in session */
    struct list session;
    
    /** List entry in process group */
    struct list pgroup;

    /** Whether the thread group is stopped by SIGSTOP, etc. */
    bool stopped;
    
    /** Condition variable signaled when thread group continues */
    cond_t stopped_cond;

    /** Controlling terminal */
    struct tty *tty;
    
    /** Interval timer (setitimer) */
    struct timer *itimer;
    
    /** Maximum number of POSIX timers */
#define TIMERS_MAX 16
    
    /** Array of POSIX timers */
    struct posix_timer posix_timers[TIMERS_MAX];

    /** Resource limits (rlimit) */
    struct rlimit_ limits[RLIMIT_NLIMITS_];

    /**
     * Group exit information
     *
     * From https://twitter.com/tblodt/status/957706819236904960
     * > there are two distinct ways for a p̶r̶o̶c̶e̶s̶s̶ thread group to exit:
     * > 
     * > - each thread calls exit
     * > wait will return the exit code for the group leader
     * > 
     * > - any thread calls exit_group
     * > the SIGNAL_GROUP_EXIT flag will be set and wait will return the status passed to exit_group
     */
    bool doing_group_exit;
    dword_t group_exit_code;

    /** Resource usage of terminated child processes */
    struct rusage_ children_rusage;
    
    /** Condition variable for wait() family of calls */
    cond_t child_exit;

    /** Process personality (for compatibility modes) */
    dword_t personality;

    /** Lock for thread group fields not protected by other locks */
    lock_t lock;
};

/**
 * Check if a task is the leader of its thread group
 *
 * @param task Task to check
 * @return true if task is the thread group leader
 */
static inline bool task_is_leader(struct task *task) {
    return task->group->leader == task;
}

/**
 * Process ID structure
 * Associates a numeric ID with a task and manages session/pgroup membership
 */
struct pid {
    /** Process ID number */
    dword_t id;
    
    /** Task this ID represents */
    struct task *task;
    
    /** List entry in session */
    struct list session;
    
    /** List entry in process group */
    struct list pgroup;
};

/** Lock for process ID and task lifecycle operations */
extern lock_t pids_lock;

/**
 * Look up a pid by ID number
 * Must be called with pids_lock held
 *
 * @param pid Process ID to find
 * @return pid structure or NULL if not found
 */
struct pid *pid_get(dword_t pid);

/**
 * Look up a task by PID
 * Must be called with pids_lock held
 *
 * @param pid Process ID to find
 * @return task or NULL if not found
 */
struct task *pid_get_task(dword_t pid);

/**
 * Look up a task by PID, including zombie tasks
 * Must be called with pids_lock held
 *
 * @param id Process ID to find
 * @return task (including zombies) or NULL if not found
 */
struct task *pid_get_task_zombie(dword_t id);

/** Maximum PID value */
#define MAX_PID (1 << 15) // oughta be enough

/**
 * Start execution of a task
 * Creates host thread and begins execution
 *
 * @param task Task to start
 */
void task_start(struct task *task);

/**
 * Run the current task
 * Main entry point for task execution
 */
void task_run_current(void);

/**
 * Hook function called when a task exits
 * Used for cleanup and notification
 */
extern void (*exit_hook)(struct task *task, int code);

/**
 * Check if current task has superuser privileges
 *
 * @return true if current task has effective UID of 0
 */
#define superuser() (current != NULL && current->euid == 0)

/**
 * Update the host thread name to match the current task
 *
 * Sets name in the format "comm-pid".
 * Will ensure that the -pid part always fits, then will fit as much of comm as possible.
 */
void update_thread_name(void);

#endif
