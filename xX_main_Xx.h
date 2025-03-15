/**
 * iSH Core Initialization
 *
 * This header defines the core initialization routines for the iSH application.
 * It handles command-line argument parsing, filesystem setup, process creation,
 * and terminal configuration.
 */

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include "kernel/init.h"
#include "kernel/fs.h"
#include "fs/devices.h"
#include "fs/real.h"
#ifdef __APPLE__
#include <sys/resource.h>
// MacOS-specific definitions for case-sensitive filesystem support
#define IOPOL_TYPE_VFS_HFS_CASE_SENSITIVITY 1
#define IOPOL_VFS_HFS_CASE_SENSITIVITY_FORCE_CASE_SENSITIVE 1
#endif

/**
 * Reset the terminal to its original state
 * Called when exiting the application
 */
void real_tty_reset_term(void);

/**
 * Exit handler for the main process
 * 
 * Resets the terminal and propagates the exit code properly
 *
 * @param task The task that is exiting
 * @param code The exit code to use
 */
static void exit_handler(struct task *task, int code) {
    // Only handle exit for the main process
    if (task->parent != NULL)
        return;
    
    // Reset terminal to original state
    real_tty_reset_term();
    
    // If the lower 8 bits contain a signal, raise that signal
    if (code & 0xff)
        raise(code & 0xff);
    
    // Otherwise, exit with the upper 8 bits as the exit code
    exit(code >> 8);
}

/**
 * Main initialization function for iSH
 * 
 * This function parses command line arguments and initializes global
 * data structures. The unusual name was suggested by the programming
 * discussions discord server: https://discord.gg/9zT7NHP
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line argument strings
 * @param envp Environment variables string
 * @return 0 on success, negative error code on failure
 */
static inline int xX_main_Xx(int argc, char *const argv[], const char *envp) {
#ifdef __APPLE__
    // Enable case-sensitive filesystem mode on macOS, if possible.
    // This needs either root permissions or the 
    // com.apple.private.iopol.case_sensitivity entitlement.
    // Since the latter isn't possible in most cases, we use setuid root
    // and then drop privileges immediately after.
    // https://worthdoingbadly.com/casesensitive-iossim/
    int iopol_err = setiopolicy_np(IOPOL_TYPE_VFS_HFS_CASE_SENSITIVITY,
            IOPOL_SCOPE_PROCESS,
            IOPOL_VFS_HFS_CASE_SENSITIVITY_FORCE_CASE_SENSITIVE);
    if (iopol_err != 0 && errno != EPERM)
        perror("could not enable case sensitivity");
    
    // Drop privileges as soon as possible after setting case sensitivity
    setgid(getgid());
    setuid(getuid());
#endif

    // Parse command line options
    int opt;
    const char *root = NULL;     // Root filesystem path
    const char *workdir = NULL;  // Working directory
    const struct fs_ops *fs = &realfs;  // Filesystem operations (default: real filesystem)
    const char *console = "/dev/tty1";  // Console device
    
    while ((opt = getopt(argc, argv, "+r:f:d:c:")) != -1) {
        switch (opt) {
            case 'r': // Specify root directory in real filesystem
            case 'f': // Specify root directory in fake filesystem
                root = optarg;
                if (opt == 'f')
                    fs = &fakefs;
                break;
            case 'd': // Specify working directory
                workdir = optarg;
                break;
            case 'c': // Specify console device
                console = optarg;
                break;
        }
    }

    // Initialize system logging
    openlog(argv[0], 0, LOG_USER);

    // Resolve and prepare the root path
    char root_realpath[MAX_PATH + 1] = "/";
    if (root != NULL && realpath(root, root_realpath) == NULL) {
        perror(root);
        exit(1);
    }
    if (fs == &fakefs)
        strcat(root_realpath, "/data");
    
    // Mount the root filesystem
    int err = mount_root(fs, root_realpath);
    if (err < 0)
        return err;

    // Initialize the first process
    become_first_process();
    current->thread = pthread_self();
    
    // Determine the working directory
    char cwd[MAX_PATH + 1];
    if (root == NULL && workdir == NULL) {
        getcwd(cwd, sizeof(cwd));
        workdir = cwd;
    }
    
    // Change to the working directory
    if (workdir != NULL) {
        struct fd *pwd = generic_open(workdir, O_RDONLY_, 0);
        if (IS_ERR(pwd)) {
            fprintf(stderr, "error opening working dir: %ld\n", PTR_ERR(pwd));
            return 1;
        }
        fs_chdir(current->fs, pwd);
    }

    // Prepare command line arguments for the first process
    char argv_copy[4096];
    int i = optind;
    size_t p = 0;
    while (i < argc) {
        strcpy(&argv_copy[p], argv[i]);
        p += strlen(argv[i]) + 1;
        i++;
    }
    argv_copy[p] = '\0';
    
    // Check if there's a program to execute
    if (argv[optind] == NULL)
        return _ENOENT;
    
    // Execute the program
    err = do_execve(argv[optind], argc - optind, argv_copy, envp == NULL ? "\0" : envp);
    if (err < 0)
        return err;
    
    // Setup terminal driver
    tty_drivers[TTY_CONSOLE_MAJOR] = &real_tty_driver;
    
    // Configure stdio based on whether we're in a terminal
    if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
        // Create terminal-based stdio
        err = create_stdio(console, TTY_CONSOLE_MAJOR, 1);
        if (err < 0)
            return err;
    } else {
        // Create pipe-based stdio
        err = create_piped_stdio();
        if (err < 0)
            return err;
    }
    
    // Register exit handler
    exit_hook = exit_handler;
    return 0;
}
