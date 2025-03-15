/**
 * iSH - Linux shell environment for iOS
 * 
 * This is the main entry point for the iSH application.
 * It initializes the environment, mounts virtual filesystems,
 * and starts the main task execution.
 */

#include <stdlib.h>
#include <string.h>
#include "kernel/calls.h"
#include "kernel/task.h"
#include "xX_main_Xx.h"

/**
 * Main entry point for the iSH application
 * 
 * @param argc Number of command line arguments
 * @param argv Array of command line argument strings
 * @return Error code (negative values indicate errors)
 */
int main(int argc, char *const argv[]) {
    // Prepare environment variables array
    char envp[100] = {0};
    
    // Copy TERM environment variable if it exists
    if (getenv("TERM"))
        strcpy(envp, getenv("TERM") - strlen("TERM") - 1);
    
    // Initialize the core system using the helper function in xX_main_Xx.h
    int err = xX_main_Xx(argc, argv, envp);
    if (err < 0) {
        fprintf(stderr, "xX_main_Xx: %s\n", strerror(-err));
        return err;
    }
    
    // Mount procfs (process information filesystem) at /proc
    do_mount(&procfs, "proc", "/proc", "", 0);
    
    // Mount devptsfs (pseudo-terminal device filesystem) at /dev/pts
    do_mount(&devptsfs, "devpts", "/dev/pts", "", 0);
    
    // Start executing the current task
    task_run_current();
}
