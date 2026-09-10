#define _POSIX_C_SOURCE 200809L

#include "npb_timeout.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <unistd.h>

static unsigned int wait_limits[3];
static unsigned int wait_depth;
static int configured;
static volatile sig_atomic_t deadline_active;

static void configuration_error(const char *message)
{
    fprintf(stderr, "[NPB] wait deadline configuration error: %s\n", message);
    _exit(2);
}

static unsigned int timeout_setting(const char *name, unsigned int fallback)
{
    const char *text = getenv(name);
    unsigned int seconds = 0;

    if (text == NULL) return fallback;
    if (*text == '\0') configuration_error(name);
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9' || seconds > 8640U)
            configuration_error(name);
        seconds = seconds * 10U + (unsigned int)(*text - '0');
        if (seconds > 86400U) configuration_error(name);
    }
    if (seconds == 0) configuration_error(name);
    return seconds;
}

static void timeout_handler(int signal_number)
{
    (void)signal_number;
    if (deadline_active) _exit(NPB_TIMEOUT_EXIT_CODE);
}

static void block_alarm(sigset_t *previous_mask)
{
    sigset_t alarm_mask;
    if (sigemptyset(&alarm_mask) != 0
        || sigaddset(&alarm_mask, SIGALRM) != 0
        || sigprocmask(SIG_BLOCK, &alarm_mask, previous_mask) != 0)
        configuration_error("cannot block SIGALRM");
}

static void restore_mask(const sigset_t *previous_mask)
{
    if (sigprocmask(SIG_SETMASK, previous_mask, NULL) != 0)
        configuration_error("cannot restore signal mask");
}

void npb_wait_begin(enum npb_wait_kind kind)
{
    struct sigaction previous_action;
    struct sigaction action;
    struct itimerval previous_timer;
    sigset_t previous_mask;

    if (kind < NPB_WAIT_ENROLLMENT || kind > NPB_WAIT_SHUTDOWN)
        configuration_error("unknown wait phase");
    if (wait_depth != 0) {
        if (wait_depth == UINT_MAX) configuration_error("wait nesting overflow");
        ++wait_depth;
        return;
    }
    if (!configured) {
        wait_limits[NPB_WAIT_ENROLLMENT] =
            timeout_setting("PPDPC_ENROLL_TIMEOUT_SECONDS", 300U);
        wait_limits[NPB_WAIT_IO] =
            timeout_setting("PPDPC_IO_TIMEOUT_SECONDS", 600U);
        wait_limits[NPB_WAIT_SHUTDOWN] =
            timeout_setting("PPDPC_SHUTDOWN_TIMEOUT_SECONDS", 60U);
        configured = 1;
    }

    block_alarm(&previous_mask);
    if (sigismember(&previous_mask, SIGALRM) != 0)
        configuration_error("SIGALRM was already blocked");
    if (sigaction(SIGALRM, NULL, &previous_action) != 0
        || getitimer(ITIMER_REAL, &previous_timer) != 0)
        configuration_error("cannot inspect existing timer");
    if ((previous_action.sa_handler != SIG_DFL
         && previous_action.sa_handler != timeout_handler)
        || previous_timer.it_value.tv_sec != 0
        || previous_timer.it_value.tv_usec != 0
        || previous_timer.it_interval.tv_sec != 0
        || previous_timer.it_interval.tv_usec != 0)
        configuration_error("SIGALRM or ITIMER_REAL is already in use");

    memset(&action, 0, sizeof action);
    action.sa_handler = timeout_handler;
    if (sigemptyset(&action.sa_mask) != 0
        || sigaction(SIGALRM, &action, NULL) != 0)
        configuration_error("cannot install SIGALRM handler");
    deadline_active = 1;
    wait_depth = 1;
    alarm(wait_limits[kind]);
    restore_mask(&previous_mask);
}

void npb_wait_end(void)
{
    sigset_t previous_mask;

    if (wait_depth == 0) configuration_error("unbalanced wait scope");
    if (--wait_depth != 0) return;
    block_alarm(&previous_mask);
    deadline_active = 0;
    alarm(0);
    restore_mask(&previous_mask);
}

int npb_bind_child_to_parent(pid_t expected_parent)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) return -1;
    if (getppid() != expected_parent) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}