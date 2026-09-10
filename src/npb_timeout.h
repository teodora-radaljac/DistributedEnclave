#ifndef PPDPC_NPB_TIMEOUT_H
#define PPDPC_NPB_TIMEOUT_H

#include <sys/types.h>

#define NPB_TIMEOUT_EXIT_CODE 124

enum npb_wait_kind {
    NPB_WAIT_ENROLLMENT,
    NPB_WAIT_IO,
    NPB_WAIT_SHUTDOWN
};

void npb_wait_begin(enum npb_wait_kind kind);
void npb_wait_end(void);
int npb_bind_child_to_parent(pid_t expected_parent);

#endif