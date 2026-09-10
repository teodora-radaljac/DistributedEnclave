#ifndef PPDPC_NPB_MPI_WAIT_H
#define PPDPC_NPB_MPI_WAIT_H

#include <mpi.h>
#include "npb_timeout.h"

static inline int npb_mpi_init(int *argc, char ***argv)
{
    npb_wait_begin(NPB_WAIT_ENROLLMENT);
    int result = MPI_Init(argc, argv);
    npb_wait_end();
    return result;
}

static inline int npb_mpi_disconnect(MPI_Comm *communicator)
{
    npb_wait_begin(NPB_WAIT_SHUTDOWN);
    int result = MPI_Comm_disconnect(communicator);
    npb_wait_end();
    return result;
}

static inline int npb_mpi_finalize(void)
{
    npb_wait_begin(NPB_WAIT_SHUTDOWN);
    int result = MPI_Finalize();
    npb_wait_end();
    return result;
}

#endif