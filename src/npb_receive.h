#ifndef PPDPC_NPB_RECEIVE_H
#define PPDPC_NPB_RECEIVE_H

#include <stddef.h>
#include <mpi.h>

static inline int npb_recv_exact(void *buffer, int count, MPI_Datatype datatype,
                                 int source, int tag, MPI_Comm communicator,
                                 MPI_Status *status)
{
    MPI_Status local_status;
    MPI_Status *actual_status = status == MPI_STATUS_IGNORE || status == NULL
        ? &local_status : status;
    int received_count = 0;
    int result;

    if (count < 0) return MPI_ERR_COUNT;
    result = MPI_Recv(buffer, count, datatype, source, tag, communicator,
                      actual_status);
    if (result != MPI_SUCCESS) return result;
    result = MPI_Get_count(actual_status, datatype, &received_count);
    if (result != MPI_SUCCESS) return result;
    return received_count == count ? MPI_SUCCESS : MPI_ERR_TRUNCATE;
}

#endif