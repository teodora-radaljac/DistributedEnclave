#ifndef PPDPC_BENCH_RENDEZVOUS_H
#define PPDPC_BENCH_RENDEZVOUS_H

#include <mpi.h>

#define BENCH_DEFAULT_SERVICE "ppdpc-enroll"

int bench_accept_worker(MPI_Comm *intercommunicator);
int bench_connect_worker(MPI_Comm *intercommunicator);

#endif