#ifndef PPDPC_DGEMM_KERNEL_H
#define PPDPC_DGEMM_KERNEL_H

void ppdpc_dgemm(const double *a, const double *b, double *c,
                 int rows, int inner_dimension, int columns);

#endif
