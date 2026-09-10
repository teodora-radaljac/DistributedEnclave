#include "dgemm_kernel.h"

#include <stddef.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline, aligned(64)))
#endif
void ppdpc_dgemm(const double *a, const double *b, double *c,
                 int rows, int inner_dimension, int columns)
{
    memset(c, 0, (size_t)rows * (size_t)columns * sizeof(double));
    for (int row = 0; row < rows; row++)
        for (int inner = 0; inner < inner_dimension; inner++) {
            double value = a[(size_t)row * (size_t)inner_dimension + inner];
            for (int column = 0; column < columns; column++)
                c[(size_t)row * (size_t)columns + column] +=
                    value * b[(size_t)inner * (size_t)columns + column];
        }
}
