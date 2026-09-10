#define _POSIX_C_SOURCE 200809L

#include "bench_rendezvous.h"
#include "npb_timeout.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int get_service_name(const char **service)
{
    *service = getenv("PPDPC_SERVICE_NAME");
    if (*service == NULL) *service = BENCH_DEFAULT_SERVICE;
    if (**service == '\0' || strlen(*service) >= MPI_MAX_PORT_NAME) {
        fprintf(stderr, "[DISCOVERY] invalid PPDPC_SERVICE_NAME\n");
        return MPI_ERR_ARG;
    }
    return MPI_SUCCESS;
}

static int keep_first_error(int result, int cleanup_result)
{
    return result == MPI_SUCCESS ? cleanup_result : result;
}

static int restore_self_handler(MPI_Errhandler *previous, int result)
{
    if (*previous != MPI_ERRHANDLER_NULL) {
        result = keep_first_error(result,
            MPI_Comm_set_errhandler(MPI_COMM_SELF, *previous));
        result = keep_first_error(result, MPI_Errhandler_free(previous));
    }
    return result;
}

int bench_accept_worker(MPI_Comm *intercommunicator)
{
    char port[MPI_MAX_PORT_NAME] = {0};
    const char *service;
    int opened = 0;
    int published = 0;
    MPI_Errhandler previous = MPI_ERRHANDLER_NULL;
    int result;

    if (intercommunicator == NULL) return MPI_ERR_ARG;
    *intercommunicator = MPI_COMM_NULL;
    result = get_service_name(&service);
    if (result != MPI_SUCCESS) return result;
    npb_wait_begin(NPB_WAIT_ENROLLMENT);
    result = MPI_Comm_get_errhandler(MPI_COMM_SELF, &previous);
    if (result != MPI_SUCCESS) goto cleanup;
    result = MPI_Comm_set_errhandler(MPI_COMM_SELF, MPI_ERRORS_RETURN);
    if (result != MPI_SUCCESS) goto cleanup;
    result = MPI_Open_port(MPI_INFO_NULL, port);
    if (result != MPI_SUCCESS) goto cleanup;
    opened = 1;
    result = MPI_Publish_name(service, MPI_INFO_NULL, port);
    if (result != MPI_SUCCESS) goto cleanup;
    published = 1;
    printf("[DISCOVERY] published service '%s'\n", service);
    result = MPI_Comm_accept(port, MPI_INFO_NULL, 0, MPI_COMM_SELF, intercommunicator);
    if (result == MPI_SUCCESS)
        result = MPI_Comm_set_errhandler(*intercommunicator, MPI_ERRORS_RETURN);
    if (result == MPI_SUCCESS) result = MPI_Barrier(*intercommunicator);

cleanup:
    if (published)
        result = keep_first_error(result, MPI_Unpublish_name(service, MPI_INFO_NULL, port));
    if (opened) result = keep_first_error(result, MPI_Close_port(port));
    result = restore_self_handler(&previous, result);
    npb_wait_end();
    return result;
}

int bench_connect_worker(MPI_Comm *intercommunicator)
{
    char port[MPI_MAX_PORT_NAME] = {0};
    const char *service;
    MPI_Errhandler previous = MPI_ERRHANDLER_NULL;
    int result;

    if (intercommunicator == NULL) return MPI_ERR_ARG;
    *intercommunicator = MPI_COMM_NULL;
    result = get_service_name(&service);
    if (result != MPI_SUCCESS) return result;
    npb_wait_begin(NPB_WAIT_ENROLLMENT);
    result = MPI_Comm_get_errhandler(MPI_COMM_SELF, &previous);
    if (result != MPI_SUCCESS) goto cleanup;
    result = MPI_Comm_set_errhandler(MPI_COMM_SELF, MPI_ERRORS_RETURN);
    if (result != MPI_SUCCESS) goto cleanup;
    for (;;) {
        int error_class = MPI_SUCCESS;
        memset(port, 0, sizeof port);
        result = MPI_Lookup_name(service, MPI_INFO_NULL, port);
        if (result == MPI_SUCCESS) {
            if (port[0] == '\0' || memchr(port, '\0', sizeof port) == NULL)
                result = MPI_ERR_PORT;
            break;
        }
        int class_result = MPI_Error_class(result, &error_class);
        if (class_result != MPI_SUCCESS) {
            result = class_result;
            break;
        }
        if (error_class != MPI_ERR_NAME && error_class != MPI_ERR_SERVICE) break;
        sleep(1);
    }
    if (result != MPI_SUCCESS) goto cleanup;
    printf("[DISCOVERY] resolved service '%s'\n", service);
    result = MPI_Comm_connect(port, MPI_INFO_NULL, 0, MPI_COMM_SELF, intercommunicator);
    if (result == MPI_SUCCESS)
        result = MPI_Comm_set_errhandler(*intercommunicator, MPI_ERRORS_RETURN);
    if (result == MPI_SUCCESS) result = MPI_Barrier(*intercommunicator);

cleanup:
    result = restore_self_handler(&previous, result);
    npb_wait_end();
    return result;
}