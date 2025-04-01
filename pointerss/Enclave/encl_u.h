#ifndef ENCL_U_H__
#define ENCL_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_PRINT_ADDRESS_DEFINED__
#define OCALL_PRINT_ADDRESS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_address, (const char* str, uint64_t a));
#endif

sgx_status_t ecall_increase(sgx_enclave_id_t eid);
sgx_status_t ecall_lookup(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
