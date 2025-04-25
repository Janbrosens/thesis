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

#ifndef _my_struct
#define _my_struct
typedef struct my_struct {
	int* sump;
	int* prodp;
} my_struct;
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_PRINT_ADDRESS_DEFINED__
#define OCALL_PRINT_ADDRESS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_address, (const char* str, uint64_t a));
#endif

sgx_status_t ecall_update_response_loc(sgx_enclave_id_t eid, struct my_struct* input_pointer);
sgx_status_t ecall_compute_response(sgx_enclave_id_t eid, int i, int j);
sgx_status_t ecall_get_response(sgx_enclave_id_t eid);
sgx_status_t ecall_get_secret(sgx_enclave_id_t eid, int pin, char* out_buf, size_t max_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
