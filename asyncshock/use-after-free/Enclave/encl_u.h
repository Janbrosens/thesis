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
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_address, (uint64_t a));
#endif
#ifndef OCALL_FREE_DEFINED__
#define OCALL_FREE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (uint64_t p));
#endif

sgx_status_t ecall_test(sgx_enclave_id_t eid);
sgx_status_t ecall_get_test_dummy_adrs(sgx_enclave_id_t eid, void** retval);
sgx_status_t ecall_setup(sgx_enclave_id_t eid);
sgx_status_t ecall_print_and_save_arg_once(sgx_enclave_id_t eid, char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
