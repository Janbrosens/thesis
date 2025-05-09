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
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* pw));
#endif

sgx_status_t ecall_setup(sgx_enclave_id_t eid);
sgx_status_t ecall_add_password(sgx_enclave_id_t eid, const char* masterpw, const char* plaintext_pw);
sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, const char* old_masterpw, const char* new_masterpw);
sgx_status_t ecall_get_passwords2(sgx_enclave_id_t eid, const char* masterpw, void* output);
sgx_status_t ecall_init_master_password(sgx_enclave_id_t eid, const char* masterpw);
sgx_status_t ecall_clear_all(sgx_enclave_id_t eid, const char* masterpw);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
