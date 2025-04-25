#ifndef ENCL_T_H__
#define ENCL_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_setup(void);
void ecall_add_password(const char* masterpw, const char* plaintext_pw);
void ecall_change_master_password(const char* old_masterpw, const char* new_masterpw);
void ecall_get_passwords(const char* masterpw);
void ecall_init_master_password(const char* masterpw);
void ecall_clear_all(const char* masterpw);

sgx_status_t SGX_CDECL ocall_print(const char* pw);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
