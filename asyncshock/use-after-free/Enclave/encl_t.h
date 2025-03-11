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

void ecall_test(void);
void ecall_test_malloc_free(void);
void* ecall_get_ecall(void);
void* ecall_get_free(void);
void* ecall_get_succes_adrs(void);
void ecall_setup(void);
void ecall_print_and_save_arg_once(uint64_t str);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_print_address(const char* str, uint64_t a);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
