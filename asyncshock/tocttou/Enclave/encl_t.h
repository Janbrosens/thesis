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

void ecall_writer_thread(void);
void ecall_checker_thread(void);
void* ecall_get_memcpy(void);
void* ecall_get_strncmp(void);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_print_address(const char* str, uint64_t a);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
