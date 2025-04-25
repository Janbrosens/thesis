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

#ifndef _my_struct
#define _my_struct
typedef struct my_struct {
	int* sump;
	int* prodp;
} my_struct;
#endif

void ecall_update_response_loc(struct my_struct* input_pointer);
void ecall_compute_response(int i, int j);
void ecall_get_response(void);
void ecall_get_secret(int pin, char* out_buf, size_t max_len);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_print_address(const char* str, uint64_t a);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
