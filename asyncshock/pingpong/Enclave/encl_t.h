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

void ecall_ping(void);
void ecall_pong(void);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(void);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(void);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(void);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
