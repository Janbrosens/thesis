#include "encl_u.h"
#include <errno.h>

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL encl_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL encl_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	sgx_thread_wait_untrusted_event_ocall();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL encl_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	sgx_thread_set_untrusted_event_ocall();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL encl_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	sgx_thread_setwait_untrusted_events_ocall();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL encl_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	sgx_thread_set_multiple_untrusted_events_ocall();
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_encl = {
	5,
	{
		(void*)encl_ocall_print,
		(void*)encl_sgx_thread_wait_untrusted_event_ocall,
		(void*)encl_sgx_thread_set_untrusted_event_ocall,
		(void*)encl_sgx_thread_setwait_untrusted_events_ocall,
		(void*)encl_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_ping(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_pong(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_encl, NULL);
	return status;
}

