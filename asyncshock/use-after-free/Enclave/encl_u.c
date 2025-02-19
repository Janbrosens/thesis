#include "encl_u.h"
#include <errno.h>

typedef struct ms_ecall_print_and_save_arg_once_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_print_and_save_arg_once_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL encl_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_encl = {
	1,
	{
		(void*)encl_ocall_print,
	}
};
sgx_status_t ecall_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_setup(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_print_and_save_arg_once(sgx_enclave_id_t eid, char* str)
{
	sgx_status_t status;
	ms_ecall_print_and_save_arg_once_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 2, &ocall_table_encl, &ms);
	return status;
}

