#include "encl_u.h"
#include <errno.h>

typedef struct ms_ecall_get_memcpy_t {
	void* ms_retval;
} ms_ecall_get_memcpy_t;

typedef struct ms_ecall_get_strncmp_t {
	void* ms_retval;
} ms_ecall_get_strncmp_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_address_t {
	const char* ms_str;
	uint64_t ms_a;
} ms_ocall_print_address_t;

static sgx_status_t SGX_CDECL encl_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL encl_ocall_print_address(void* pms)
{
	ms_ocall_print_address_t* ms = SGX_CAST(ms_ocall_print_address_t*, pms);
	ocall_print_address(ms->ms_str, ms->ms_a);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_encl = {
	2,
	{
		(void*)encl_ocall_print,
		(void*)encl_ocall_print_address,
	}
};
sgx_status_t ecall_writer_thread(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_checker_thread(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_get_memcpy(sgx_enclave_id_t eid, void** retval)
{
	sgx_status_t status;
	ms_ecall_get_memcpy_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_encl, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_strncmp(sgx_enclave_id_t eid, void** retval)
{
	sgx_status_t status;
	ms_ecall_get_strncmp_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_encl, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

