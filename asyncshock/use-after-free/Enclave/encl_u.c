#include "encl_u.h"
#include <errno.h>

typedef struct ms_ecall_get_ecall_t {
	void* ms_retval;
} ms_ecall_get_ecall_t;

typedef struct ms_ecall_get_free_t {
	void* ms_retval;
} ms_ecall_get_free_t;

typedef struct ms_ecall_get_succes_adrs_t {
	void* ms_retval;
} ms_ecall_get_succes_adrs_t;

typedef struct ms_ecall_print_and_save_arg_once_t {
	uint64_t ms_str;
} ms_ecall_print_and_save_arg_once_t;

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
sgx_status_t ecall_test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_test_malloc_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_get_ecall(sgx_enclave_id_t eid, void** retval)
{
	sgx_status_t status;
	ms_ecall_get_ecall_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_encl, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_free(sgx_enclave_id_t eid, void** retval)
{
	sgx_status_t status;
	ms_ecall_get_free_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_encl, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_succes_adrs(sgx_enclave_id_t eid, void** retval)
{
	sgx_status_t status;
	ms_ecall_get_succes_adrs_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_encl, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_setup(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_print_and_save_arg_once(sgx_enclave_id_t eid, uint64_t str)
{
	sgx_status_t status;
	ms_ecall_print_and_save_arg_once_t ms;
	ms.ms_str = str;
	status = sgx_ecall(eid, 6, &ocall_table_encl, &ms);
	return status;
}

