#include "encl_u.h"
#include <errno.h>

typedef struct ms_ecall_update_response_loc_t {
	struct my_struct* ms_input_pointer;
} ms_ecall_update_response_loc_t;

typedef struct ms_ecall_compute_response_t {
	int ms_i;
	int ms_j;
} ms_ecall_compute_response_t;

typedef struct ms_ecall_check_secret_t {
	int ms_s;
} ms_ecall_check_secret_t;

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
sgx_status_t ecall_update_response_loc(sgx_enclave_id_t eid, struct my_struct* input_pointer)
{
	sgx_status_t status;
	ms_ecall_update_response_loc_t ms;
	ms.ms_input_pointer = input_pointer;
	status = sgx_ecall(eid, 0, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_compute_response(sgx_enclave_id_t eid, int i, int j)
{
	sgx_status_t status;
	ms_ecall_compute_response_t ms;
	ms.ms_i = i;
	ms.ms_j = j;
	status = sgx_ecall(eid, 1, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_get_response(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_check_secret(sgx_enclave_id_t eid, int s)
{
	sgx_status_t status;
	ms_ecall_check_secret_t ms;
	ms.ms_s = s;
	status = sgx_ecall(eid, 3, &ocall_table_encl, &ms);
	return status;
}

