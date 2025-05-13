#include "encl_u.h"
#include <errno.h>

typedef struct ms_ecall_add_password_t {
	const char* ms_masterpw;
	size_t ms_masterpw_len;
	const char* ms_plaintext_pw;
	size_t ms_plaintext_pw_len;
} ms_ecall_add_password_t;

typedef struct ms_ecall_change_master_password_t {
	const char* ms_old_masterpw;
	size_t ms_old_masterpw_len;
	const char* ms_new_masterpw;
	size_t ms_new_masterpw_len;
} ms_ecall_change_master_password_t;

typedef struct ms_ecall_get_passwords2_t {
	const char* ms_masterpw;
	void* ms_output;
} ms_ecall_get_passwords2_t;

typedef struct ms_ecall_init_master_password_t {
	const char* ms_masterpw;
	size_t ms_masterpw_len;
} ms_ecall_init_master_password_t;

typedef struct ms_ecall_clear_all_t {
	const char* ms_masterpw;
	size_t ms_masterpw_len;
} ms_ecall_clear_all_t;

typedef struct ms_ecall_set_debug_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_ecall_set_debug_t;

typedef struct ms_ocall_print_t {
	const char* ms_pw;
} ms_ocall_print_t;

typedef struct ms_ocall_print_address_t {
	const char* ms_str;
	uint64_t ms_a;
} ms_ocall_print_address_t;

static sgx_status_t SGX_CDECL encl_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_pw);

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
sgx_status_t ecall_setup(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_encl, NULL);
	return status;
}

sgx_status_t ecall_add_password(sgx_enclave_id_t eid, const char* masterpw, const char* plaintext_pw)
{
	sgx_status_t status;
	ms_ecall_add_password_t ms;
	ms.ms_masterpw = masterpw;
	ms.ms_masterpw_len = masterpw ? strlen(masterpw) + 1 : 0;
	ms.ms_plaintext_pw = plaintext_pw;
	ms.ms_plaintext_pw_len = plaintext_pw ? strlen(plaintext_pw) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, const char* old_masterpw, const char* new_masterpw)
{
	sgx_status_t status;
	ms_ecall_change_master_password_t ms;
	ms.ms_old_masterpw = old_masterpw;
	ms.ms_old_masterpw_len = old_masterpw ? strlen(old_masterpw) + 1 : 0;
	ms.ms_new_masterpw = new_masterpw;
	ms.ms_new_masterpw_len = new_masterpw ? strlen(new_masterpw) + 1 : 0;
	status = sgx_ecall(eid, 2, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_get_passwords2(sgx_enclave_id_t eid, const char* masterpw, void* output)
{
	sgx_status_t status;
	ms_ecall_get_passwords2_t ms;
	ms.ms_masterpw = masterpw;
	ms.ms_output = output;
	status = sgx_ecall(eid, 3, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_init_master_password(sgx_enclave_id_t eid, const char* masterpw)
{
	sgx_status_t status;
	ms_ecall_init_master_password_t ms;
	ms.ms_masterpw = masterpw;
	ms.ms_masterpw_len = masterpw ? strlen(masterpw) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_clear_all(sgx_enclave_id_t eid, const char* masterpw)
{
	sgx_status_t status;
	ms_ecall_clear_all_t ms;
	ms.ms_masterpw = masterpw;
	ms.ms_masterpw_len = masterpw ? strlen(masterpw) + 1 : 0;
	status = sgx_ecall(eid, 5, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_set_debug(sgx_enclave_id_t eid, const char* str)
{
	sgx_status_t status;
	ms_ecall_set_debug_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	status = sgx_ecall(eid, 6, &ocall_table_encl, &ms);
	return status;
}

