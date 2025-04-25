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

typedef struct ms_ecall_get_passwords_t {
	const char* ms_masterpw;
	size_t ms_masterpw_len;
} ms_ecall_get_passwords_t;

typedef struct ms_ecall_clear_all_t {
	const char* ms_masterpw;
	size_t ms_masterpw_len;
} ms_ecall_clear_all_t;

typedef struct ms_ocall_print_t {
	const char* ms_pw;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL encl_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_pw);

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

sgx_status_t ecall_get_passwords(sgx_enclave_id_t eid, const char* masterpw)
{
	sgx_status_t status;
	ms_ecall_get_passwords_t ms;
	ms.ms_masterpw = masterpw;
	ms.ms_masterpw_len = masterpw ? strlen(masterpw) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_clear_all(sgx_enclave_id_t eid, const char* masterpw)
{
	sgx_status_t status;
	ms_ecall_clear_all_t ms;
	ms.ms_masterpw = masterpw;
	ms.ms_masterpw_len = masterpw ? strlen(masterpw) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_encl, &ms);
	return status;
}

