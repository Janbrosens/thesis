#include "encl_u.h"
#include <errno.h>

typedef struct ms_ecall_login_t {
	int ms_deviceId;
	const char* ms_pw;
	size_t ms_pw_len;
} ms_ecall_login_t;

typedef struct ms_ecall_logout_t {
	int ms_deviceId;
} ms_ecall_logout_t;

typedef struct ms_ecall_get_password_t {
	int ms_deviceId;
} ms_ecall_get_password_t;

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
sgx_status_t ecall_login(sgx_enclave_id_t eid, int deviceId, const char* pw)
{
	sgx_status_t status;
	ms_ecall_login_t ms;
	ms.ms_deviceId = deviceId;
	ms.ms_pw = pw;
	ms.ms_pw_len = pw ? strlen(pw) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_logout(sgx_enclave_id_t eid, int deviceId)
{
	sgx_status_t status;
	ms_ecall_logout_t ms;
	ms.ms_deviceId = deviceId;
	status = sgx_ecall(eid, 1, &ocall_table_encl, &ms);
	return status;
}

sgx_status_t ecall_get_password(sgx_enclave_id_t eid, int deviceId)
{
	sgx_status_t status;
	ms_ecall_get_password_t ms;
	ms.ms_deviceId = deviceId;
	status = sgx_ecall(eid, 2, &ocall_table_encl, &ms);
	return status;
}

