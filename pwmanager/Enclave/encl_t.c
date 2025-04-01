#include "encl_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_login(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_login_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_login_t* ms = SGX_CAST(ms_ecall_login_t*, pms);
	ms_ecall_login_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_login_t), ms, sizeof(ms_ecall_login_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_pw = __in_ms.ms_pw;
	size_t _len_pw = __in_ms.ms_pw_len ;
	char* _in_pw = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pw, _len_pw);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pw != NULL && _len_pw != 0) {
		_in_pw = (char*)malloc(_len_pw);
		if (_in_pw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pw, _len_pw, _tmp_pw, _len_pw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_pw[_len_pw - 1] = '\0';
		if (_len_pw != strlen(_in_pw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_login(__in_ms.ms_deviceId, (const char*)_in_pw);

err:
	if (_in_pw) free(_in_pw);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_logout(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_logout_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_logout_t* ms = SGX_CAST(ms_ecall_logout_t*, pms);
	ms_ecall_logout_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_logout_t), ms, sizeof(ms_ecall_logout_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_logout(__in_ms.ms_deviceId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_password_t* ms = SGX_CAST(ms_ecall_get_password_t*, pms);
	ms_ecall_get_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_password_t), ms, sizeof(ms_ecall_get_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_get_password(__in_ms.ms_deviceId);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_login, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_logout, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_password, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][3];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_address(const char* str, uint64_t a)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_address_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_address_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_address_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_address_t));
	ocalloc_size -= sizeof(ms_ocall_print_address_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	if (memcpy_verw_s(&ms->ms_a, sizeof(ms->ms_a), &a, sizeof(a))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

