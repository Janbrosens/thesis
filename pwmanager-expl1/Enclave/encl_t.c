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

typedef struct ms_ocall_print_t {
	const char* ms_pw;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL sgx_ecall_setup(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_setup();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_password_t* ms = SGX_CAST(ms_ecall_add_password_t*, pms);
	ms_ecall_add_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_add_password_t), ms, sizeof(ms_ecall_add_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_masterpw = __in_ms.ms_masterpw;
	size_t _len_masterpw = __in_ms.ms_masterpw_len ;
	char* _in_masterpw = NULL;
	const char* _tmp_plaintext_pw = __in_ms.ms_plaintext_pw;
	size_t _len_plaintext_pw = __in_ms.ms_plaintext_pw_len ;
	char* _in_plaintext_pw = NULL;

	CHECK_UNIQUE_POINTER(_tmp_masterpw, _len_masterpw);
	CHECK_UNIQUE_POINTER(_tmp_plaintext_pw, _len_plaintext_pw);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_masterpw != NULL && _len_masterpw != 0) {
		_in_masterpw = (char*)malloc(_len_masterpw);
		if (_in_masterpw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_masterpw, _len_masterpw, _tmp_masterpw, _len_masterpw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_masterpw[_len_masterpw - 1] = '\0';
		if (_len_masterpw != strlen(_in_masterpw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_plaintext_pw != NULL && _len_plaintext_pw != 0) {
		_in_plaintext_pw = (char*)malloc(_len_plaintext_pw);
		if (_in_plaintext_pw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext_pw, _len_plaintext_pw, _tmp_plaintext_pw, _len_plaintext_pw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_plaintext_pw[_len_plaintext_pw - 1] = '\0';
		if (_len_plaintext_pw != strlen(_in_plaintext_pw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_add_password((const char*)_in_masterpw, (const char*)_in_plaintext_pw);

err:
	if (_in_masterpw) free(_in_masterpw);
	if (_in_plaintext_pw) free(_in_plaintext_pw);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_change_master_password_t* ms = SGX_CAST(ms_ecall_change_master_password_t*, pms);
	ms_ecall_change_master_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_change_master_password_t), ms, sizeof(ms_ecall_change_master_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_old_masterpw = __in_ms.ms_old_masterpw;
	size_t _len_old_masterpw = __in_ms.ms_old_masterpw_len ;
	char* _in_old_masterpw = NULL;
	const char* _tmp_new_masterpw = __in_ms.ms_new_masterpw;
	size_t _len_new_masterpw = __in_ms.ms_new_masterpw_len ;
	char* _in_new_masterpw = NULL;

	CHECK_UNIQUE_POINTER(_tmp_old_masterpw, _len_old_masterpw);
	CHECK_UNIQUE_POINTER(_tmp_new_masterpw, _len_new_masterpw);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_old_masterpw != NULL && _len_old_masterpw != 0) {
		_in_old_masterpw = (char*)malloc(_len_old_masterpw);
		if (_in_old_masterpw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_old_masterpw, _len_old_masterpw, _tmp_old_masterpw, _len_old_masterpw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_old_masterpw[_len_old_masterpw - 1] = '\0';
		if (_len_old_masterpw != strlen(_in_old_masterpw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_new_masterpw != NULL && _len_new_masterpw != 0) {
		_in_new_masterpw = (char*)malloc(_len_new_masterpw);
		if (_in_new_masterpw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_new_masterpw, _len_new_masterpw, _tmp_new_masterpw, _len_new_masterpw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_new_masterpw[_len_new_masterpw - 1] = '\0';
		if (_len_new_masterpw != strlen(_in_new_masterpw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_change_master_password((const char*)_in_old_masterpw, (const char*)_in_new_masterpw);

err:
	if (_in_old_masterpw) free(_in_old_masterpw);
	if (_in_new_masterpw) free(_in_new_masterpw);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_passwords2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_passwords2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_passwords2_t* ms = SGX_CAST(ms_ecall_get_passwords2_t*, pms);
	ms_ecall_get_passwords2_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_passwords2_t), ms, sizeof(ms_ecall_get_passwords2_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_masterpw = __in_ms.ms_masterpw;
	size_t _len_masterpw = sizeof(char);
	char* _in_masterpw = NULL;
	void* _tmp_output = __in_ms.ms_output;

	CHECK_UNIQUE_POINTER(_tmp_masterpw, _len_masterpw);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_masterpw != NULL && _len_masterpw != 0) {
		if ( _len_masterpw % sizeof(*_tmp_masterpw) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_masterpw = (char*)malloc(_len_masterpw);
		if (_in_masterpw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_masterpw, _len_masterpw, _tmp_masterpw, _len_masterpw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_get_passwords2((const char*)_in_masterpw, _tmp_output);

err:
	if (_in_masterpw) free(_in_masterpw);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_master_password_t* ms = SGX_CAST(ms_ecall_init_master_password_t*, pms);
	ms_ecall_init_master_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_init_master_password_t), ms, sizeof(ms_ecall_init_master_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_masterpw = __in_ms.ms_masterpw;
	size_t _len_masterpw = __in_ms.ms_masterpw_len ;
	char* _in_masterpw = NULL;

	CHECK_UNIQUE_POINTER(_tmp_masterpw, _len_masterpw);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_masterpw != NULL && _len_masterpw != 0) {
		_in_masterpw = (char*)malloc(_len_masterpw);
		if (_in_masterpw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_masterpw, _len_masterpw, _tmp_masterpw, _len_masterpw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_masterpw[_len_masterpw - 1] = '\0';
		if (_len_masterpw != strlen(_in_masterpw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_init_master_password((const char*)_in_masterpw);

err:
	if (_in_masterpw) free(_in_masterpw);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_clear_all(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_clear_all_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_clear_all_t* ms = SGX_CAST(ms_ecall_clear_all_t*, pms);
	ms_ecall_clear_all_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_clear_all_t), ms, sizeof(ms_ecall_clear_all_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_masterpw = __in_ms.ms_masterpw;
	size_t _len_masterpw = __in_ms.ms_masterpw_len ;
	char* _in_masterpw = NULL;

	CHECK_UNIQUE_POINTER(_tmp_masterpw, _len_masterpw);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_masterpw != NULL && _len_masterpw != 0) {
		_in_masterpw = (char*)malloc(_len_masterpw);
		if (_in_masterpw == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_masterpw, _len_masterpw, _tmp_masterpw, _len_masterpw)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_masterpw[_len_masterpw - 1] = '\0';
		if (_len_masterpw != strlen(_in_masterpw) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_clear_all((const char*)_in_masterpw);

err:
	if (_in_masterpw) free(_in_masterpw);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_setup, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_change_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_passwords2, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_init_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_clear_all, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][6];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* pw)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pw = pw ? strlen(pw) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pw, _len_pw);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pw != NULL) ? _len_pw : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (pw != NULL) {
		if (memcpy_verw_s(&ms->ms_pw, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pw % sizeof(*pw) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pw, _len_pw)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pw);
		ocalloc_size -= _len_pw;
	} else {
		ms->ms_pw = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

