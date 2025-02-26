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


typedef struct ms_ecall_get_test_dummy_adrs_t {
	void* ms_retval;
} ms_ecall_get_test_dummy_adrs_t;

typedef struct ms_ecall_print_and_save_arg_once_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_print_and_save_arg_once_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_address_t {
	uint64_t ms_a;
} ms_ocall_print_address_t;

typedef struct ms_ocall_free_t {
	uint64_t ms_p;
} ms_ocall_free_t;

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_test();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_test_dummy_adrs(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_test_dummy_adrs_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_test_dummy_adrs_t* ms = SGX_CAST(ms_ecall_get_test_dummy_adrs_t*, pms);
	ms_ecall_get_test_dummy_adrs_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_test_dummy_adrs_t), ms, sizeof(ms_ecall_get_test_dummy_adrs_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _in_retval;


	_in_retval = ecall_get_test_dummy_adrs();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_setup(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_setup();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_print_and_save_arg_once(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_print_and_save_arg_once_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_print_and_save_arg_once_t* ms = SGX_CAST(ms_ecall_print_and_save_arg_once_t*, pms);
	ms_ecall_print_and_save_arg_once_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_print_and_save_arg_once_t), ms, sizeof(ms_ecall_print_and_save_arg_once_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = __in_ms.ms_str;
	size_t _len_str = __in_ms.ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_print_and_save_arg_once(_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_test, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_test_dummy_adrs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_setup, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_print_and_save_arg_once, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][4];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_print_address(uint64_t a)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_print_address_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_address_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_address_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_address_t));
	ocalloc_size -= sizeof(ms_ocall_print_address_t);

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

sgx_status_t SGX_CDECL ocall_free(uint64_t p)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_free_t));
	ocalloc_size -= sizeof(ms_ocall_free_t);

	if (memcpy_verw_s(&ms->ms_p, sizeof(ms->ms_p), &p, sizeof(p))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

