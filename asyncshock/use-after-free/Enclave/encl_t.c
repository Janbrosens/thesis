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

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_test();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test_malloc_free(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_test_malloc_free();
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

static sgx_status_t SGX_CDECL sgx_ecall_get_succes_adrs(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_succes_adrs_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_succes_adrs_t* ms = SGX_CAST(ms_ecall_get_succes_adrs_t*, pms);
	ms_ecall_get_succes_adrs_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_succes_adrs_t), ms, sizeof(ms_ecall_get_succes_adrs_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _in_retval;


	_in_retval = ecall_get_succes_adrs();
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


	ecall_print_and_save_arg_once(__in_ms.ms_str);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_test, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_test_malloc_free, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_test_dummy_adrs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_succes_adrs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_setup, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_print_and_save_arg_once, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][6];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
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

