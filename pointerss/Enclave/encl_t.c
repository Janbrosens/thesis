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


typedef struct ms_ecall_update_response_loc_t {
	struct my_struct* ms_input_pointer;
} ms_ecall_update_response_loc_t;

typedef struct ms_ecall_compute_response_t {
	int ms_i;
	int ms_j;
} ms_ecall_compute_response_t;

typedef struct ms_ecall_get_secret_t {
	int ms_pin;
	char* ms_out_buf;
	size_t ms_max_len;
} ms_ecall_get_secret_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_address_t {
	const char* ms_str;
	uint64_t ms_a;
} ms_ocall_print_address_t;

static sgx_status_t SGX_CDECL sgx_ecall_update_response_loc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_update_response_loc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_update_response_loc_t* ms = SGX_CAST(ms_ecall_update_response_loc_t*, pms);
	ms_ecall_update_response_loc_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_update_response_loc_t), ms, sizeof(ms_ecall_update_response_loc_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	struct my_struct* _tmp_input_pointer = __in_ms.ms_input_pointer;
	size_t _len_input_pointer = sizeof(struct my_struct);
	struct my_struct* _in_input_pointer = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input_pointer, _len_input_pointer);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input_pointer != NULL && _len_input_pointer != 0) {
		_in_input_pointer = (struct my_struct*)malloc(_len_input_pointer);
		if (_in_input_pointer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input_pointer, _len_input_pointer, _tmp_input_pointer, _len_input_pointer)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_update_response_loc(_in_input_pointer);

err:
	if (_in_input_pointer) free(_in_input_pointer);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_compute_response(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_compute_response_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_compute_response_t* ms = SGX_CAST(ms_ecall_compute_response_t*, pms);
	ms_ecall_compute_response_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_compute_response_t), ms, sizeof(ms_ecall_compute_response_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_compute_response(__in_ms.ms_i, __in_ms.ms_j);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_response(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_get_response();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_secret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_secret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_secret_t* ms = SGX_CAST(ms_ecall_get_secret_t*, pms);
	ms_ecall_get_secret_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_secret_t), ms, sizeof(ms_ecall_get_secret_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_out_buf = __in_ms.ms_out_buf;
	size_t _tmp_max_len = __in_ms.ms_max_len;
	size_t _len_out_buf = _tmp_max_len;
	char* _in_out_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out_buf, _len_out_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out_buf != NULL && _len_out_buf != 0) {
		if ( _len_out_buf % sizeof(*_tmp_out_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out_buf = (char*)malloc(_len_out_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_buf, 0, _len_out_buf);
	}
	ecall_get_secret(__in_ms.ms_pin, _in_out_buf, _tmp_max_len);
	if (_in_out_buf) {
		if (memcpy_verw_s(_tmp_out_buf, _len_out_buf, _in_out_buf, _len_out_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out_buf) free(_in_out_buf);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_update_response_loc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_compute_response, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_response, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_secret, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][4];
} g_dyn_entry_table = {
	2,
	{
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

