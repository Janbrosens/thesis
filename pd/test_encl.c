// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include <stddef.h>

// sgx_is_outside_enclave()
// Parameters:
//      addr - the start address of the buffer
//      size - the size of the buffer
// Return Value:
//      1 - the buffer is strictly outside the enclave
//      0 - the whole buffer or part of the buffer is not outside the enclave,
//          or the buffer is wrap around
//
extern char* __enclave_start, __enclave_end;
int sgx_is_outside_enclave(const void *addr, size_t size)
{
    size_t start = (size_t)addr;
    size_t end = 0;
    size_t enclave_start = (size_t) &__enclave_start;
    size_t enclave_end = (size_t) &__enclave_end - 1;
    // the enclave range is [enclave_start, enclave_end] inclusively

    if(size > 0)
    {
        end = start + size - 1;
    }
    else
    {
        end = start;
    }
    if( (start <= end) && ((end < enclave_start) || (start > enclave_end)) )
    {
        return 1;
    }
    return 0;
}
char *strncpy(char *dest, const char *src, size_t n) {
    size_t i = 0;
    for (; i < n && src[i] != '\0'; ++i)
        dest[i] = src[i];
    for (; i < n; ++i)
        dest[i] = '\0';
    return dest;
}

typedef struct my_struct {
    int* sump;
    int* prodp;
} my_struct_t;

my_struct_t msp = {
    .sump = NULL,
    .prodp = NULL
};

typedef struct ecr_struct{
    int i;
    int j;
} ecr_struct_t;

typedef struct pw_struct{
    char *passwords[10];
    int array_len;
    int pw_len;
}pw_struct_t;

pw_struct_t s = {
    .passwords = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
    .array_len = 0,
    .pw_len = 0
};

void __attribute__((noinline)) ecall_update_response_loc(my_struct_t* input_pointer){

    /* 1. copy input_pointer struct inside */
    if (!(sgx_is_outside_enclave(input_pointer, sizeof(my_struct_t))))
        return;

    msp = *input_pointer; 
     
    if (!(sgx_is_outside_enclave(msp.sump, sizeof(int)) &&
          sgx_is_outside_enclave(msp.prodp,  sizeof(int))))
    {
        msp.sump = NULL;
        msp.prodp = NULL;
    }
}

void __attribute__((noinline)) ecall_compute_response(ecr_struct_t *ops)
{
    if (!(sgx_is_outside_enclave(ops, sizeof(ecr_struct_t))))
        return;

    int i = ops->i;
    int j = ops->j;

    if( (msp.sump != NULL) && (msp.prodp != NULL)){
        *(msp.sump) = i + j;
        *(msp.prodp) = i * j;
    }
}

int pw_count = 5;
char stored_passwords[5][32] = {
    "password1",
    "123456",
    "admin",
    "letmein",
    "default"
};

void __attribute__((noinline)) ecall_get_passwords( pw_struct_t *output) {
    if (!sgx_is_outside_enclave(output, sizeof(pw_struct_t))) {
        return;
    }
    s = *output;
    
    /*
    if (!verify_master_password(masterpw) && !debug) {
        output->array_len = 0;
        return;
    }*/
    
    // Assume output->passwords is already allocated
    for (int i = 0; i < pw_count; ++i) {
        if (!sgx_is_outside_enclave(s.passwords[i], s.pw_len)) {
            //ocall_print_address("wrong pointer", s.passwords[i] );
            return; // attacker-provided pointer not safe
        }
        strncpy(s.passwords[i], stored_passwords[i], s.pw_len - 1);    
    }
}





void encl_body(void *rdi,  void *rsi)
{
    ecall_get_passwords(rdi);
    ecall_update_response_loc(rdi);
    ecall_compute_response(rsi);
}
