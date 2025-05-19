// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include <stddef.h>
#include "defines.h"

/*
 * Data buffer spanning two pages that will be placed first in .data
 * segment. Even if not used internally the second page is needed by
 * external test manipulating page permissions.
 */

/*
 * Unmeasured data buffer in enclave for testing purposes. This is allocated in
 * a separate .unmeasured section, so as to allow the LinuxSelftestEnclave
 * loader to recognize this as such and mark it as _unmeasured_ SGX memory for
 * Pandora symbolic exploration. Allows testing vulnerabilities where
 * unmeasured enclave memory is accessed before secure initialization.
 */
extern volatile uint8_t unmeasured_encl_buffer[100];

volatile uint8_t non_exec_data_buffer[10] = { 0xc3 /* x86 ret instruction */ };

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



struct my_struct {
    int* sump;
    int* prodp;
} msp;

static void ecall_update_response_loc(void* op) {
    struct my_struct* input_pointer = op;
    if (sgx_is_outside_enclave(input_pointer, sizeof(struct my_struct))) {
        msp = *input_pointer; 
        
        if (!(sgx_is_outside_enclave(msp.sump, sizeof(int)) && sgx_is_outside_enclave(msp.prodp,  sizeof(int)))) {
                msp.sump = NULL;
                msp.prodp = NULL;
            }
        
    }

}

void encl_body(void *rdi,  void *rsi)
{
    const void (*encl_op_array[ENCL_OP_MAX])(void *) = {
    	ecall_update_response_loc
    	
    };
    
    struct encl_op_header *op = (struct encl_op_header *)rdi;
    
    // 1. check if the argument struct header lies entirely outside 
    #if FIX_SANITIZATION >= 1
        // NOTE: this is necessary but not sufficient (as subsequent
         // operations will dereference further offsets) 
        if (!sgx_is_outside_enclave(op, sizeof(struct encl_op_header)))
            return;
    #endif

    // 2. copy the untrusted array idx inside the enclave to protect against TOCTOU attacks 
    #if FIX_SANITIZATION >= 2
        volatile uint64_t op_type = op->type;
    #else
        #define op_type (op->type)
    #endif

    if (op_type < ENCL_OP_MAX)
    {
        (*(encl_op_array[op_type] + (size_t) &__enclave_start))(op);
    }
}
