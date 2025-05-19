#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../mystruct.h"
#include "sgx_trts.h"

char* secret = "super_secret";
int pincode = 1234;

struct my_struct msp;

void ecall_update_response_loc(struct my_struct* input_pointer) {
        
        msp = *input_pointer; 

        
        if (!(sgx_is_outside_enclave(msp.sump, sizeof(int)) && sgx_is_outside_enclave(msp.prodp,  sizeof(int)))) {
            msp.sump = NULL;
            msp.prodp = NULL;
        }

}

void ecall_compute_response(int i, int j) {
    if( msp.sump != NULL && msp.prodp != NULL){
        *(msp.sump) = i + j;
        *(msp.prodp) = i * j;
    }
}

void ecall_get_response(){

    ocall_print_address("sump", (uint64_t) *(msp.sump));
    ocall_print_address("prodp", (uint64_t) *(msp.prodp));

}

void ecall_get_secret(int pin, char* out_buf, size_t max_len) {
    if (pin == pincode) {
        strncpy(out_buf, secret, max_len - 1);
    } else {
        strncpy(out_buf, "Pincode is wrong", max_len - 1);
    }
    out_buf[max_len - 1] = '\0'; // Always null-terminate
}

