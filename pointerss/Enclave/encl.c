#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../mystruct.h"
#include "sgx_trts.h"

int secret = 1234;

struct my_struct msp;

void ecall_update_response_loc(struct my_struct* input_pointer) {
    if (sgx_is_outside_enclave(input_pointer, sizeof(struct my_struct))) {
        msp = *input_pointer; 
        
        if (!(sgx_is_outside_enclave(msp.sump, sizeof(int)) && sgx_is_outside_enclave(msp.prodp,  sizeof(int)))) {
            msp.sump = NULL;
            msp.prodp = NULL;
        }
    }

}

void ecall_compute_response(int i, int j) {
        *(msp.sump) = i + j;
        *(msp.prodp) = i * j;
}

void ecall_get_response(){

    ocall_print_address("sump", (uint64_t) *(msp.sump));
    ocall_print_address("prodp", (uint64_t) *(msp.prodp));

}

void ecall_check_secret(int s){
    if(s == secret){
        ocall_print("Secret ok");
    }else{
        ocall_print("Secret wrong");
    }
}
