#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct my_struct {
    int* sump;
    int* prodp;
};
struct my_struct* msp;

void ecall_update_response_loc(struct my_struct* input_pointer) {
    if (outside_encl(input_pointer)) {
        struct my_struct enclave_copy = *input_pointer; 
        if (outside_encl(enclave_copy.sump) && outside_encl(enclave_copy.prodp)) {
            msp = input_pointer;
            msp->sump = enclave_copy.sump;
            msp->prodp = enclave_copy.prodp;
        }
    }
}

void ecall_compute_response(int i, int j) {
        *(msp->sump) = i + j;
        *(msp->prodp) = i * j;
}