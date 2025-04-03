#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct my_struct {
    int* sump;
    int* prodp;
};
struct my_struct msp;

void ecall_update_response_loc(struct my_struct* input_pointer) {
    if (outside_encl(input_pointer)) {
        struct my_struct msp = *input_pointer; 
        if (!(outside_encl(msp.sump) && outside_encl(msp.prodp))) {
            msp.sump = NULL;
            msp.prodp = NULL;
        }
    }
}

void ecall_compute_response(int i, int j) {
        *(msp.sump) = i + j;
        *(msp.prodp) = i * j;
}

