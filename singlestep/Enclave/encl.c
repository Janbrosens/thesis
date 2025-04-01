#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



int idx = 0;
int pincode = 1234;

int array[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};  


void ecall_increase(){
    idx++;
}

int ecall_lookup(){
    ocall_print("test1");

    ocall_print("test2");

    ocall_print("test3");

    return array[idx];
}

