#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



int volatile idx = 0;
int pincode = 1234;

int array[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};  

int ecall_lookup(){
    if(idx < 10){
        //ocall_print("idx in bounds"); // VRAAG werkt niet als uitcomment
        return array[idx];
    }else{
        return 9999;
    }
}

void ecall_increase(){
    idx++;
}

