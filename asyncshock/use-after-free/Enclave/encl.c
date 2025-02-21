#include <stddef.h>  // For NULL
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy
#include <stdio.h>
#include "encl_t.h"  // Include this to get OCall declarations



char *glob_str_ptr;

int other_functions(const char *c) { 
    /* do other things */
}

int puts(const char *c) {  
    ocall_print(c);  
    return 0;  
}

struct my_func_ptr {  
    int (*my_puts)(const char *);  
    char desc[8];  
} my_func_ptr;  

void ecall_test(){

    const char* str= "jeffrey";
    ocall_print(str);
}


void ecall_setup() {  
    glob_str_ptr = malloc(sizeof(struct my_func_ptr));  
}

void ecall_print_and_save_arg_once(char *str) {  
    struct my_func_ptr *mfp = malloc(sizeof(struct my_func_ptr));  
    mfp->my_puts = puts;  

    //TEST
    char* test = str;
   

    if (glob_str_ptr != NULL) {  

        ocall_print(test);
        
        memcpy(glob_str_ptr, (char *)str, sizeof(glob_str_ptr));  
        glob_str_ptr[sizeof(glob_str_ptr)] = '\0';  
        mfp->my_puts(glob_str_ptr);  
        free(glob_str_ptr);  
        glob_str_ptr = NULL;  
    }  
    free(mfp);  
}