#include <stddef.h>  // For NULL
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy
#include <stdio.h>
#include "encl_t.h"  // Include this to get OCall declarations



char *glob_str_ptr;

int other_functions(const char *c) { 
    /* do other things */
}

int test_dummy(){
    return 0;
}

void *ecall_get_test_dummy_adrs(void)
{
    return test_dummy;    
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
    ocall_print_address((char*)glob_str_ptr);

}

void ecall_print_and_save_arg_once(char *str) {  
    struct my_func_ptr *mfp = malloc(sizeof(struct my_func_ptr));
    mfp->my_puts = puts;  

    ocall_print_address((char*)mfp);

    ocall_print_address((char*)glob_str_ptr);

    //TEST
    char* test = str;
   

    if (glob_str_ptr != NULL) {  

        //ocall_print(test);
        
        memcpy(glob_str_ptr, (char *)str, sizeof(glob_str_ptr));  
        glob_str_ptr[sizeof(glob_str_ptr)] = '\0';  
        mfp->my_puts(glob_str_ptr);  

        ocall_print("test"); //PROBLEM ocalls (prints) are not done for thread B

        free(glob_str_ptr);
        
        //ocall_print("test");
        //for testing, extra helper function where page access can be revoked from
        //strchr -> didnt work to edit perm
        // ocall_print("pf after free"); same
        // test_dummy works (see RSA example)
        test_dummy();

        //ocall_print(str);

        glob_str_ptr = NULL;  
    }  
    free(mfp);  
}