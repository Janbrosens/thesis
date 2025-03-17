#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



static char data[] = {'g', 'o', 'o', 'd', ' ', 'd', 'a', 't', 'a', '\0'};  

int ecall_checker_thread() {
    //ocall_print("test1");  
    char *str = calloc(1, 10);
    //ocall_print("test2");  
    if (strncmp(" bad data ", data, 9) != 0) { 
        ocall_print("test3"); 
        memcpy(str, data, 10);  
        ocall_print("ACCESS OK");
        ocall_print(str); 
        //PROBLEEM MET FREE
        free(str);  
        return 0;  
    } else {  
        ocall_print(" Sorry, no access!\n");  
        return -1;  
    }  
}  


void ecall_writer_thread() {    
    
    ocall_print_address("strncmp", (uint64_t) (void*) strncmp);
    ocall_print_address("memcpy", (uint64_t) (void*) memcpy);
    ocall_print_address("ecall_checker", (uint64_t) (void*) ecall_checker_thread);

    snprintf(data, 10, " bad data ");  
}  

void *ecall_get_memcpy()
{
    return memcpy;    
}

void *ecall_get_strncmp()
{
    return strncmp;    
}



