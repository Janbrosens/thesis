static char data[] = {'g', 'o', 'o', 'd', ' ', 'd', 'a', 't', 'a', '\0'};  
static int random_wait = 0;  


void ecall_writer_thread() {    
    snprintf(data, 10, " bad data ");  
}  

int ecall_checker_thread() {  
    char *str = calloc(1, 10);  
    if (strncmp(" bad data ", data, 9) != 0) {  
        memcpy(str, data, 10);  
        ocall_print(" Access ok : %s\n", str);  
        free(str);  
        return 0;  
    } else {  
        ocall_print(" Sorry, no access!\n");  
        return -1;  
    }  
}  
