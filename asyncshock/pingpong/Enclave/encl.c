#include <stdio.h>
#include "sgx_thread.h"
#include "encl_t.h"  // Include this to get OCall declarations


void ecall_ping() {
    
    ocall_print("[SGX] Ping!\n");
    
}

void ecall_pong() {
    
    ocall_print("[SGX] Pong!\n");
    
}
