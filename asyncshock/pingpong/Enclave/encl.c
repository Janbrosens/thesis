#include <stdio.h>
#include "sgx_thread.h"
#include "encl_t.h"  // Include this to get OCall declarations


sgx_thread_mutex_t mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t cond = SGX_THREAD_COND_INITIALIZER;
int turn = 0;  // 0 for ping, 1 for pong

void ecall_ping() {
    
    ocall_print("[SGX] Ping!\n");
    
}

void ecall_pong() {
    
    ocall_print("[SGX] Pong!\n");
    
}
