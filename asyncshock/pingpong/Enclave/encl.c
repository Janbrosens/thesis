#include <stdio.h>
#include "sgx_thread.h"
#include "encl_t.h"  // Include this to get OCall declarations


sgx_thread_mutex_t mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_cond_t cond = SGX_THREAD_COND_INITIALIZER;
int turn = 0;  // 0 for ping, 1 for pong

void ecall_ping() {
    sgx_thread_mutex_lock(&mutex);
    while (turn != 0) {
        sgx_thread_cond_wait(&cond, &mutex);
    }
    ocall_print("[SGX] Ping!\n");
    turn = 1;  // Switch turn
    sgx_thread_cond_signal(&cond);
    sgx_thread_mutex_unlock(&mutex);
}

void ecall_pong() {
    sgx_thread_mutex_lock(&mutex);
    while (turn != 1) {
        sgx_thread_cond_wait(&cond, &mutex);
    }
    ocall_print("[SGX] Pong!\n");
    turn = 0;  // Switch turn
    sgx_thread_cond_signal(&cond);
    sgx_thread_mutex_unlock(&mutex);
}
