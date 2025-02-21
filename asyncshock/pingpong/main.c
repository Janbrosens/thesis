#include <stdio.h>
#include <pthread.h>
#include "sgx_urts.h"
#include "Enclave/encl_u.h"
#include "sgx-step/libsgxstep/debug.h"

#define NUM_ITERATIONS 10



sgx_enclave_id_t create_enclave(void)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t eid = -1;

    info_event("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    return eid;
}



void ocall_print(const char *str)
{
    info("ocall_print: enclave says: %s", str);
}



int turn = 0; // 0 for thread_A, 1 for thread_B

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

// Function for thread A
void* thread_A(void* arg) {
    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        
        pthread_mutex_lock(&lock);
        while (turn != 0) { // Wait until it's thread_A's turn
            pthread_cond_wait(&cond, &lock);
        }

        ecall_ping(eidarg); // Enter enclave and print "Ping"
        turn = 1; // Give turn to thread_B
        pthread_cond_signal(&cond); // Wake up thread_B

        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

// Function for thread B
void* thread_B(void* arg) {
    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        pthread_mutex_lock(&lock);
        while (turn != 1) { // Wait until it's thread_B's turn
            pthread_cond_wait(&cond, &lock);
        }

        ecall_pong(eidarg); // Enter enclave and print "Pong"
        turn = 0; // Give turn back to thread_A
        pthread_cond_signal(&cond); // Wake up thread_A
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}


int main() {

    //Create Enclave
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 1;

    //ecall_ping(eid);
    //ecall_pong(eid);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_A, (void*)&eid);
    pthread_create(&t2, NULL, thread_B, (void*)&eid);

    //printf("test");

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    sgx_destroy_enclave(eid);
    return 0;
}

