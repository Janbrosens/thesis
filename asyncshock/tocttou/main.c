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

#define DO_TIMER_STEP      0

//These are global variables (see memcmp)
int irq_cnt = 0, do_irq = 0, fault_cnt = 0, trigger_cnt = 0, step_cnt = 0;
uint64_t *pte_encl = NULL, *pte_trigger = NULL, *pmd_encl = NULL;
void *code_adrs, *trigger_adrs;

// test_dummy pointer
//void *td_pt = NULL;

// THREADING INIT
int turn = 1; // 0 for thread_A, 1 for thread_B
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

    switch (signo) {
        case SIGSEGV:
            info("[Thread %lu] Caught page fault with fault address: %p, Adjusted page start: %p\n", pthread_self(), si->si_addr, fault_page);
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

    
    /*
    //Revoke access rights on test_dummy after caught page fault on free 
    if(fault_page == free_page_start){
        if (mprotect(free_page_start, 4096, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights restored on free\n");
        }
        //printf("tessdasdasdast\n");
        // revoke execute permission on test_dummy()
        if (mprotect(test_dummy_page_start, 4096, PROT_NONE) != 0) {
            perror("mprotect failed");
        }else{
            printf("access rights revoked on test_dummy\n");
        }
    
    }*/

    

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





int main( int argc, char **argv )
{

    //Create Enclave
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 1;

    //TESTING 
    //ecall_test_malloc_free(eid);

    // Dry Run 

    ecall_checker_thread(eid);
    ecall_writer_thread(eid);
    ecall_checker_thread(eid);

    void *memcpy_addr = (void *)memcpy;
    void *strncmp_addr = (void *)strncmp;

    printf("memcpy address: %p\n", memcpy_addr);
    printf("strncmp address: %p\n", strncmp_addr);



    // Do setup again
    /* 1. Setup attack execution environment. */
    attacker_config_runtime();

    // get the address of test_dummy function, written to td_pt
    //ecall_get_test_dummy_adrs(eid, &td_pt);


    info_event("destroying SGX enclave");
    //SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}