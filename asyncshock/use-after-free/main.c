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

/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "Enclave/encl_u.h"


//These are global variables (see memcmp)
int irq_cnt = 0, do_irq = 0, fault_cnt = 0, trigger_cnt = 0, step_cnt = 0;
uint64_t *pte_encl = NULL, *pte_trigger = NULL, *pmd_encl = NULL;
void *code_adrs, *trigger_adrs;

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


// Called upon SIGSEGV caused by untrusted page tables. 
void fault_handler(int signo, siginfo_t * si, void  *ctx)
{

    info("mynameisjef");

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
            info("Unknown #PF address!");
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
}

int main( int argc, char **argv )
{

    //code to get the address and page of the free() function, which permissions we will revoke like in the example in the paper

    void *free_addr = (void *)free;  // Get address of free()
    
    // Align address to page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((size_t)free_addr & ~(page_size - 1));

    printf("free() address: %p, page start: %p\n", free_addr, page_start);

    // revoke execute permission on free()
    mprotect(page_start, page_size, PROT_READ | PROT_WRITE);


    //TODO register signal handler



    
    sgx_enclave_id_t eid = create_enclave();
    int rv = 1, secret = 1;

    ecall_test(eid);

    ecall_setup(eid);

    //char* str = "japers";
    char *str = malloc(4096);  // Allocate a full page
    strcpy(str, "japers");     // Copy the string into the allocated memory

   
    ecall_print_and_save_arg_once(eid, str);

    info_event("destroying SGX enclave");
    SGX_ASSERT( sgx_destroy_enclave( eid ) );

    info("all is well; exiting..");
	return 0;
}