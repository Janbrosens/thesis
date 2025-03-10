#include <stddef.h>  // For NULL
#include <stdlib.h>  // For malloc and free
#include <string.h>  // For memcpy
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "encl_t.h"  // Include this to get OCall declarations


// --- CODE FOR CUSTOM MALLOC AND FREE ---
// for this setup, we use a simple malloc that always returns the last freed block as next block 

#define MEM_POOL_SIZE 1024  // Fixed memory pool size
#define ALIGNMENT 8         // Ensure proper memory alignment

// Block structure to track free memory
typedef struct Block {
    size_t size;
    struct Block* next;
} Block;

static uint8_t memory_pool[MEM_POOL_SIZE]; // The memory pool
static Block* free_list = NULL;  // Stack-based free list
static size_t offset = 0;        // Current allocation offset

// Align size to the next multiple of ALIGNMENT
static size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

// Custom malloc
void* my_malloc(size_t size) {
    size = align_size(size);

    // Try to reuse from the free list (FILO behavior)
    if (free_list) {
        Block* block = free_list;
        free_list = free_list->next;
        return (void*)(block);
    }

    // Otherwise, allocate from the pool
    if (offset + size > MEM_POOL_SIZE) {
        return NULL; // Out of memory
    }

    void* ptr = &memory_pool[offset];
    offset += size;
    return ptr;
}

// Custom free (adds the block to the free list stack)
void my_free(void* ptr, size_t size) {
    if (!ptr) return;

    Block* block = (Block*)ptr;
    block->size = align_size(size);
    block->next = free_list;
    free_list = block; // LIFO: latest freed block is used first
}

void ecall_test_malloc_free(){
    void* a = my_malloc(100);
    void* b = my_malloc(100);
   
    ocall_print_address("Allocated A at ", (uint64_t) a);
    ocall_print_address("Allocated B at ", (uint64_t) b);

    my_free(b, 100);  // Free B first
    my_free(a, 100);  // Free A next

    void* c = my_malloc(100);  // Should reuse A’s space
    ocall_print_address("Allocated C (should reuse A) at ", (uint64_t) c);


    void* d = my_malloc(100);  // Should reuse B’s space
    ocall_print_address("Allocated D (should reuse B) at ", (uint64_t) d);

    ocall_print("");
    ocall_print("----- TEST DONE -----");
    ocall_print("");


}

// Function that is called if exploit is succesfull
void success(){
    ocall_print("☠️  SYSTEM HACKED ☠️");
}

char *glob_str_ptr;

int other_functions(const char *c) { 
    /* do other things */
}

// test_dummy is defined in asm.S, because for this setup we want to make it page aligned and alone on a page
uint64_t test_dummy();

void *ecall_get_test_dummy_adrs()
{
    return test_dummy;    
}

void *ecall_get_succes_adrs()
{
    return success;    
}


int puts(const char *c) {  
    ocall_print(c);  
    return 0;  
}

struct my_func_ptr {  
    int (*my_puts)(const char *);  
    char desc[8];  
} my_func_ptr;  


void ecall_test(){
    const char* str= "jeffrey";
    ocall_print(str);
}

// this ecall is called once before every execution
void ecall_setup() {  
    glob_str_ptr = my_malloc(sizeof(struct my_func_ptr));  
    ocall_print_address("glob str ptr",(uint64_t)glob_str_ptr);
}


void ecall_print_and_save_arg_once(uint64_t str) {  
    ocall_print_address("str", str);

    struct my_func_ptr *mfp = my_malloc(sizeof(struct my_func_ptr));
    mfp->my_puts = puts;  

    ocall_print_address("glob str ptr", (uint64_t)glob_str_ptr);
    ocall_print_address("mfp",(uint64_t)mfp);
    ocall_print_address("succes func",(uint64_t) (void*)success);

    if (glob_str_ptr != NULL) {  
        
        memcpy(glob_str_ptr,(char*) str, sizeof(glob_str_ptr));  
        glob_str_ptr[sizeof(glob_str_ptr)] = '\0';  

        ocall_print_address("mfp->myputs",(uint64_t) mfp->my_puts); 
        ocall_print_address("puts",(uint64_t) (void*)puts); 

        mfp->my_puts(glob_str_ptr);  
        my_free(glob_str_ptr, sizeof(struct my_func_ptr));

        ocall_print("glob_str_ptr is freed");

        // for this setup, extra helper function where page access can be revoked from easily,
        // normal attack will require a more complex state machine to revoke page accesses
        // --- PAGE FAULT HERE (after free) ---
        test_dummy();
        glob_str_ptr = NULL;  
    }  
    
    my_free(mfp, sizeof(struct my_func_ptr));  
    ocall_print("exiting enclave");

}