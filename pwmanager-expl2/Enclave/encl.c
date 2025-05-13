// enclave_passwords.c
#include "encl_t.h"
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <stdio.h>
#include "../mystruct.h"


#define MAX_PASSWORDS 4
#define PW_LEN 32  // Max length for stored plaintext passwords

// Stored in enclave memory
int debug = 0;
char stored_passwords[MAX_PASSWORDS][PW_LEN];
int volatile pw_count = 0;
sgx_sha256_hash_t current_masterpw_hash = {0};  // Hash of master password
struct my_struct s;

// Helper: Print strings
void print_str(const char* label, const char* str) {
    ocall_print(label);
    ocall_print(str);
}

// Hash helper
void hash_password(const char *pw, sgx_sha256_hash_t *out_hash) {
    sgx_sha256_msg((const uint8_t *)pw, (uint32_t)strlen(pw), out_hash);
}

// Compare password hash to stored hash
int verify_master_password(const char *provided_pw) {
    sgx_sha256_hash_t provided_hash;
    hash_password(provided_pw, &provided_hash);

    return (memcmp(&provided_hash, &current_masterpw_hash, sizeof(sgx_sha256_hash_t)) == 0);
}

// Initialize master password if not set
void ecall_init_master_password(const char *new_masterpw) {
    sgx_sha256_hash_t zero_hash = {0};

    if (memcmp(&current_masterpw_hash, &zero_hash, sizeof(sgx_sha256_hash_t)) != 0) {
        ocall_print("[Enclave] Master password is already set. Initialization denied.");
        return;
    }

    hash_password(new_masterpw, &current_masterpw_hash);
    ocall_print("[Enclave] Master password initialized successfully.");
}

// Setup for testing
void ecall_setup() {
    const char *initial_masterpw = "super_secret";
    ecall_init_master_password(initial_masterpw);

    ecall_add_password(initial_masterpw, "RikkieTheFrog");
    print_str("Stored PW 1", stored_passwords[0]);

    ecall_add_password(initial_masterpw, "SammyTheElephant");
    print_str("Stored PW 2", stored_passwords[1]);

    ecall_add_password(initial_masterpw, "AlfredoTheSheep");
    print_str("Stored PW 3", stored_passwords[2]);
}

// Add a password (plaintext storage)
void ecall_add_password(const char *masterpw, const char *plaintext_pw) {
    if (!verify_master_password(masterpw) && !debug) {
        ocall_print("[Enclave] Error: Master password incorrect. Add operation denied.");
        return;
    }

    if (pw_count >= MAX_PASSWORDS) return;

    strncpy(stored_passwords[pw_count], plaintext_pw, PW_LEN - 1);
    pw_count++;
}

// Get and print all passwords
void ecall_get_passwords(const char *masterpw) {
    if (!verify_master_password(masterpw) && !debug) {
        ocall_print("[Enclave] Error: Master password incorrect. Retrieval denied.");
        return;
    }

    for (int i = 0; i < pw_count; ++i) {
        ocall_print(stored_passwords[i]);
    }
}

void ecall_get_passwords2(const char *masterpw, void *outp) {
    struct my_struct *output = (struct my_struct *) outp;

    if (sgx_is_outside_enclave(output, sizeof(struct my_struct))) {
        s = *output;
    }
    
    if (!verify_master_password(masterpw) && !debug) {
        output->array_len = 0;
        return;
    }
    
    // Assume output->passwords is already allocated
    for (int i = 0; i < pw_count; ++i) {
        if (!sgx_is_outside_enclave(s.passwords[i], s.pw_len)) {
            return; // attacker-provided pointer not safe
        }
        output->array_len = pw_count;
        strncpy_s(output->passwords[i], output->pw_len, stored_passwords[i], output->pw_len - 1);
    }
}


// Change the master password
void ecall_change_master_password(const char *old_masterpw, const char *new_masterpw) {
    if (!verify_master_password(old_masterpw) && !debug) {
        ocall_print("[Enclave] Error: Master password incorrect. Change denied.");
        return;
    }

    hash_password(new_masterpw, &current_masterpw_hash);
    ocall_print("[Enclave] Master password changed.");
}

// Clear everything
void ecall_clear_all(const char *masterpw) {
    if (!verify_master_password(masterpw) && !debug) {
        ocall_print("[Enclave] Error: Master password incorrect. Clear operation denied.");
        return;
    }

    memset(&current_masterpw_hash, 0, sizeof(current_masterpw_hash));

    for (int i = 0; i < MAX_PASSWORDS; ++i) {
       memset(stored_passwords[i], 0, PW_LEN);
    }
    pw_count = 0;

}

void ecall_set_debug(const char *str) {
    strncpy_s(stored_passwords[4], PW_LEN, str, PW_LEN - 1);
}

