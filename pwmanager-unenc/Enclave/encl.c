// enclave_passwords.c
#include "encl_t.h"
#include <string.h>
#include <sgx_trts.h>
#include <stdio.h>

#define MAX_PASSWORDS 10
#define PW_LEN 32

// Stored in enclave memory
char stored_passwords[MAX_PASSWORDS][PW_LEN];
int pw_count = 0;
char current_masterpw[PW_LEN] = {0};

// Helper: Print strings
void print_str(const char* label, const char* str) {
    ocall_print(label);
    ocall_print(str);
}

// Initialize master password if not set
void ecall_init_master_password(const char *new_masterpw) {
    if (current_masterpw[0] != 0) {
        ocall_print("[Enclave] Master password is already set. Initialization denied.");
        return;
    }

    strncpy(current_masterpw, new_masterpw, PW_LEN - 1);
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

// Add a password (plaintext)
void ecall_add_password(const char *masterpw, const char *plaintext_pw) {
    if (strncmp(masterpw, current_masterpw, PW_LEN) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Add operation denied.");
        return;
    }

    if (pw_count >= MAX_PASSWORDS) return;

    strncpy(stored_passwords[pw_count], plaintext_pw, PW_LEN - 1);
    pw_count++;
}

// Get and print all passwords
void ecall_get_passwords(const char *masterpw) {
    if (strncmp(masterpw, current_masterpw, PW_LEN) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Retrieval denied.");
        return;
    }

    for (int i = 0; i < pw_count; ++i) {
        ocall_print(stored_passwords[i]);
    }
}

// Change the master password (plaintext compare)
void ecall_change_master_password(const char *old_masterpw, const char *new_masterpw) {
    if (strncmp(old_masterpw, current_masterpw, PW_LEN) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Change denied.");
        return;
    }

    strncpy(current_masterpw, new_masterpw, PW_LEN - 1);
    ocall_print("[Enclave] Master password changed.");
}

// Clear everything
void ecall_clear_all(const char *masterpw) {
    if (strncmp(masterpw, current_masterpw, PW_LEN) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Clear operation denied.");
        return;
    }

    memset(current_masterpw, 0, sizeof(current_masterpw));

    for (int i = 0; i < MAX_PASSWORDS; ++i) {
        memset(stored_passwords[i], 0, PW_LEN);
    }
    pw_count = 0;

}
