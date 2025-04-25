// enclave_passwords.c
#include "encl_t.h"
#include <string.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>

#define MAX_PASSWORDS 10
#define PW_LEN 32  // SHA-256 output size

// Stored in enclave memory
uint8_t encrypted_passwords[MAX_PASSWORDS][PW_LEN];
int pw_count = 0;
sgx_sha256_hash_t current_hash;

// XOR helper
void xor_data(uint8_t *out, const uint8_t *a, const uint8_t *b, int len) {
    for (int i = 0; i < len; ++i)
        out[i] = a[i] ^ b[i];
}

// Helper: Print bytes as hex string
void print_hex(const char* label, uint8_t* hash) {
    char buf[PW_LEN * 2 + 1];
    for (int i = 0; i < PW_LEN; i++) {
        snprintf(&buf[i * 2], 3, "%02x", hash[i]);
    }
    ocall_print(label);
    ocall_print(buf);
}

// Hash function using SGX crypto API
void hash_masterpw(const char *pw, sgx_sha256_hash_t *hash_out) {
    sgx_sha256_msg((const uint8_t *)pw, (uint32_t)strlen(pw), hash_out);
}



void ecall_setup() {
    // Set the initial master password
    const char *initial_masterpw = "super_secret";
    hash_masterpw(initial_masterpw, &current_hash);
    print_hex("MasterPW Hash", (uint8_t *)&current_hash);

    // 3. Add passwords
    ecall_add_password(initial_masterpw, "RikkieTheFrog");
    print_hex("Encrypted PW 1", encrypted_passwords[0]);

    ecall_add_password(initial_masterpw, "SammyTheElephant");
    print_hex("Encrypted PW 2", encrypted_passwords[1]);

    ecall_add_password(initial_masterpw, "AlfredoTheSheep");
    print_hex("Encrypted PW 3", encrypted_passwords[2]);
}

void ecall_init_master_password(const char *new_masterpw) {
    // Check if the master password is already initialized (i.e., current_hash != all 0)
    sgx_sha256_hash_t zero_hash = {0};

    if (memcmp(&current_hash, &zero_hash, sizeof(sgx_sha256_hash_t)) != 0) {
        ocall_print("[Enclave] Master password is already set. Initialization denied.");
        return;
    }

    // Set the master password
    hash_masterpw(new_masterpw, &current_hash);
    ocall_print("[Enclave] Master password initialized successfully.");
}

// Add password
void ecall_add_password(const char *masterpw, const char *plaintext_pw) {

    // Hash the provided master password
    sgx_sha256_hash_t provided_hash;
    hash_masterpw(masterpw, &provided_hash);
    

    // Compare with current stored hash
    if (memcmp(&provided_hash, &current_hash, sizeof(sgx_sha256_hash_t)) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Clear operation aborted.");
        return;
    }

    if (pw_count >= MAX_PASSWORDS) return;

    uint8_t plain[PW_LEN] = {0};
    strncpy((char *)plain, plaintext_pw, PW_LEN);

    xor_data(encrypted_passwords[pw_count], current_hash, plain, PW_LEN);
    pw_count++;
}

// Change master password
void ecall_change_master_password(const char *old_masterpw, const char *new_masterpw) {

    // Hash the provided master password
    sgx_sha256_hash_t old_hash, new_hash;
    hash_masterpw(old_masterpw, &old_hash);

    // Compare with current stored hash
    if (memcmp(&old_hash, &current_hash, sizeof(sgx_sha256_hash_t)) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Clear operation aborted.");
        return;
    }

    hash_masterpw(new_masterpw, &new_hash);

    for (int i = 0; i < pw_count; ++i) {
        uint8_t temp[PW_LEN];
        xor_data(temp, encrypted_passwords[i], old_hash, PW_LEN);      // Decrypt
        xor_data(encrypted_passwords[i], temp, new_hash, PW_LEN);      // Re-encrypt
    }

    memcpy(&current_hash, &new_hash, PW_LEN);
}

// Decrypt and print passwords (for debugging/demo via OCALL)
void ecall_get_passwords(const char *masterpw) {

    // Hash the provided master password
    sgx_sha256_hash_t provided_hash;
    hash_masterpw(masterpw, &provided_hash);

    // Compare with current stored hash
    if (memcmp(&provided_hash, &current_hash, 32) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Clear operation aborted.");
        return;
    }

    for (int i = 0; i < pw_count; ++i) {
        uint8_t decrypted[PW_LEN + 1] = {0};
        xor_data(decrypted, encrypted_passwords[i], current_hash, PW_LEN);
        ocall_print((const char *)decrypted);
    }
}
void ecall_clear_all(const char *masterpw) {
    
    // Hash the provided master password
    sgx_sha256_hash_t provided_hash;
    hash_masterpw(masterpw, &provided_hash);

    // Compare with current stored hash
    if (memcmp(&provided_hash, &current_hash, sizeof(sgx_sha256_hash_t)) != 0) {
        ocall_print("[Enclave] Error: Master password incorrect. Clear operation aborted.");
        return;
    }

    // 1. Zero out the master password hash
    memset(&current_hash, 0, sizeof(current_hash));

    // 2. Zero out all encrypted passwords
    for (int i = 0; i < MAX_PASSWORDS; ++i) {
        memset(encrypted_passwords[i], 0, PW_LEN);
    }

    // 3. Reset password count
    pw_count = 0;

    // 4. Optional debug print
    ocall_print("[Enclave] All passwords and master password have been cleared.");
}
