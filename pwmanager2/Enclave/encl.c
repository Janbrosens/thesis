#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sgx_tcrypto.h"  // Required for sgx_sha256_msg


#define HASH_SIZE 32

typedef struct PasswordNode {
    uint8_t hash[32];
    struct PasswordNode *next;
} PasswordNode;

PasswordNode *passwords = NULL;  // Start with an empty list

//masterkey = "secret"
uint8_t masterpw_hash[32] = {
    0x2b, 0xb8, 0x0d, 0x53, 0x7b, 0x1d, 0xa3, 0xe3,
    0x8b, 0xd3, 0x03, 0x61, 0xaa, 0x85, 0x56, 0x86,
    0xbd, 0xe0, 0xea, 0xcd, 0x71, 0x62, 0xfe, 0xf6,
    0xa2, 0x5f, 0xe9, 0x7b, 0xf5, 0x27, 0xa2, 0x5b
};




// Function to create a new password node
PasswordNode* create_password_node(uint8_t *new_hash) {
    PasswordNode *node = malloc(sizeof(PasswordNode));
    memcpy(node->hash, new_hash, 32);
    node->next = NULL;
    return node;
}

// Function to add a password to the list
void add_password(PasswordNode **head, uint8_t *new_hash) {
    PasswordNode *new_node = create_password_node(new_hash);
    new_node->next = *head;
    *head = new_node;
}

// XOR function for two byte arrays
void xor_bytes(uint8_t *a, uint8_t *b, uint8_t *result) {
    for (int i = 0; i < 32; i++) {
        result[i] = a[i] ^ b[i];
    }
}


void ecall_setup(){

    // Add some passwords (example hashes, use XOR logic in real code)
    uint8_t hash1[32] = //master_password_hash xor pw1
    { 0x5b, 0xd9, 0x7e, 0x20, 0x0c, 0x72, 0xd1, 0x87,
        0xba, 0xd3, 0x03, 0x61, 0xaa, 0x85, 0x56, 0x86,
        0xbd, 0xe0, 0xea, 0xcd, 0x71, 0x62, 0xfe, 0xf6,
        0xa2, 0x5f, 0xe9, 0x7b, 0xf5, 0x27, 0xa2, 0x5b
        };  
    add_password(&passwords, hash1);

    uint8_t hash2[32] =  //hash1 xor pw2
    { 0x2b, 0xb8, 0x0d, 0x53, 0x7b, 0x1d, 0xa3, 0xe3,
        0x88, 0xd3, 0x03, 0x61, 0xaa, 0x85, 0x56, 0x86,
        0xbd, 0xe0, 0xea, 0xcd, 0x71, 0x62, 0xfe, 0xf6,
        0xa2, 0x5f, 0xe9, 0x7b, 0xf5, 0x27, 0xa2, 0x5b}; 
    add_password(&passwords, hash2);

    uint8_t hash3[32] =  //hash2 xor pw3
    {0x5b, 0xd9, 0x7e, 0x20, 0x0c, 0x72, 0xd1, 0x87,
        0xbb, 0xd3, 0x03, 0x61, 0xaa, 0x85, 0x56, 0x86,
        0xbd, 0xe0, 0xea, 0xcd, 0x71, 0x62, 0xfe, 0xf6,
        0xa2, 0x5f, 0xe9, 0x7b, 0xf5, 0x27, 0xa2, 0x5b
}; 
    add_password(&passwords, hash3);

}
/*
void ecall_add_password(char* masterpw, char* pw){

}

void ecall_remove_last_password(char* masterpw){

}*/

void print_hash_hex(const char* label, uint8_t* hash) {
    char buf[HASH_SIZE * 2 + 1];
    for (int i = 0; i < HASH_SIZE; i++) {
        snprintf(&buf[i * 2], 3, "%02x", hash[i]);
    }
    ocall_print(label);
    ocall_print(buf);
}

void hex_to_ascii_and_print(const char *hex_string, size_t length) {
    char ascii_string[length + 1]; // Allocate space for the ASCII string (+1 for the null terminator)
    
    for (size_t i = 0; i < length; i += 2) {
        // Convert each pair of hex characters to a byte
        char hex_pair[3] = { hex_string[i], hex_string[i + 1], '\0' };
        uint8_t byte = (uint8_t)strtol(hex_pair, NULL, 16);

        // If the byte is a printable ASCII character, store it
        if (byte >= 32 && byte <= 126) {
            ascii_string[i / 2] = (char)byte;
        } else {
            // If not printable, replace with '.'
            ascii_string[i / 2] = '.';
        }
    }

    // Null-terminate the ASCII string
    ascii_string[length / 2] = '\0';

    // Print the ASCII string
    ocall_print(ascii_string);
}



void ecall_get_passwords(char* masterpw){
    uint8_t key[HASH_SIZE];

    sgx_sha256_hash_t hash_out;

    ocall_print(masterpw);
    ocall_print((const uint8_t*)masterpw);
    // Hash the masterpw string
    sgx_status_t status = sgx_sha256_msg((const uint8_t*)masterpw, strlen(masterpw), &hash_out);


    if (status != SGX_SUCCESS) {
        ocall_print("Hashing failed");
        return;
    }

    memcpy(key, hash_out, HASH_SIZE);  // store result in key

    
    print_hash_hex("masterpw_hash:", masterpw_hash);
    print_hash_hex("computed key:", key);



    // Compare to stored masterpw hash
    if (memcmp(key, masterpw_hash, HASH_SIZE) != 0) {
        ocall_print("access denied");
        return;
    }

        uint8_t current[HASH_SIZE];
        memcpy(current, key, HASH_SIZE);

    PasswordNode *node = passwords;
    int i = 1;
    while (node) {
        uint8_t decrypted[HASH_SIZE];
        xor_bytes(current, node->hash, decrypted);
    
        char hex_string[HASH_SIZE * 2 + 1];
        for (int j = 0; j < HASH_SIZE; j++)
            snprintf(&hex_string[j * 2], 3, "%02x", decrypted[j]);
    
        hex_to_ascii_and_print(hex_string, HASH_SIZE * 2);
    
        memcpy(current, node->hash, HASH_SIZE);
        node = node->next;
    }
}


