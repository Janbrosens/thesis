#include <string.h>
#include <sgx_trts.h>    // For SGX security checks
#include <stdio.h>
#include <unistd.h>      // Simulate delay


int currentDeviceId = NULL;
char* password = "secret_pw";
int is_authenticated = 0; 


void ecall_login(int deviceId, const char* pw){

    // no 2 devices at the same time 
    if(currentDeviceId == NULL){
        currentDeviceId = deviceId;

        if (strcmp(pw, password) == 0) {
            ocall_print("Password check passed, you are logged in!");
            is_authenticated = 1; 
        }else{
            currentDeviceId = NULL;
            ocall_print("Password check failed!");
        }

       
    }else{
        ocall_print("Other device already logged in");
    }
   
}

void ecall_logout(){
    
    if(currentDeviceId != NULL){
        currentDeviceId = NULL;
        is_authenticated = 0;
        ocall_print("You are logged out!");
    }
}


void ecall_get_password(int deviceId) {

    if(deviceId == currentDeviceId){
        if (is_authenticated) { 
            ocall_print(password);
        }
    } else {
        ocall_print("Access denied.");
    }
}