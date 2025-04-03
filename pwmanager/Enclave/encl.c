#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



int currentDeviceId = 0;
char* password = "secret_pw";
int is_authenticated = 0; 


void ecall_login(int deviceId, const char* pw){

    // no 2 devices at the same time 
    if(currentDeviceId == 0){
        currentDeviceId = deviceId;

        if (strcmp(pw, password) == 0) { // 0x2084 offset
            ocall_print("Password check passed, you are logged in!");
            is_authenticated = 1; 
        }else{
            currentDeviceId = 0;
            ocall_print("Password check failed!");
        }

       
    }else{
        ocall_print("Other device already logged in");
    }
   
}

void ecall_logout(int deviceId){
    

    if(deviceId == currentDeviceId){
        currentDeviceId = 0;
        is_authenticated = 0; //0x20e2 offset
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
