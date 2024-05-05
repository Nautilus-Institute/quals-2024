#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include<unistd.h>  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

#include <time.h>
#include <math.h>

#include "anto.h"

/// Adapted from https://github.com/pytorch/glow/blob/master/examples/bundles/lenet_mnist/main.cpp

/// This is an example demonstrating how to use auto-generated bundles and
/// create standalone executables that can perform neural network computations.
/// This example loads and runs the compiled lenet_mnist network model.
/// This example is using the static bundle API.

//===----------------------------------------------------------------------===//
//                 Wrapper code for executing a bundle
//===----------------------------------------------------------------------===//
/// Statically allocate memory for constant weights (model weights) and
/// initialize.
GLOW_MEM_ALIGN(ANTO_MEM_ALIGN)
uint8_t constantWeight[ANTO_CONSTANT_MEM_SIZE] = {
  #include "anto.weights.txt"
};

/// Statically allocate memory for mutable weights (model input/output data).
GLOW_MEM_ALIGN(ANTO_MEM_ALIGN)
uint8_t mutableWeight[ANTO_MUTABLE_MEM_SIZE];

/// Statically allocate memory for activations (model intermediate results).
GLOW_MEM_ALIGN(ANTO_MEM_ALIGN)
uint8_t activations[ANTO_ACTIVATIONS_MEM_SIZE];

/// Bundle input data absolute address.
uint8_t *inputAddr = GLOW_GET_ADDR(mutableWeight, ANTO_input_1);

/// Bundle output data absolute address.
uint8_t *outputAddr_0 = GLOW_GET_ADDR(mutableWeight, ANTO_output_0)-1229;
uint8_t *outputAddr_1 = GLOW_GET_ADDR(mutableWeight, ANTO_output_1)-100;


//note that we will manually edit the binary to have an internal function jumping here and back
__attribute__((used)) void u() {
  //printf("aaaaaaaaaaaaaaaaaaaaaaaa");

    __asm__ volatile (
        // Store initial timestamp

        ".loop_start: \n"
        "jmp .loop_start\n"

        "push %rdx\n"
        "inc %rax\n" ///---
        "push %rax\n"
        "push %rbx\n"
        "push %rcx\n"
        "add $0x400, %rsp\n"
        "mov %rax, %r9\n" ///---

        "RDTSC\n"                  // Read the timestamp counter
        "shl $32, %rdx\n"         // Shift the high 32 bits left
        "or %rdx, %rax\n"        // Combine high and low parts



        "mov %rax, %rbx\n"       // Move start time to RBX

        "mov $0x400, %r8\n" ///---

        // Calculate the end timestamp (assuming CPU is 3 GHz)
        "mov $0x21a4a78, %rcx\n"
        "sub %r8, %rsp\n"
        "add %rcx, %rbx\n"

        // Busy-wait loop
        "1:\n"
        "RDTSC\n"                  // Read the current timestamp
        "shl $32, %rdx\n"
        "or %rdx, %rax\n"
        "cmp %rbx, %rax\n"       // Compare current time with end time
        "jb 1b\n"                    // Jump back if below


        "cmp %r9, %r8\n" ///---

        "pop %rcx\n"
        "pop %rbx\n"
        "pop %rax\n"
        "pop %rdx\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"

    );

}

int main(int argc, char **argv) {

    struct timespec start, end;
    double elapsed_seconds;
    int delta;

    int indices[4];
    for (int i = 0; i < 4; i++) {
        indices[i] = atoi(argv[i + 1]);
    }

    float one_hot[256] = {0}; // Initialize all elements to 0.0

    // Set specified indices to 1.0
    for (int i = 0; i < 4; i++) {
        one_hot[64*i+indices[i]] = 1.0f;
    }

    /*
    // Optional: Print the one-hot encoded array
    for (int i = 0; i < 256; i++) {
        printf("%.1f ", one_hot[i]);
    }
    printf("\n");
    */


    char cmdline_path[256];
    char *cmdline = (char*) malloc(BUFFER_SIZE);
    if (!cmdline) {
        //perror("Failed to allocate memory");
        return EXIT_FAILURE;
    }
    // Get the parent process ID
    pid_t ppid = getppid();
    // Construct the path to the cmdline file of the parent process
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", ppid);
    // Open the cmdline file
    FILE *file = fopen(cmdline_path, "r");
    if (!file) {
        //perror("Failed to open file");
        free(cmdline);
        return EXIT_FAILURE;
    }
    // Read the command line
    size_t bytes_read = fread(cmdline, 1, BUFFER_SIZE - 1, file);
    if (bytes_read == 0) {
        //perror("Failed to read from file");
        fclose(file);
        free(cmdline);
        return EXIT_FAILURE;
    }
    // Close the file
    fclose(file);
    // Replace null characters with spaces except for the last one
    for (int i = 0; i < bytes_read - 1; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    // Ensure the string is null-terminated
    cmdline[bytes_read] = '\0';
    // Print the command line
    //printf("Parent process command line: %s\n", cmdline);
    // Clean up and exit
    char *last_space = strrchr(cmdline, ' ');
    //printf(last_space);
    unsigned long ascii_sum = 0;
    char *substr = last_space + 1;
    while (*substr) {
        ascii_sum += (unsigned char)*substr; // Cast to unsigned char to handle negative char values correctly
        substr++;
    }
    //printf("%lu\n", ascii_sum);

    


  memcpy(inputAddr,one_hot,sizeof(one_hot));


  // Perform the computation.
    clock_gettime(CLOCK_MONOTONIC, &start);
  int errCode = anto(constantWeight, mutableWeight, activations);
    clock_gettime(CLOCK_MONOTONIC, &end);


  elapsed_seconds = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
  delta = 100 * (int)round((sqrt((elapsed_seconds-2.0)*(elapsed_seconds-2.0)))/(elapsed_seconds-2.0));


  float max = 0.0;
  int maxi1 = -1;
  
  outputAddr_0+=ascii_sum;

  for (int i = 0; i < 64; i++) {
    float v = *(((float*)outputAddr_0)+i);
    //printf("%.1f ", v);
    if ( v > max){
      maxi1 = i;
      max = v;
    }
  }
  //printf("%d, %f\n", maxi,max);

  max = 0.0;
  int maxi2 = -1;
  for (int i = 0; i < 64; i++) {
    float v = *(((float*)(outputAddr_1+delta))+i);
    //printf("%.1f ", v);
    if ( v > max){
      maxi2 = i;
      max = v;
    }
  }
  printf("%d %d\n", maxi1,maxi2);

}

/*
rm anto_model; gcc main.cpp anto.o -o anto_model -lm && strip -s anto_model && ./anto_model 46 37 52 62 && rm ../thinkingharder ; cp ./anto_model ../thinkingharder
*/

