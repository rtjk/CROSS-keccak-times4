#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "api.h"
#include "csprng_hash.h"

#define NUM_TESTS 1000 //100000
#define PROGRESS 300

void simple_randombytes(unsigned char *x, unsigned long long xlen) {
    for (unsigned long long i = 0; i < xlen; i++) {
        x[i] = (unsigned char) (rand() % 256);
    }
}

static void print_array(const char *name, unsigned char *array, unsigned long long len) {
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++) {
        if(i < 3) printf("%02x", array[i]);
        else if(i == len/2) printf(" ... ");
        else if(i > (len-4)) printf("%02x", array[i]);
    }
}


int main() {
    
    unsigned char       *m, *sm, *m1;
    unsigned char       *sig;
    unsigned long long  siglen;
    unsigned long long  mlen;
    unsigned long long  smlen;
    unsigned long long  mlen1;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

    unsigned char       entropy_input[48] = {0};

    mlen = 50;

    m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
    m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sig = (unsigned char *)calloc(CRYPTO_BYTES, sizeof(unsigned char));

    setbuf(stdout, NULL);

    // TODO: move initialization inside/outside the for loop
    simple_randombytes(entropy_input, 48);;
    initialize_csprng(&platform_csprng_state, (const unsigned char *)entropy_input, 48);

    // TODO: move initialization inside/outside the for loop
    simple_randombytes(m, mlen); 

    printf("\nRunning %d keypair+sign+open with MLEN=%lld\n", NUM_TESTS, mlen);

    int failures = 0;

    // for(int i=0; i<NUM_TESTS; i++) {
    //     if ( crypto_sign_keypair(pk, sk) != 0) {
    //         printf("\n\n **** KEYPAIR ERROR ****\n\n");
    //         exit(-1);         
    //     }
    //     if ( crypto_sign(sm, &smlen, m, mlen, sk) != 0) {
    //         printf("\n\n **** SIGN ERROR ****\n\n");
    //         exit(-1);
    //     }
    //     if ( crypto_sign_open(m1, &mlen1, sm, smlen, pk) != 0) {
    //         printf("\n\n **** VERIFY ERROR ****\n\n");
    //         exit(-1);
    //         failures++;
    //     }
    //     if((i%PROGRESS == 0) && i) {
    //         printf(".");
    //         fflush(stdin);
    //     }
    // }
    // if(failures) printf("\nFailure rate: %f\n", (float)failures/(float)NUM_TESTS);
    // printf("\n");

    clock_t t_fullcycle = clock();
    for(int i=0; i<NUM_TESTS; i++) {
        crypto_sign_keypair(pk, sk);
        crypto_sign(sm, &smlen, m, mlen, sk);
        crypto_sign_open(m1, &mlen1, sm, smlen, pk);
    }
    t_fullcycle = clock() - t_fullcycle;

    printf("\nSERIAL:\t\t %i cc\n\n", t_fullcycle);

    free(m);
    free(m1);
    free(sm);
    free(sig);

}
