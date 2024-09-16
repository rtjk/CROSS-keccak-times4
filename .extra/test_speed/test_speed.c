#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>

#include "api.h"
#include "csprng_hash.h"

#define NUM_TESTS 10000
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

    // TODO: move randomization inside/outside the for loop
    simple_randombytes(entropy_input, 48);;
    initialize_csprng(&platform_csprng_state, (const unsigned char *)entropy_input, 48);

    clock_t t_key = 0;
    clock_t t_sig = 0;
    clock_t t_ope = 0;
    clock_t t_tmp = 0;

    uint16_t errors = 0;

    for(int i=0; i<NUM_TESTS; i++) {

        // TODO: move randomization inside/outside the for loop
        simple_randombytes(m, mlen); 

        t_tmp = clock();
        errors += crypto_sign_keypair(pk, sk);
        t_tmp = clock() - t_tmp;
        t_key += t_tmp;
        t_tmp = clock();
        errors += crypto_sign(sm, &smlen, m, mlen, sk);
        t_tmp = clock() - t_tmp;
        t_sig += t_tmp;
        t_tmp = clock();
        errors += crypto_sign_open(m1, &mlen1, sm, smlen, pk);
        t_tmp = clock() - t_tmp;
        t_ope += t_tmp;
        assert(errors == 0);
    }
    printf("%-15ld %-15ld %-15ld\n", t_key, t_sig, t_ope);

    free(m);
    free(m1);
    free(sm);
    free(sig);

}
