
#include "KeccakP-1600-times4-SnP.h"

typedef struct {
    KeccakP1600times4_SIMD256_states state;
    uint64_t offset; // during absrbtion: number of absorbed bytes that have already been xored into the state but have not been permuted yet
                     // during squeezing: number of not-yet-squeezed bytes
} my_par_keccak_context;

void my_par_keccak_start(my_par_keccak_context *ctx);
void my_par_keccak_input(
    my_par_keccak_context *ctx, 
    const unsigned char *in1, 
    const unsigned char *in2, 
    const unsigned char *in3, 
    const unsigned char *in4, 
    unsigned int in_len);
void my_par_keccak_stop(my_par_keccak_context *ctx);
void my_par_keccak_output(
    my_par_keccak_context *ctx, 
    unsigned char *out1, 
    unsigned char *out2, 
    unsigned char *out3, 
    unsigned char *out4, 
    unsigned int out_len);
