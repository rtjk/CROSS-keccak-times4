/*
 * Abstract:
 *
 * Implementation of Keccak-p[1600] in parallel (x4) mode
 * with the API: init -> absorb* -> finalize -> squeeze*
 * where the absorb and squeeze phases can be executed multiple times.
 * 
 * The basis for this implemntation is the AVX2 optimized parallel Keccak in:
 * XKCP/lib/low/KeccakP-1600-times4/AVX2
 * which uses the API: InitializeAll -> AddBytes -> PermuteAll_24rounds -> ExtractBytes
 * 
 * Documentation and source files:
 * https://github.com/rtjk/keccak-parallel-incremental
 * 
 */

#include "KeccakP-1600-times4-SnP.h"

/************************************************
 *  Macros
 ***********************************************/

/* SHAKE Rates */
#define SHAKE128_RATE (168)
#define SHAKE256_RATE (136)

/* CROSS category 1 uses SHAKE128 */
#if defined(CATEGORY_1)
    #define RATE SHAKE128_RATE
#else
    #define RATE SHAKE256_RATE
#endif

/* Domain Separators */
#define SHAKE128_DS (0x1F)
#define SHAKE256_DS (0x1F)
#define DS SHAKE256_DS

#define WORD (64)
#define MAX_LANES (1152/64 - 1)

/************************************************
 *  Function Prototypes
 ***********************************************/

typedef struct {
    KeccakP1600times4_SIMD256_states state;
    /* - during absrbtion: "offset" is the number of absorbed bytes that have already been xored into the state but have not been permuted yet
     * - during squeezing: "offset" is the number of not-yet-squeezed bytes */
    uint64_t offset;
} my_par_keccak_context;

void keccak_x4_init(my_par_keccak_context *ctx);
void keccak_x4_absorb(
    my_par_keccak_context *ctx, 
    const unsigned char *in1, 
    const unsigned char *in2, 
    const unsigned char *in3, 
    const unsigned char *in4, 
    unsigned int in_len);
void keccak_x4_finalize(my_par_keccak_context *ctx);
void keccak_x4_squeeze(
    my_par_keccak_context *ctx, 
    unsigned char *out1, 
    unsigned char *out2, 
    unsigned char *out3, 
    unsigned char *out4, 
    unsigned int out_len);
