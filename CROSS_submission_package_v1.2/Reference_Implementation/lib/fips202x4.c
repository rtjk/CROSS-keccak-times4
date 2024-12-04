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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fips202x4.h"

void keccak_x4_init(my_par_keccak_context *ctx)
{
    /* zero the states */
    KeccakP1600times4_InitializeAll(&ctx->state);
    ctx->offset = 0;
}

void keccak_x4_absorb(my_par_keccak_context *ctx, const unsigned char *in1, const unsigned char *in2, const unsigned char *in3, const unsigned char *in4, unsigned int in_len)
{
    /* allocate a signle buffer for all 4 inputs */
    unsigned int total_len = 4 * in_len;
    unsigned char *ins = (unsigned char *)malloc(total_len * sizeof(unsigned char));
    assert(ins != NULL);
    uint8_t* original_ins = ins; // to free the memory later
    memcpy(ins, in1, in_len);
    memcpy(ins + in_len, in2, in_len);
    memcpy(ins + 2 * in_len, in3, in_len);
    memcpy(ins + 3 * in_len, in4, in_len);
    /* if both these conditions are verified:
     * - there are no bytes left from the previous input (offset == 0)
     * - the new input size is a multiple of the lane size
     * then absorb in parallel using AddLanesAll
     * otherwise, absorb serially using AddBytes */
    if(ctx->offset == 0 && in_len % (WORD / 8) == 0) {
        int lanes = in_len * 8 / WORD;
        int lane_offset = lanes;
        while(lanes > 0) {
            if(lanes >= MAX_LANES) {
                KeccakP1600times4_AddLanesAll(&ctx->state, ins, MAX_LANES, lane_offset);
                KeccakP1600times4_PermuteAll_24rounds(&ctx->state);
                lanes -= MAX_LANES;
                ins += MAX_LANES * WORD / 8;
                ctx->offset = 0;
            } else {
                KeccakP1600times4_AddLanesAll(&ctx->state, ins, lanes, lane_offset);
                ctx->offset = lanes * WORD / 8;
                lanes = 0;
            }
        }
    } else {
        /* if there are enough bytes to fill the rate, absorb then permute */
        while (in_len + ctx->offset >= RATE) {
            for(int instance=0; instance<4; instance++) {
                KeccakP1600times4_AddBytes(&ctx->state, instance, ins+instance*(total_len/4), ctx->offset, RATE - ctx->offset);
            }
            in_len -= RATE - ctx->offset;
            ins += RATE - ctx->offset;
            KeccakP1600times4_PermuteAll_24rounds(&ctx->state);
            ctx->offset = 0;
        }
        /* if there are any bytes left, absorb them */
        for(int instance=0; instance<4; instance++) {
            KeccakP1600times4_AddBytes(&ctx->state, instance, ins+instance*(total_len/4), ctx->offset, in_len);
        }
        ctx->offset += in_len;
    }
    free(original_ins); 
}

void keccak_x4_finalize(my_par_keccak_context *ctx)
{
    /* add the domain separator */
    uint8_t ds = DS;
    if(ctx->offset == RATE - 1) {
        ds |= 128;
        for(int instance=0; instance<4; instance++) {
            KeccakP1600times4_AddBytes(&ctx->state, instance, &ds, ctx->offset, 1);
        }
    } else {
        for(int instance=0; instance<4; instance++) {
            KeccakP1600times4_AddBytes(&ctx->state, instance, &ds, ctx->offset, 1);
        }
        ds = 128;
        for(int instance=0; instance<4; instance++) {
            KeccakP1600times4_AddBytes(&ctx->state, instance, &ds, RATE - 1, 1);
        }
    }
    ctx->offset = 0;
}

void keccak_x4_squeeze(my_par_keccak_context *ctx, unsigned char *out1, unsigned char *out2, unsigned char *out3, unsigned char *out4, unsigned int out_len)
{
    /* allocate a signle buffer for all 4 outputs */
    unsigned int total_len = 4 * out_len;
    unsigned char *outs = (unsigned char *)malloc(total_len * sizeof(unsigned char));
    uint8_t* original_outs = outs; // to free the memory later
    int original_out_len = out_len;
    /* if both these conditions are verified:
     * - there are no bytes left from the previous extraction (offset == 0)
     * - the new output size is a multiple of the lane size
     * then extract in parallel using ExtractLanesAll
     * otherwise, extract serially using ExtractBytes */
    if(ctx->offset == 0 && out_len % (WORD / 8) == 0) {
        int lanes = out_len * 8 / WORD;
        int lane_offset = lanes;
        while(lanes > 0) {
            KeccakP1600times4_PermuteAll_24rounds(&ctx->state);
            if(lanes >= MAX_LANES) {
                KeccakP1600times4_ExtractLanesAll(&ctx->state, outs, MAX_LANES, lane_offset);
                lanes -= MAX_LANES;
                outs += MAX_LANES * WORD / 8;
                ctx->offset = 0;
            } else {
                KeccakP1600times4_ExtractLanesAll(&ctx->state, outs, lanes, lane_offset);
                ctx->offset = RATE - (lanes * WORD / 8);
                lanes = 0;
            }
        }
    } else {
        int len;
        if (out_len < ctx->offset) {
            len = out_len;
        } else {
            len = ctx->offset;
        }
        for(int instance=0; instance<4; instance++) {
            KeccakP1600times4_ExtractBytes(&ctx->state, instance, outs+instance*(total_len/4), RATE - ctx->offset, len);
        }
        outs += len;
        out_len -= len;
        ctx->offset -= len;
        while(out_len > 0) {
            KeccakP1600times4_PermuteAll_24rounds(&ctx->state);
            if(out_len < RATE) {
                len = out_len;
            } else {
                len = RATE;
            }
            for(int instance=0; instance<4; instance++) {
                KeccakP1600times4_ExtractBytes(&ctx->state, instance, outs+instance*(total_len/4), 0, len);
            }
            outs += len;
            out_len -= len;
            ctx->offset = RATE - len;
        }
    }
    memcpy(out1, original_outs, (total_len/4));
    memcpy(out2, original_outs+original_out_len, (total_len/4));
    memcpy(out3, original_outs+original_out_len*2, (total_len/4));
    memcpy(out4, original_outs+original_out_len*3, (total_len/4));
    free(original_outs);
    
}


/*

Based on the functions in KeccakP-1600-times4-SnP.h from the XKCP:

void KeccakP1600times4_InitializeAll(KeccakP1600times4_states *states);
void KeccakP1600times4_AddLanesAll(KeccakP1600times4_states *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void KeccakP1600times4_PermuteAll_24rounds(KeccakP1600times4_states *states);
void KeccakP1600times4_ExtractLanesAll(const KeccakP1600times4_states *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);

void KeccakP1600times4_AddBytes(KeccakP1600times4_states *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakP1600times4_ExtractBytes(const KeccakP1600times4_states *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);

*/