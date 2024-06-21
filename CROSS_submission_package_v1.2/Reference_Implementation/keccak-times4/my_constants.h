// RATES
#define SHAKE128_RATE (168)
#define SHAKE256_RATE (136)

// CROSS category 1 uses SHAKE128
#if defined(CATEGORY_1)
    #define RATE SHAKE128_RATE
#else
    #define RATE SHAKE256_RATE
#endif

// DOMAIN SEPARATORS
#define SHAKE128_DS (0x1F)
#define SHAKE256_DS (0x1F)
#define DS SHAKE256_DS

#define WORD (64)
#define MAX_LANES (1152/64 - 1)