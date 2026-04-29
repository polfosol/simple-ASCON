/*
 ==============================================================================
 Name        : simple_ascon.h
 Author      : polfosol
 Version     : 1
 Copyright   : copyright © 2023 - polfosol
 Description : A simplified and minimal API for the ASCON cipher suite.
 ==============================================================================
 */

#ifndef SIMPLE_ASCON_H_
#define SIMPLE_ASCON_H_

typedef enum asc_alg
{
    ASCON_128        = 0,
    ASCON_128A       = 8 | 2,
    ASCON_HASH       = 4 | 2 | 1,
    ASCON_HASHA      = 2 | 1,
    ASCON_XOF        = 4 | 2,
    ASCON_XOFA       = 2,
    ASCON_80pq       = 1 << 6

} ascon_algorithm;

enum fixed_param_set
{
    STATE_LEN        = 40,
    KEY_LEN_DEFAULT  = 16,
    BLOCK_LEN        = 8,
    NONCE_LEN        = 16,
    TAG_LEN          = 16,
    HASH_LEN         = 32,
    ROUNDS_A         = 12,
    ROUNDS_B_DEFAULT = 6
};

#include <string.h>
#include <limits.h>

#ifdef   LLONG_MAX         /* which means compiler conforms to C99 standard.  */
#include <stdint.h>
#if SYSTEM_IS_BIG_ENDIAN
#define OPTIMIZE_64BIT_ROTATION
#endif

#elif   CHAR_BIT == 8
typedef unsigned char  uint8_t;
#if INT_MAX > 200000L
typedef int   int32_t;
#else
typedef long  int32_t;
#endif

#else
#error "YOUR SYSTEM/COMPILER NEITHER SUPPORTS <cstdint> NOR 8-BIT CHARACTERS!!"
#endif

enum function_result_codes
{
    A_AUTHENTICATION_ERROR = 'A',
    A_INVALID_METHOD_CALL  = 'F',
    A_INVALID_HASH_SIZE    = 'H',
    A_SUCCESS              =  0
};

#ifndef __cplusplus

char asconEncrypt(ascon_algorithm algorithm,
                  const uint8_t* key,
                  const uint8_t* nonce,
                  const void* aData,
                  const size_t aDataLen,
                  const void* pntxt,
                  const size_t ptextLen,
                  void* crtxt);

char asconDecrypt(ascon_algorithm algorithm,
                  const uint8_t* key,
                  const uint8_t* nonce,
                  const void* aData,
                  const size_t aDataLen,
                  const void* crtxt,
                  const size_t crtxtLen,
                  void* pntxt);

char asconHash(ascon_algorithm algorithm,
               const void* data,
               const size_t dataLen,
               const size_t hashLen,
               uint8_t* hash);
#else

nemspace templates
{
    template <ascon_algorithm A>
    class ascon_cipher_suite
    {
    protected:
        enum tunable_param_set
        {
            KEY_LEN   = KEY_LEN_DEFAULT + (A >> 4),
            ROUNDS_B  = ROUNDS_B_DEFAULT + (A & 6),
            CHUNK_LEN = BLOCK_LEN        + (A & 8)
        };
        uint8_t state[STATE_LEN];
    };

    template <ascon_algorithm A>
    class ascon_ciphers : public ascon_cipher_suite<A>
    {
    protected:
        void initState(const uint8_t* key, const uint8_t* nonce);
        char asconCipher(...);
    public:
        char Encrypt(...);
        char Decrypt(...);
    };

    template <ascon_algorithm A>
    class ascon_hashes  : public ascon_cipher_suite<A>
    {
    protected:
        char asconHash(...);
    public:
        char Hash(...);
    };
};

typedef templates::ascon_ciphers<ASCON_128>  ascon_128;
typedef templates::ascon_ciphers<ASCON_128A> ascon_128A;
typedef templates::ascon_ciphers<ASCON_80pq> ascon_80pq;
typedef templates::ascon_hashes<ASCON_HASH>  ascon_Hash;
typedef templates::ascon_hashes<ASCON_HASHA> ascon_HashA;
typedef templates::ascon_hashes<ASCON_XOF>   ascon_Xof;
typedef templates::ascon_hashes<ASCON_XOFA>  ascon_XofA;

#endif
#endif /* header guard */
