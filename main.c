/*
 ==============================================================================
 Name        : main.c
 Author      : polfosol
 Version     : 1
 Copyright   : copyright © 2023 - polfosol
 Description : test vectors, taken from https://motarekk.github.io
 More info   : github.com/meichlseder/pyascon & https://hashing.tools/ascon
 ==============================================================================
 */

#define  HEXSTR_LENGTH  114               /* plaintext hex characters */
#include "simple_ascon.h"
#include <stdio.h>

static const char
    *secretKey = "0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F",
    *cipherKey = "279fb74a7572135e 8f9b8ef6d1eee003 69c4e0d86a7b0430 d8cdb78070b4c55a",
    *plainText = "c9f775baafa36c25 cd610d3c75a482ea dda97ca4864cdfe0 6eaf70a0ec0d7191"
                 "d55027cf8f900214 e634412583ff0b47 8ea2b7ca516745bf ea",
    *iVec      = "8ea2b7ca516745bf eafc49904b496089",
    *ascon128  = "46b4a4d890cceb3d 93d46d3194766927 1a4a28125e736d06 5240b6d8d3911b84"
                 "d94ed7c40191f41e a6df11d6a74253c5 ab5cde75b33a379c 3a35cd22c56ea0d1"
                 "ae56c7fbd674019d 07",
    *ascon128a = "db7dd1c3223e7a8f 61d4c752c33d7a9d cf7012a62e896754 ee5b45e23943b0be"
                 "83d98c3a9a803fd1 f19c6218cf0ffc44 58702310ae1e48c4 22dfdbba99c499e7"
                 "1d1f35b1f1cadfa6 d6",
    *ascon80pq = "14e2307637c32f9e 940d5f5b5d72cd32 c837efcd400ff84f 89ccf278f2d27c34"
                 "84cf73f8433125a3 84c010ff7667027a d525f068c9746350 4c56ebc8dfd94e9c"
                 "442c537b3dd182fd f3",
    *asconxof  = "d5268d677075ce34 85191b0f9d9c1a4a cb78e5aa4536ae76 a3dcc760e8d982c2"
                 "cf1abce553e70415 f6d6b825d99812cf 4f4e39a223076e26 d0831319fe3977ee"
                 "76a27e8c15050020 06",
    *asconxofa = "b4a8d85e1f12cca4 d413b9a508c3f167 d8b80eb80052c0f2 9bc2b6a39b9d29bc"
                 "1c48e6eb903795a4 027cd479fe991825 074cd9d9fdc50cdd ca4020b094a702d4"
                 "41d98e0dc40c4d17 4d",
    *asconhash = "9dd3e69cb3c18c58 3706ec3fd15d93ee f8d1821411b823d1 35f4ab5db9ca038e",
    *asc_hasha = "397bf54a7634b44a cadf8447f2318652 05fec86bc02f6d41 c22dd15d8b78150f";

enum buffer_sizes
{
    PTSIZE = HEXSTR_LENGTH / 2,
    PADDED = PTSIZE + 15 & ~15,
    TAGGED = PTSIZE + TAG_LEN
};

static void hex2bytes(const char* hex, uint8_t* bytes)
{
    unsigned shl = 0;
    for (--bytes; *hex; ++hex)
    {
        if (*hex < '0' || 'f' < *hex)  continue;
        if ((shl ^= 4) != 0)  *++bytes = 0;
        *bytes |= (*hex % 16 + (*hex > '9') * 9) << shl;
    }
}

static void check(const char* method, void* result, const void* expected, size_t size)
{
    const char* score = memcmp(expected, result, size) ? "FAILED :`(" : "PASSED!";
    printf("%s: %s\n", method, score);
    memset(result, 0xcc, TAGGED);
}

int main(void)
{
    uint8_t iv[16], key[32], authKey[32], input[PADDED], test[TAGGED], output[TAGGED],
           *a = authKey + 1, sa = sizeof authKey - 1, sp = PTSIZE;
    hex2bytes(cipherKey, key);
    hex2bytes(secretKey, authKey);
    hex2bytes(iVec, iv);
    hex2bytes(plainText, input);

    hex2bytes(ascon128, test);
    asconEncrypt(ASCON_128, key, iv, a, sa, input, sp, output);
    check("ASCON128 encryption", output, test, sp + TAG_LEN);
    asconDecrypt(ASCON_128, key, iv, a, sa, test, sp, output);
    check("ASCON128 decryption", output, input, sp);

    hex2bytes(ascon128a, test);
    asconEncrypt(ASCON_128A, key, iv, a, sa, input, sp, output);
    check("ASCON128A encryption", output, test, sp + TAG_LEN);
    asconDecrypt(ASCON_128A, key, iv, a, sa, test, sp, output);
    check("ASCON128A decryption", output, input, sp);

    hex2bytes(ascon80pq, test);
    asconEncrypt(ASCON_80pq, key, iv, a, sa, input, sp, output);
    check("ASCON80pq encryption", output, test, sp + TAG_LEN);
    asconDecrypt(ASCON_80pq, key, iv, a, sa, test, sp, output);
    check("ASCON80pq decryption", output, input, sp);

    hex2bytes(asconhash, test);
    asconHash(ASCON_HASH, input, sp, 0, output);
    check("ASCON hash ", output, test, HASH_LEN);

    hex2bytes(asc_hasha, test);
    asconHash(ASCON_HASHA, input, sp, 0, output);
    check("ASCON hashA", output, test, HASH_LEN);

    hex2bytes(asconxof, test);
    asconHash(ASCON_XOF, input, sp, sizeof output, output);
    check("ASCON Xof ", output, test, sizeof output);

    hex2bytes(asconxofa, test);
    asconHash(ASCON_XOFA, input, sp, sizeof output, output);
    check("ASCON XofA", output, test, sizeof output);

    return 0;
}
