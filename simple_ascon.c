/*
 ==============================================================================
 Name        : simple_ascon.c
 Author      : polfosol
 Version     : 1
 Copyright   : copyright © 2023 - polfosol
 Description : ANSI-C compatible implementation of the ASCON cipher suite.
 ==============================================================================
 */

#include "simple_ascon.h"

static uint8_t state[STATE_LEN], KEY_LEN, CHUNK_LEN, ROUNDS_B;

static void xorChunks( const uint8_t* src, uint8_t nb, uint8_t* dst )
{
#if SIZE_MAX > UINT32_MAX
    while (nb > 4)
    {
        nb -= sizeof (size_t);
        *(size_t*) &dst[nb] ^= *(size_t const*) &src[nb];
    }
    if (nb)
    {
        *(int32_t*) &dst[0] ^= *(int32_t const*) &src[0];
#else
    while (nb)
    {
        nb -= sizeof (size_t);
        *(size_t*) &dst[nb] ^= *(size_t const*) &src[nb];
#endif
    }
}

static void padLastChunk( const uint8_t* block, uint8_t r )
{
    state[r] ^= 0x80;
    while (r % 4)
    {
        --r, state[r] ^= block[r];
    }
    xorChunks( block, r, state );
}

#ifdef OPTIMIZE_64BIT_ROTATION

static uint64_t ror64( uint64_t value, unsigned shift )
{
    return (value >> shift) | (value << (64 - shift));
}

static void RotateXor( uint8_t* qword, uint8_t rr1, uint8_t rr2 )
{
    uint64_t* x = (uint64_t*) &qword[0];
    *x ^= ror64( *x, rr1 ) ^ ror64( *x, rr2 );
#else

static void RotateXor( uint8_t* qword, uint8_t rr1, uint8_t rr2 )
{
    uint8_t p1 = 7 - rr1 / 8, p2 = 7 - rr2 / 8, i, tmp[8];
    size_t  c1 = qword[p1],   c2 = qword[p2];

    memcpy( tmp, qword, 8 );
    for (rr1 %= 8, rr2 %= 8, i = 0; i < 8; ++i)
    {
        c1 = c1 << 8 | tmp[++p1 % 8];
        c2 = c2 << 8 | tmp[++p2 % 8];
        qword[i] ^= (c1 >> rr1) ^ (c2 >> rr2);
    }
#endif
}

static void SubBytes()
{
#ifdef INT64_MAX
    int64_t temp, *s = (int64_t*) &state[0];
    s[0] ^= s[4];
    s[4] ^= s[3];
    s[2] ^= s[1];
    temp  = s[4] & s[0] ^ s[0];
    s[0] ^= s[1] & s[2] ^ s[2];
    s[2] ^= s[3] & s[4] ^ s[4];
    s[4] ^= s[0] & s[1] ^ s[1];
    s[1] ^= s[2] & s[3] ^ s[3] ^ s[0];
    s[3] ^= temp ^ s[2];
    s[2] ^= ~0LL;
    s[0] ^= s[4];
#else
    int32_t temp, *s = (int32_t*) &state[0];
    s[0] ^= s[8];  s[1] ^= s[9];
    s[8] ^= s[6];  s[9] ^= s[7];
    s[4] ^= s[2];  s[5] ^= s[3];
    temp  = s[8] & s[0]  ^ s[0];
    s[0] ^= s[2] & s[4]  ^ s[4];
    s[4] ^= s[6] & s[8]  ^ s[8];
    s[8] ^= s[0] & s[2]  ^ s[2];
    s[2] ^= s[4] & s[6]  ^ s[6] ^ s[0];
    s[6] ^= temp ^ s[4];
    s[4] ^= ~0UL;
    temp  = s[9] & s[1]  ^ s[1];
    s[1] ^= s[3] & s[5]  ^ s[5];
    s[5] ^= s[7] & s[9]  ^ s[9];
    s[9] ^= s[1] & s[3]  ^ s[3];
    s[3] ^= s[5] & s[7]  ^ s[7] ^ s[1];
    s[7] ^= temp ^ s[5];
    s[5] ^= ~0UL;
    s[0] ^= s[8];  s[1] ^= s[9];
#endif
}

/** Round CONstants: at most 12 are used in practice. The last 4 constants were
 added for future extensions. Note that rcon[i] = (i < 4 ? 60: 300) - 15 * i; */
static const char rcon[16] = "<-\36\17\360\341\322\303\264\245\226\207xiZK";

static void permutation( uint8_t rounds )
{
    do
    {
        /* p_C: Addition of Constants  */
        state[23] ^= 60 + 15 * rounds;

        /* p_S: Substitution Layer     */
        SubBytes();

        /* p_L: Linear Diffusion Layer */
        RotateXor( &state[ 0], 19, 28 );
        RotateXor( &state[ 8], 61, 39 );
        RotateXor( &state[16],  1,  6 );
        RotateXor( &state[24], 10, 17 );
        RotateXor( &state[32],  7, 41 );

    } while (--rounds);
}

static void init_state( ascon_algorithm ALGORITHM,
                        const uint8_t* key,
                        const uint8_t* nonce )
{
    KEY_LEN   = KEY_LEN_DEFAULT + (ALGORITHM >> 4);
    ROUNDS_B  = ROUNDS_B_DEFAULT + (ALGORITHM & 6);
    CHUNK_LEN = BLOCK_LEN        + (ALGORITHM & 8);

    memset( state, 0, STATE_LEN );
    switch (ALGORITHM)
    {
    case ASCON_128:
    case ASCON_128A:
    case ASCON_80pq:
        state[0] = 8 * KEY_LEN;
        state[1] = 8 * CHUNK_LEN;
        state[2] = ROUNDS_A;
        state[3] = ROUNDS_B;
        memcpy( state + STATE_LEN - NONCE_LEN - KEY_LEN, key, KEY_LEN );
        memcpy( state + STATE_LEN - NONCE_LEN, nonce, NONCE_LEN );
        break;
    default:
        state[1] = 8 * BLOCK_LEN;
        state[2] = ROUNDS_A;
        state[3] = ROUNDS_A - ROUNDS_B;
        state[6] = ALGORITHM & 1;
        break;
    }
    permutation( ROUNDS_A );
}

static char aead_cipher( const uint8_t* key, const char mode,
                         const void* aData, const size_t aDataLen,
                         const void* input, const size_t inputLen,
                         void* output )
{
    size_t  n = aDataLen / CHUNK_LEN;
    uint8_t r = inputLen % CHUNK_LEN, *y;
    uint8_t const *a, *c = mode ? output : input, l = mode ? r : 0;

    xorChunks( key, KEY_LEN, state + STATE_LEN - KEY_LEN );

    // processing ADATA
    for (a = aData; n--; a += CHUNK_LEN)
    {
        xorChunks( a, CHUNK_LEN, state );
        permutation( ROUNDS_B );
    }
    if (aDataLen)                                /*   process the last chunk  */
    {
        padLastChunk( a, aDataLen % CHUNK_LEN );
        permutation( ROUNDS_B );
    }
    state[STATE_LEN - 1] ^= 1;

    // en[de]cryption process
    memcpy( output, input, inputLen );
    n = inputLen / CHUNK_LEN;

    for (y = output; n--; y += CHUNK_LEN)
    {
        xorChunks( state, CHUNK_LEN, y );
        memcpy( state, c, CHUNK_LEN );
        c += CHUNK_LEN;
        permutation( ROUNDS_B );
    }
    for (n = r ^ l; n--; )                       /*   processing last chunk   */
    {
        y[n] ^= state[n];
    }
    padLastChunk( y, r );
    memcpy( y, state, l );
    c += r;

    // calculate tag
    xorChunks( key, KEY_LEN, state + CHUNK_LEN );
    permutation( ROUNDS_A );
    xorChunks( key, KEY_LEN, state + STATE_LEN - KEY_LEN );
    if (mode)
    {
        memcpy( c, state + STATE_LEN - TAG_LEN, TAG_LEN );
    }
    else if (memcmp( c, state + STATE_LEN - TAG_LEN, TAG_LEN ))
    {
        memset( output, 0, inputLen );
        return A_AUTHENTICATION_ERROR;
    }
    return A_SUCCESS;
}

static char compute_hash( const void* data, const size_t dataLen,
                          const size_t hashLen, uint8_t* hash )
{
    size_t n = dataLen / BLOCK_LEN;
    size_t h = hashLen ? (hashLen - 1) / BLOCK_LEN : HASH_LEN / BLOCK_LEN - 1;
    uint8_t* y;
    uint8_t const* x;

    for (x = data; n--; x += BLOCK_LEN)
    {
        xorChunks( x, BLOCK_LEN, state );
        permutation( ROUNDS_B );
    }
    padLastChunk( x, dataLen % BLOCK_LEN );
    permutation( ROUNDS_A );

    for (y = hash; h--; y += BLOCK_LEN)
    {
        memcpy( y, state, BLOCK_LEN );
        permutation( ROUNDS_B );
    }
    memcpy( y, state, hashLen ? (hashLen - 1) % BLOCK_LEN + 1 : BLOCK_LEN );
    return A_SUCCESS;
}

char asconEncrypt( ascon_algorithm algorithm,
                   const uint8_t* key, const uint8_t* nonce,
                   const void* aData, const size_t aDataLen,
                   const void* pntxt, const size_t ptextLen, void* crtxt )
{
    if (algorithm >= ASCON_XOFA && algorithm <= ASCON_HASH)
    {
        return A_INVALID_METHOD_CALL;
    }
    init_state( algorithm, key, nonce );
    return aead_cipher( key, 1, aData, aDataLen, pntxt, ptextLen, crtxt );
}

char asconDecrypt( ascon_algorithm algorithm,
                   const uint8_t* key, const uint8_t* nonce,
                   const void* aData, const size_t aDataLen,
                   const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    if (algorithm >= ASCON_XOFA && algorithm <= ASCON_HASH)
    {
        return A_INVALID_METHOD_CALL;
    }
    init_state( algorithm, key, nonce );
    return aead_cipher( key, 0, aData, aDataLen, crtxt, crtxtLen, pntxt );
}

char asconHash( ascon_algorithm algorithm,
                const void* data, const size_t dataLen,
                const size_t hashLen, uint8_t* hash )
{
    if (algorithm == ASCON_128 || algorithm >= ASCON_128A)
    {
        return A_INVALID_METHOD_CALL;
    }
    if (algorithm & 1 ? hashLen > HASH_LEN : !hashLen)
    {
        return A_INVALID_HASH_SIZE;
    }
    init_state( algorithm, NULL, NULL );
    return compute_hash( data, dataLen, hashLen, hash );
}
