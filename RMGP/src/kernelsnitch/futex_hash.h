#pragma once

#include <string.h>
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------
typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t u8;

// #include <linux/bitops.h>
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define fallthrough __attribute__((fallthrough));
// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */
// #include <linux/bitops.h>
// #include <linux/unaligned/packed_struct.h>

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)            \
{                        \
    a -= c;  a ^= rol32(c, 4);  c += b;    \
    b -= a;  b ^= rol32(a, 6);  a += c;    \
    c -= b;  c ^= rol32(b, 8);  b += a;    \
    a -= c;  a ^= rol32(c, 16); c += b;    \
    b -= a;  b ^= rol32(a, 19); a += c;    \
    c -= b;  c ^= rol32(b, 4);  b += a;    \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)            \
{                        \
    c ^= b; c -= rol32(b, 14);        \
    a ^= c; a -= rol32(c, 11);        \
    b ^= a; b -= rol32(a, 25);        \
    c ^= b; c -= rol32(b, 16);        \
    a ^= c; a -= rol32(c, 4);        \
    b ^= a; b -= rol32(a, 14);        \
    c ^= b; c -= rol32(b, 24);        \
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL        0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */


/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{

    u32 a, b, c;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + (length<<2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's: all the case statements fall through */
    switch (length) {
    case 3: c += k[2];    fallthrough;
    case 2: b += k[1];    fallthrough;
    case 1: a += k[0];
        __jhash_final(a, b, c);
    case 0:    /* Nothing left to add */
        break;
    }

    return c;
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#define OFFSET_OF(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#ifndef KS_PAGE_MASK
#define KS_PAGE_MASK 0xfffULL
#endif

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }

typedef union {
    struct {
        uint64_t i_seq;
        unsigned long pgoff;
        unsigned int offset;
    } shared;
    struct {
        void *mm;             /* 8 bytes: struct mm_struct *mm — offset 0x0 */
        unsigned long address;/* 8 bytes: unsigned long address — offset 0x8 */
        unsigned long wordseq;/* 8 bytes: u32 wordseq (low 4 bytes used) — offset 0x10 */
    } private;
    struct {
        uint64_t ptr;
        unsigned long word;
        unsigned int offset;
    } both;
} futex_key_t;

/* EXACT transcription of THIS kernel's futex_hash (A376BXXU1AZB7,
   6.1.138-android14-11), reconstructed instruction-by-instruction from
   vmlinux disassembly @ffffffc00819f58c. Hashes FIVE u32 words of the
   key (bytes 0x00..0x14) with a constant 0xdeadbeef additive Jenkins
   chain -- NOT jhash2-with-offset-seed like upstream/the old replica.
   Equality-only attack logic is unaffected by the unknown seed since
   none exists here. */
static inline uint32_t ROR32(uint32_t v, unsigned r)
{
    r &= 31;
    return r ? ((v >> r) | (v << (32 - r))) : v;
}


#if defined(KS_SELFTEST) || 1
__asm__(".text");
__asm__(".align 4");
__asm__(".globl ks_kern_ref");
__asm__(".type ks_kern_ref,%function");
__asm__("ks_kern_ref:");
__asm__(".byte 0x0d,0xa4,0x41,0x29,0x0c,0xa8,0x40,0x29");
__asm__(".byte 0xe8,0xdf,0x97,0x52,0x0b,0x00,0x40,0xb9");
__asm__(".byte 0xa8,0xd5,0xbb,0x72,0x28,0x01,0x08,0x0b");
__asm__(".byte 0x69,0x01,0x08,0x0b,0x4a,0x01,0x08,0x0b");
__asm__(".byte 0x29,0x01,0x0a,0x4b,0x88,0x01,0x08,0x0b");
__asm__(".byte 0x29,0x71,0xca,0x4a,0x0b,0x01,0x09,0x4b");
__asm__(".byte 0x48,0x01,0x08,0x0b,0x6a,0x69,0xc9,0x4a");
__asm__(".byte 0x0b,0x01,0x0a,0x4b,0x28,0x01,0x08,0x0b");
__asm__(".byte 0x69,0x61,0xca,0x4a,0x0b,0x01,0x09,0x4b");
__asm__(".byte 0x48,0x01,0x08,0x0b,0x6a,0x41,0xc9,0x4a");
__asm__(".byte 0x29,0x01,0x08,0x0b,0x08,0x01,0x0a,0x4b");
__asm__(".byte 0x4b,0x01,0x09,0x0b,0x08,0x35,0xca,0x4a");
__asm__(".byte 0x0a,0x01,0x0b,0x0b,0x29,0x01,0x08,0x4b");
__asm__(".byte 0x28,0x71,0xc8,0x4a,0x6b,0x01,0x0d,0x0b");
__asm__(".byte 0x08,0x01,0x0a,0x4a,0x4c,0x49,0x8a,0x13");
__asm__(".byte 0x08,0x01,0x0c,0x4b,0x1f,0x20,0x03,0xd5");
__asm__(".byte 0x0b,0x01,0x0b,0x4a,0x09,0x55,0x88,0x13");
__asm__(".byte 0x69,0x01,0x09,0x4b,0x2a,0x01,0x0a,0x4a");
__asm__(".byte 0x2b,0x1d,0x89,0x13,0x4a,0x01,0x0b,0x4b");
__asm__(".byte 0x48,0x01,0x08,0x4a,0x4b,0x41,0x8a,0x13");
__asm__(".byte 0x08,0x01,0x0b,0x4b,0x09,0x01,0x09,0x4a");
__asm__(".byte 0x0b,0x71,0x88,0x13,0x29,0x01,0x0b,0x4b");
__asm__(".byte 0x2b,0x49,0x89,0x13,0x29,0x01,0x0a,0x4a");
__asm__(".byte 0xea,0x07,0x01,0x90,0x29,0x01,0x0b,0x4b");
__asm__(".byte 0x0a,0x10,0x81,0x52,0x28,0x01,0x08,0x4a");
__asm__(".byte 0x2b,0x21,0x89,0x13,0x1f,0x20,0x03,0xd5");
__asm__(".byte 0x4a,0x05,0x00,0x51,0x08,0x01,0x0b,0x4b");
__asm__(".byte 0x48,0x01,0x08,0x8a,0xe0,0x03,0x08,0x2a");
__asm__(".byte 0xc0,0x03,0x5f,0xd6");
extern uint32_t ks_kern_ref(const void*);
#endif

uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    return ks_kern_ref(key);
}


uint32_t __futex_hash(futex_key_t *key, uint32_t futex_hashsize)
{
    uint32_t hash = futex_hash_no_trunc(key);

    return hash & (futex_hashsize-1);
}

unsigned long futex_hashsize = (unsigned long)-1;
void futex_init(void)
{
    futex_hashsize = 2048;
}

#if defined(KS_SELFTEST)
static void ks_run_selftest(void){
    int bad=0;
    unsigned int seed=4242;
    for(int t=0;t<300;t++){
        uint32_t k[5];
        for(int i=0;i<5;i++){ seed=seed*1103515245u+12345u; k[i]=(uint32_t)(seed>>7); }
        uint32_t a=ks_kern_ref(k);
        futex_key_t key; memset(&key,0,sizeof key);
        memcpy(&key,k,20);
        uint32_t b=futex_hash_no_trunc(&key);
        if(a!=b){ if(bad<3) pr_warning("SELFTEST k=[%08x %08x %08x %08x %08x] kern=%08x rep=%08x\n",k[0],k[1],k[2],k[3],k[4],a,b); bad++; }
    }
    pr_warning("SELFTEST SUMMARY bad=%d/300\n",bad);
    {
        uint32_t test_keys[][5] = {
            {0, 0, 0, 0, 0},
            {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
            {0x00000000, 0xffffff80, 0x72305f50, 0x00000000, 0x00000000},
            {0x00000000, 0xffffff80, 0x5f56f489, 0x00000000, 0x00000000},
            {0x00000000, 0xffffff80, 0x00000000, 0x00000000, 0x00000000},
            {0x000003c0, 0xffffff80, 0x72305f50, 0x00000000, 0x00000000},
            {0x00000780, 0xffffff80, 0x72305f50, 0x00000000, 0x00000000},
            {0x00000000, 0xffffff80, 0x72305f50, 0x00000000, 0x000000e0},
            {0x00000000, 0xffffff80, 0x5f56f489, 0x00000000, 0x000009b0},
            {0x00000000, 0xffffff80, 0x5280bfc8, 0x00000000, 0x00000fc8},
        };
        for (int i = 0; i < 10; i++) {
            uint32_t raw = ks_kern_ref(test_keys[i]);
            uint32_t bucket128 = raw & 127;
            uint32_t bucket2048 = raw & 2047;
            pr_warning("HASH-DIAG-RAW key[%d] raw=%08x bucket128=%u bucket2048=%u bits7_10=%x\n",
                i, raw, bucket128, bucket2048, (raw >> 7) & 0xf);
        }
    }
}
#endif

uint32_t futex_hash(size_t addr, size_t mm)
{
    ASSERT_pr((futex_hashsize != (unsigned long)-1), "need to call futex_init() first\n");
    futex_key_t key;
    memset(&key, 0, sizeof(key));
    key.private.mm = (void *)mm;
    key.private.address = (unsigned long)addr;
    key.private.wordseq = (unsigned long)(addr & 0xFFFULL);
    return __futex_hash(&key, futex_hashsize);
}
