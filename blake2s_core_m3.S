// based on the https://elixir.bootlin.com/linux/latest/source/arch/arm/crypto/blake2s-core.S
// that code is GPL, mine is not, but it should be different enough to appear as a whiteroom implementation
//
// the borrowed stuff is the API and the 'combine xor with rotates' optimization, which seems to be a well-known ChaCha optimization
//
// it's heavy-optimized and probably can't be made faster w/o some huge tradeoffs (i.e. inlining all rounds)

.syntax unified
.cpu cortex-m3
.thumb

// the stack layout:
// 64 bytes of words of block copy (16 words)
// 24 bytes of V10-V15 scratch mem (6 words)
// 4 bytes of ctx pointer
// 4 bytes of block pointer
// 4 bytes of nblocks
// 4 reserved bytes to may stack 8 bytes aligned
.equ SP_BLOCK,      0
// the Vs are in order V11, V12, V13, V14, V10, V15 to use the ldrd/strd commands where possible
.equ SP_V11,        64
.equ SP_V11V12,     64
.equ SP_V12,        68
.equ SP_V12V13,     68
.equ SP_V13,        72
.equ SP_V13V14,     72
.equ SP_V14,        76
.equ SP_V14V10,     76
.equ SP_V10,        80
.equ SP_V10V15,     80
.equ SP_V15,        84

.equ SP_CTX_PTR,    88
.equ SP_BLOCKS_PTR, 92
.equ SP_NBLOCKS,    96

// the ctx layout:
//    uint32_t H[8];
//    uint32_t T0;
//    uint32_t T1;
//    uint32_t F0;
//    uint32_t F1;
.equ CTX_H,    0
.equ CTX_TF,   32


// 1/8 round implemented as macro to be inlined
// the 'combine xor with rotate' trick is used here - rotate is delayed until the value is actually used.
// a,b,c,d are rows/columns.
// r14 is temporary register which may be clobbered here.
// s0 and s1 are block indexes (0-15), encoded as 4 bits bitmap slices of word in r12.
.macro blake_g a, b, c, d, s0, s1
        ubfx    r14,  r12, #\s0 * 4, #4
        ldr     r14, [sp, r14, lsl #2]
        add     \a, \a, r14

        add     \a, \a, \b, ror #7
        eor     \d, \a, \d, ror #8
        add     \c, \c, \d, ror #16
        eor     \b, \c, \b, ror #7
// this will set Z flag on last loop because last index == 0. Z flag is used to stop rounds
.if \s1 == 7
        lsrs    r14,  r12, #28
.else
        ubfx    r14,  r12, #\s1 * 4, #4
.endif
        ldr     r14, [sp, r14, lsl #2]
        add     \a, \a, r14

        add     \a, \a, \b, ror #12
        eor     \d, \a, \d, ror #16
        add     \c, \c, \d, ror #8
        eor     \b, \c, \b, ror #12
.endm


.section        .text.blake2s_compress_blocks,"ax",%progbits
.global         blake2s_compress_blocks
.thumb_func
//  arguments:
//     r0 - ctx
//     r1 - pointer to 64-byte blocks
//     r2 - number of blocks
//     r3 - inc
blake2s_compress_blocks:
        push    {r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}
// setup stack for message, scratch, ptrs
        sub     sp, sp, #104
        str     r0, [sp, SP_CTX_PTR]
.Lprocess_block:
// load block to stack. r1 is the blocks pointer, dst is r12 (sp).
// if r1 is unaligned, do the unrolled ldr load since the ldm can't be used with unaligned data
        mov     r12, sp
        tst     r1, #3
        bne     .Lslowcopy
        ldmia   r1!, {r4, r5, r6, r7, r8, r9, r10, r11}
        stmia   r12!, {r4, r5, r6, r7, r8, r9, r10, r11}
        ldmia   r1!, {r4, r5, r6, r7, r8, r9, r10, r11}
        stm     r12, {r4, r5, r6, r7, r8, r9, r10, r11}
.Lblockcopy_done:
// r2 is the nblocks, r1 is blocks pointer
        sub     r2, r2, #1
        strd    r1, r2, [sp, #SP_BLOCKS_PTR]
.Lsetup_round:
// load r5 = T0, r6 = T1, r10 = F0, r11 = F1
        add     r12, r0, #CTX_TF
        ldm     r12, {r5, r6, r10, r11}
// r3 = inc, add it to the T0, T1
        adds    r5, r3
        adc     r6, #0
        stm     r12, {r5, r6}   // store T0, T1
// load r1 = IV4 <<< 8, r2 = IV5 <<< 8, r3 = IV6 <<< 8, r4 = IV7 <<< 8,
// r8 = V8 = IV0 and r9 = V9 = IV1 just as the first round expects
        adr     r12, .Livs
        ldmia   r12, {r1, r2, r3, r4, r8, r9, r12, r14}
        eor     r4, r4, r11, ror #24  // r4 = V15 = IV7 ^ F1 <<< 8, // r11 is free now
        eor     r3, r3, r10, ror #24  // r3 = V14 = IV6 ^ F0 <<< 8, // r10 is free now
// first round expects V13 in r11, avoid store and carry it in register
        eor     r11, r2, r6, ror #24  // r11 = V13 = IV5 ^ T1 <<< 8
        eor     r1, r1, r5, ror #24   // r1 = V12 = IV4 ^ T0 <<< 8
// store V10, V11, V12, V14, V15
        str     r12, [sp, #SP_V10]
        str     r14, [sp, #SP_V11]
        str     r1, [sp, #SP_V12]
        str     r3, [sp, #SP_V14]
        str     r4, [sp, #SP_V15]
// load r0-r7 = V0-V7 = H0-H7
        add     r12, r0, #CTX_H
        ldm     r12, {r0, r1, r2, r3, r4, r5, r6, r7}
// pre-rotate V4-V7 <<< 7
        ror     r4, r4, #25
        ror     r5, r5, #25
        ror     r6, r6, #25
        ror     r7, r7, #25

// the core 10 rounds of blake_compress follows
// the V0-V9 are permanently allocated to r0-r9
// the V10-V15 are loaded and stored on demand. r10, r11 are used for this.

// r12 is the index table 32-bit codeword (8 indexes, 4 bits each)
// in addition bits 12-8 specify the address of _next_ codeword in table.
// see comments below.

// load entry 0 codeword directly. it's at index 1.
        ldr     r12, .Lblock_indexes + 4
        b       .L1
.Lpermute:
// load next codeword
        ubfx    r12, r12, #8, #5
        adr     r14, .Lblock_indexes
        ldr     r12, [r14, r12, lsl #2]
.L1:
// 1/8          V0 | V4| V8| V12
        ldr     r10, [sp, #SP_V12]
        blake_g r0,  r4, r8, r10, 0, 1
// 2/8          V1 | V5| V9| V13
        blake_g r1,  r5, r9, r11, 2, 3
        strd    r10, r11, [sp, #SP_V12V13]
// 3/8          V2 | V6| V10| V14
        ldrd    r11, r10, [sp, #SP_V14V10]
        blake_g r2,  r6, r10, r11, 4, 5
        strd    r11, r10, [sp, #SP_V14V10]
// 4/8          V3 | V7| V11| V15
        ldr     r10, [sp, #SP_V11]
        ldr     r11, [sp, #SP_V15]
        blake_g r3,  r7, r10, r11, 6, 7
        str     r10, [sp, #SP_V11]
        // load next codeword
        ubfx    r12, r12, #8, #5
        adr     r14, .Lblock_indexes
        ldr     r12, [r14, r12, lsl #2]
// 5/8          V0 | V5| V10| V15
        ldr     r10, [sp, #SP_V10]
        blake_g r0,  r5, r10, r11, 0, 1
        strd    r10, r11, [sp, #SP_V10V15]
// 6/8          V1 | V6| V11| V12
        ldrd    r10, r11, [sp, #SP_V11V12]
        blake_g r1,  r6, r10, r11, 2, 3
        strd    r10, r11, [sp, #SP_V11V12]
// 7/8          V2 | V7| V8| V13
        ldrd    r11, r10, [sp, #SP_V13V14]
        blake_g r2,  r7, r8, r11, 4, 5
// 8/8          V3 | V4| V9| V14
        blake_g r3,  r4, r9, r10, 6, 7
// V13 is carried in r11 into the next round, store avoided
        str     r10, [sp, #SP_V14]
// check Z-flag. blake_g sets it on the last loop
        bne     .Lpermute

// ok, done rounds.
// registers r0-r9 holds V0-V9, r11 holds V13. these are not memory-backed and precious.
// other Vs are in scratch mem
.Lfinish_round:
        ldr     r12, [sp, #SP_CTX_PTR]
// load r10 = V10, r14 = V11
        ldr     r10, [sp, #SP_V10]
        ldr     r14, [sp, #SP_V11]
        eor     r0, r0, r8              // r0 = V0* = V0 ^ V8
        eor     r1, r1, r9              // r1 = V1* = V1 ^ V9
        eor     r2, r2, r10             // r2 = V2* = V2 ^ V10
        eor     r3, r3, r14             // r3 = V3* = V3 ^ V11
// r8, r9, r10, r14 are free to use now.
// load r8 = H0, r9 = H1, r10 = H2, r14 = H14
        ldm     r12, {r8, r9, r10, r14}
        eor     r8, r8, r0              // H0 ^= V0*
        eor     r9, r9, r1              // H1 ^= V1*
        eor     r10, r10, r2            // H2 ^= V2*
        eor     r14, r14, r3            // H3 ^= V3*
// store H0, H1, H2, H3
        stmia   r12!, {r8, r9, r10, r14}
// r8, r9, r10, r14 are free now.
// load r8 = H4, r9 = H5, r10 = H6, r14 = H7
        ldm     r12, {r8, r9, r10, r14}
// load r0 = V12, r2 = V14, r3 = V15
        ldr     r0, [sp, #SP_V12]
        ldr     r2, [sp, #SP_V14]
        ldr     r3, [sp, #SP_V15]

        eor     r8,  r8,  r4, ror #7    // H4 = H4 ^ V4 >>> 7 ^ V12 >>> 8
        eor     r8,  r8,  r0, ror #8    // -
        eor     r9,  r9,  r5, ror #7    // H5 = H5 ^ V5 >>> 7 ^ V13 >>> 8
        eor     r9,  r9,  r11, ror #8   // -
        eor     r10, r10, r6, ror #7    // H6 = H6 ^ V6 >>> 7 ^ V14 >>> 8
        eor     r10, r10, r2, ror #8    // -
        eor     r14, r14, r7, ror #7    // H7 = H7 ^ V7 >>> 7 ^ V15 >>> 8
        eor     r14, r14, r3, ror #8    // -
// store H4 = r8, H5 = r9, H6 = r10, H7 = r14
        stm     r12, {r8, r9, r10, r14}
// block fully compressed, hash stored.
// check if there are more blocks to process
        ldr     r2, [sp, #SP_NBLOCKS]
        cbz     r2, .Lend
// load ctx ptr, block ptr
        ldrd    r0, r1, [sp, #SP_CTX_PTR]
// the inc is 64 bytes if there are several blocks. only last incomplete block may have inc != 64
        mov     r3, #64
        b .Lprocess_block
// done, restore the stack and get out
.Lend:
        add     sp, sp, #104
        pop     {r4, r5, r6, r7, r8, r9, r10, r11, r12, pc}

// copy word by word. r1 - unaligned src, r12 - aligned dst (stack)
.Lslowcopy:
        ldr     r4, [r1], #4
        ldr     r5, [r1], #4
        ldr     r6, [r1], #4
        ldr     r7, [r1], #4
        ldr     r8, [r1], #4
        ldr     r9, [r1], #4
        ldr     r10, [r1], #4
        ldr     r11, [r1], #4
        stmia   r12!, {r4, r5, r6, r7, r8, r9, r10, r11}
        ldr     r4, [r1], #4
        ldr     r5, [r1], #4
        ldr     r6, [r1], #4
        ldr     r7, [r1], #4
        ldr     r8, [r1], #4
        ldr     r9, [r1], #4
        ldr     r10, [r1], #4
        ldr     r11, [r1], #4
        stm     r12, {r4, r5, r6, r7, r8, r9, r10, r11}
        b .Lblockcopy_done

        .balign 4
.Livs:
// the words are stored in order 4,5,6,7, 0,1,2,3.
// words 4,5,6,7 are precalculated <<< 8 to save on rotates
        .word   0x0E527F51, 0x05688C9B, 0x83D9AB1F, 0xE0CD195B
        .word   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A

// block words index table. each word stores the indexes for 8 blake_g passes (4 bits each index).
// moreover, bits 12-8 of each codeword are occured to be unique and exploited to form a hashtable.
// the 20 codewords are inserted in the 31 words table, next word pointed by bits 12-8 of previous.
// the entry0 is at index 1.
// this optimization allows scheduling the rounds using just the single codeword register, reloading
// it every 8 passes.
.Lblock_indexes:
        .word 0xdf250c8b, 0x76543210, 0,          0xebcd1397, 0x357b20c1, 0xfa427509, 0x91ef57d4, 0xa2684f05
        .word 0xdc3e9bf,  0,          0,          0x38b0a6c2, 0x491763ea, 0,          0,          0x803b9ef6
        .word 0,          0xb8293670, 0xfedcba98, 0x8f04a562, 0,          0xd386cb1e, 0x931ce7bd, 0xa4def15c
        .word 0,          0,          0x6df984ae, 0,          0,          0x5167482a, 0x5a417d2c

.end
