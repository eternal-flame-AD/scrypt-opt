use core::arch::x86_64::*;

use crate::{
    memory::Align32,
    simd::{Inverse, Swizzle},
};

static BSWAP: __m256i = unsafe {
    core::mem::transmute::<[u8; 32], __m256i>([
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8,
        15, 14, 13, 12,
    ])
};

static BSWAP_128: __m128i = unsafe {
    core::mem::transmute::<[u8; 16], __m128i>([
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
    ])
};

const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K32X4: [[u32; 4]; 16] = [
    [K32[3], K32[2], K32[1], K32[0]],
    [K32[7], K32[6], K32[5], K32[4]],
    [K32[11], K32[10], K32[9], K32[8]],
    [K32[15], K32[14], K32[13], K32[12]],
    [K32[19], K32[18], K32[17], K32[16]],
    [K32[23], K32[22], K32[21], K32[20]],
    [K32[27], K32[26], K32[25], K32[24]],
    [K32[31], K32[30], K32[29], K32[28]],
    [K32[35], K32[34], K32[33], K32[32]],
    [K32[39], K32[38], K32[37], K32[36]],
    [K32[43], K32[42], K32[41], K32[40]],
    [K32[47], K32[46], K32[45], K32[44]],
    [K32[51], K32[50], K32[49], K32[48]],
    [K32[55], K32[54], K32[53], K32[52]],
    [K32[59], K32[58], K32[57], K32[56]],
    [K32[63], K32[62], K32[61], K32[60]],
];

#[inline(always)]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    unsafe {
        let t1 = _mm_sha256msg1_epu32(v0, v1);
        let t2 = _mm_alignr_epi8(v3, v2, 4);
        let t3 = _mm_add_epi32(t1, t2);
        _mm_sha256msg2_epu32(t3, v3)
    }
}

struct PermuteABEFCDGH;

impl crate::simd::Swizzle<8> for PermuteABEFCDGH {
    const INDEX: [usize; 8] = [5, 4, 1, 0, 7, 6, 3, 2];
}

#[cfg_attr(not(target_feature = "sha"), target_feature(enable = "sha"))]
#[cfg_attr(not(target_feature = "avx2"), target_feature(enable = "avx2"))]
pub(crate) unsafe fn multiway_arx_mb2_sha_ni<
    const BIG_ENDIAN_INPUT: bool,
    const BIG_ENDIAN_OUTPUT: bool,
>(
    state: [&mut Align32<[u32; 8]>; 2],
    blocks: [[&Align32<[u32; 8]>; 2]; 2],
) {
    // modern processors have ~2x latency over CPI on SHA-NI instructions
    // so here is a dual buffer clone
    // taken from sha2 crate
    unsafe {
        macro_rules! rounds4 {
            ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
                let k = K32X4[$i];
                let kv = _mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
                let t1: [_; 2] = core::array::from_fn(|i| _mm_add_epi32($rest[i], kv));
                $cdgh = core::array::from_fn(|i| _mm_sha256rnds2_epu32($cdgh[i], $abef[i], t1[i]));
                let t2: [_; 2] = core::array::from_fn(|i| _mm_shuffle_epi32(t1[i], 0x0E));
                $abef = core::array::from_fn(|i| _mm_sha256rnds2_epu32($abef[i], $cdgh[i], t2[i]));
            }};
        }

        macro_rules! schedule_rounds4 {
            (
            $abef:ident, $cdgh:ident,
            $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
            $i: expr
        ) => {{
                $w4 = core::array::from_fn(|i| schedule($w0[i], $w1[i], $w2[i], $w3[i]));
                rounds4!($abef, $cdgh, $w4, $i);
            }};
        }

        let mut abef = [_mm_undefined_si128(); 2];
        let mut cdgh = [_mm_undefined_si128(); 2];

        repeat2!(i, {
            let load = _mm256_load_si256(state[i].as_ptr().cast());
            let permuted = _mm256_permutevar8x32_epi32(load, PermuteABEFCDGH::INDEX_YMM);
            abef[i] = _mm256_extracti128_si256(permuted, 0);
            cdgh[i] = _mm256_extracti128_si256(permuted, 1);
        });

        let mut w0 = [_mm_undefined_si128(); 2];
        let mut w1 = [_mm_undefined_si128(); 2];
        let mut w2 = [_mm_undefined_si128(); 2];
        let mut w3 = [_mm_undefined_si128(); 2];
        let mut w4: [_; 2];

        repeat2!(i, {
            w0[i] = _mm_load_si128(blocks[i][0].as_ptr().cast());
            w1[i] = _mm_load_si128(blocks[i][0].as_ptr().add(4).cast());
            w2[i] = _mm_load_si128(blocks[i][1].as_ptr().cast());
            w3[i] = _mm_load_si128(blocks[i][1].as_ptr().add(4).cast());
        });

        if BIG_ENDIAN_INPUT {
            repeat2!(i, {
                w0[i] = _mm_shuffle_epi8(w0[i], BSWAP_128);
                w1[i] = _mm_shuffle_epi8(w1[i], BSWAP_128);
                w2[i] = _mm_shuffle_epi8(w2[i], BSWAP_128);
                w3[i] = _mm_shuffle_epi8(w3[i], BSWAP_128);
            });
        }

        rounds4!(abef, cdgh, w0, 0);
        rounds4!(abef, cdgh, w1, 1);
        rounds4!(abef, cdgh, w2, 2);
        rounds4!(abef, cdgh, w3, 3);
        schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
        schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
        schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
        schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
        schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
        schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
        schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
        schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
        schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
        schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
        schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
        schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);

        repeat2!(i, {
            let new_state = _mm256_permutevar8x32_epi32(
                _mm256_setr_m128i(abef[i], cdgh[i]),
                Inverse::<8, PermuteABEFCDGH>::INDEX_YMM,
            );
            let saved_state = _mm256_load_si256(state[i].as_ptr().cast());
            let result = _mm256_add_epi32(new_state, saved_state);
            _mm256_store_si256(
                state[i].as_mut_ptr().cast(),
                if BIG_ENDIAN_OUTPUT {
                    _mm256_shuffle_epi8(result, BSWAP)
                } else {
                    result
                },
            );
        });
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    #[test]
    fn test_sha256_sha_ni_single_block() {
        if !crate::features::Feature::check(&crate::features::Sha) {
            return;
        }

        // Test vector from NIST FIPS 180-4
        // Input: "abc" repeated 16 times
        let input_block = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        let mut state0 = Align32(IV);
        let mut state1 = Align32(IV);

        let block_left = Align32(input_block[..8].try_into().unwrap());
        let block_right = Align32(input_block[8..].try_into().unwrap());

        unsafe {
            multiway_arx_mb2_sha_ni::<false, false>(
                [&mut state0, &mut state1],
                [[&block_left, &block_right], [&block_left, &block_right]],
            );
        }

        let expected = Align32([
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ]);

        assert_eq!(state0, expected);
        assert_eq!(state1, expected);

        state0 = Align32(IV);
        state1 = Align32(IV);

        unsafe {
            multiway_arx_mb2_sha_ni::<false, true>(
                [&mut state0, &mut state1],
                [[&block_left, &block_right], [&block_left, &block_right]],
            );
        }

        for i in 0..8 {
            state0[i] = u32::from_be_bytes(state0[i].to_ne_bytes());
            state1[i] = u32::from_be_bytes(state1[i].to_ne_bytes());
        }

        assert_eq!(state0, expected);
        assert_eq!(state1, expected);

        state0 = Align32(IV);
        state1 = Align32(IV);

        unsafe {
            multiway_arx_mb2_sha_ni::<false, false>(
                [&mut state0, &mut state1],
                [
                    [&block_left, &block_right],
                    [&Align32([0; 8]), &block_right],
                ],
            );
        }

        assert_eq!(state0, expected);
        assert_ne!(state1, expected);

        state0 = Align32(IV);
        state1 = Align32(IV);

        unsafe {
            multiway_arx_mb2_sha_ni::<false, false>(
                [&mut state0, &mut state1],
                [
                    [&Align32([0; 8]), &block_right],
                    [&block_left, &block_right],
                ],
            );
        }

        assert_ne!(state0, expected);
        assert_eq!(state1, expected);
    }
}
