use core::arch::x86_64::*;

#[cfg(target_feature = "avx512vl")]
macro_rules! mm_ror_epi32x {
    ($a:expr, $amt:literal) => {
        _mm_ror_epi32($a, $amt)
    };
}

#[cfg(not(target_feature = "avx512vl"))]
macro_rules! mm_ror_epi32x {
    ($a:expr, $amt:literal) => {
        _mm_or_si128(_mm_slli_epi32($a, 32 - $amt), _mm_srli_epi32($a, $amt))
    };
}

#[rustfmt::skip]
macro_rules! repeat64 {
    ($i:ident, $b:block) => {
        let $i = 0; $b; let $i = 1; $b; let $i = 2; $b; let $i = 3; $b;
        let $i = 4; $b; let $i = 5; $b; let $i = 6; $b; let $i = 7; $b;
        let $i = 8; $b; let $i = 9; $b; let $i = 10; $b; let $i = 11; $b;
        let $i = 12; $b; let $i = 13; $b; let $i = 14; $b; let $i = 15; $b;
        let $i = 16; $b; let $i = 17; $b; let $i = 18; $b; let $i = 19; $b;
        let $i = 20; $b; let $i = 21; $b; let $i = 22; $b; let $i = 23; $b;
        let $i = 24; $b; let $i = 25; $b; let $i = 26; $b; let $i = 27; $b;
        let $i = 28; $b; let $i = 29; $b; let $i = 30; $b; let $i = 31; $b;
        let $i = 32; $b; let $i = 33; $b; let $i = 34; $b; let $i = 35; $b;
        let $i = 36; $b; let $i = 37; $b; let $i = 38; $b; let $i = 39; $b;
        let $i = 40; $b; let $i = 41; $b; let $i = 42; $b; let $i = 43; $b;
        let $i = 44; $b; let $i = 45; $b; let $i = 46; $b; let $i = 47; $b;
        let $i = 48; $b; let $i = 49; $b; let $i = 50; $b; let $i = 51; $b;
        let $i = 52; $b; let $i = 53; $b; let $i = 54; $b; let $i = 55; $b;
        let $i = 56; $b; let $i = 57; $b; let $i = 58; $b; let $i = 59; $b;
        let $i = 60; $b; let $i = 61; $b; let $i = 62; $b; let $i = 63; $b;
    };
}

#[allow(unused, reason = "currently not used but handy later, tests need it")]
pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[allow(unused)]
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

/// Do a 4-way SHA-256 compression function without adding back the saved state, without feedback
///
/// This is useful for making state share registers with a-h when caller has the previous state recalled cheaply from elsewhere after the fact
#[allow(unused)]
pub(crate) fn multiway_arx_mb4(state: &mut [__m128i; 8], mut block: [__m256i; 8]) {
    unsafe {
        let [a, b, c_outer, d_outer, e, f, g_outer, h_outer] = &mut *state;

        let mut cd = _mm256_setr_m128i(*c_outer, *d_outer);
        let mut gh = _mm256_setr_m128i(*g_outer, *h_outer);

        macro_rules! get_block {
            ($i:expr) => {{
                let reg_idx = ($i % 16) / 2;
                if $i % 2 == 0 {
                    _mm256_castsi256_si128(block[reg_idx])
                } else {
                    _mm256_extracti128_si256(block[reg_idx], 1)
                }
            }};
        }

        macro_rules! set_block {
            ($i:expr, $val:expr) => {{
                let reg_idx = ($i % 16) / 2;
                let val = $val;
                if $i % 2 == 0 {
                    block[reg_idx] = _mm256_inserti128_si256(block[reg_idx], val, 0);
                    _mm256_castsi256_si128(block[reg_idx])
                } else {
                    block[reg_idx] = _mm256_inserti128_si256(block[reg_idx], val, 1);
                    _mm256_extracti128_si256(block[reg_idx], 1)
                }
            }};
        }

        repeat64!(i, {
            let w = if i < 16 {
                get_block!(i)
            } else {
                let w15 = get_block!((i - 15) % 16);
                let s0 = _mm_xor_si128(
                    _mm_xor_si128(mm_ror_epi32x!(w15, 7), mm_ror_epi32x!(w15, 18)),
                    _mm_srli_epi32(w15, 3),
                );
                let w2 = get_block!((i - 2) % 16);
                let s1 = _mm_xor_si128(
                    _mm_xor_si128(mm_ror_epi32x!(w2, 17), mm_ror_epi32x!(w2, 19)),
                    _mm_srli_epi32(w2, 10),
                );
                let mut new_schedule = _mm_add_epi32(get_block!(i), s0);
                new_schedule = _mm_add_epi32(new_schedule, get_block!((i - 7) % 16));
                new_schedule = _mm_add_epi32(new_schedule, s1);
                set_block!(i, new_schedule)
            };

            let s1 = _mm_xor_si128(
                _mm_xor_si128(mm_ror_epi32x!(*e, 6), mm_ror_epi32x!(*e, 11)),
                mm_ror_epi32x!(*e, 25),
            );

            let g = _mm256_castsi256_si128(gh);
            let h = _mm256_extracti128_si256(gh, 1);

            let ch = _mm_xor_si128(_mm_and_si128(*e, *f), _mm_andnot_si128(*e, g));
            let mut t1 = s1;
            t1 = _mm_add_epi32(t1, ch);
            t1 = _mm_add_epi32(t1, _mm_set1_epi32(K32[i] as _));
            t1 = _mm_add_epi32(t1, w);
            t1 = _mm_add_epi32(t1, h);

            let s0 = _mm_xor_si128(
                _mm_xor_si128(mm_ror_epi32x!(*a, 2), mm_ror_epi32x!(*a, 13)),
                mm_ror_epi32x!(*a, 22),
            );

            let c = _mm256_castsi256_si128(cd);

            let maj = _mm_xor_si128(
                _mm_xor_si128(_mm_and_si128(*a, *b), _mm_and_si128(*a, c)),
                _mm_and_si128(*b, c),
            );
            let mut t2 = s0;
            t2 = _mm_add_epi32(t2, maj);

            gh = _mm256_setr_m128i(*f, g);

            let d = _mm256_extracti128_si256(cd, 1);

            *f = *e;
            *e = _mm_add_epi32(d, t1);
            cd = _mm256_setr_m128i(*b, c);
            *b = *a;
            *a = _mm_add_epi32(t1, t2);
        });

        *c_outer = _mm256_castsi256_si128(cd);
        *d_outer = _mm256_extracti128_si256(cd, 1);
        *g_outer = _mm256_castsi256_si128(gh);
        *h_outer = _mm256_extracti128_si256(gh, 1);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sha256_sse_single_block() {
        // Test vector from NIST FIPS 180-4
        // Input: "abc" repeated 16 times
        let input_block = [
            0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000018,
        ];

        // Create 16 identical blocks for SSE processing
        let block: [__m256i; 8] = unsafe {
            core::array::from_fn(|i| {
                _mm256_setr_m128i(
                    _mm_set1_epi32(input_block[i * 2] as _),
                    _mm_set1_epi32(input_block[i * 2 + 1] as _),
                )
            })
        };

        // Initial hash values (H0) for 16 parallel hashes
        let mut state: [__m128i; 8] =
            core::array::from_fn(|i| unsafe { _mm_set1_epi32(IV[i] as _) });

        // Process the blocks
        multiway_arx_mb4(&mut state, block);

        for i in 0..8 {
            state[i] = unsafe { _mm_add_epi32(state[i], _mm_set1_epi32(IV[i] as _)) };
        }

        // Expected output hash for "abc"
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];

        // Extract results from SSE state
        let mut results: [[u32; 4]; 8] = unsafe { core::mem::zeroed() };
        for i in 0..8 {
            unsafe {
                _mm_storeu_si128(results[i].as_mut_ptr() as *mut _, state[i]);
            }
        }

        // Verify all 4 results match the expected hash
        for i in 0..4 {
            let result = [
                results[0][i],
                results[1][i],
                results[2][i],
                results[3][i],
                results[4][i],
                results[5][i],
                results[6][i],
                results[7][i],
            ];
            assert_eq!(
                result, expected,
                "SHA-256 AVX-512 hash mismatch at index {}",
                i
            );
        }
    }
}
