use generic_array::{
    ArrayLength, GenericArray,
    typenum::{IsLess, NonZero, U8, U16, U32, Unsigned},
};
use sha2::{
    Digest, digest::crypto_common, digest::generic_array as rc_generic_array,
    digest::generic_array::GenericArray as RcGenericArray,
};

use crate::{Align64, Block, BlockU8, Mul2, Mul128};

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const OPAD: u8 = 0x5c;
const IPAD: u8 = 0x36;

#[derive(Clone)]
struct SoftSha256 {
    words: [u32; 8],
    buf: RcGenericArray<u8, rc_generic_array::typenum::U64>,
    ptr: u8,
    prev_blocks: u64,
}

impl SoftSha256 {
    #[inline(always)]
    fn update(&mut self, mut data: &[u8]) {
        let remainder = &mut self.buf[self.ptr as usize..];
        let copy_len = remainder.len().min(data.len());
        remainder[..copy_len].copy_from_slice(&data[..copy_len]);
        data = &data[copy_len..];
        self.ptr += copy_len as u8;

        if self.ptr == 64 {
            self.prev_blocks += 1;
            let old = core::mem::take(&mut self.buf);

            sha2::compress256(&mut self.words, &[old]);
            self.ptr = 0;

            let mut chunks = data.chunks_exact(64);
            while let Some(chunk) = chunks.next() {
                self.prev_blocks += 1;

                let block = RcGenericArray::from_slice(chunk).clone();
                sha2::compress256(&mut self.words, &[block]);
            }

            let remainder = chunks.remainder();
            self.buf[..remainder.len()].copy_from_slice(remainder);
            self.ptr = remainder.len() as u8;
        }
    }

    // a special case for hashing 4 more bytes without a full state clone
    #[inline(always)]
    fn remainder_finalize<L: ArrayLength + IsLess<U32>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> [u32; 8] {
        let msg_len_bytes = self.prev_blocks * 64 + self.ptr as u64 + L::U64;
        let mut words = self.words;
        let mut tmp = self.buf;
        let mut ptr = self.ptr;

        if ptr > 64 - L::U8 - 1 {
            let last_block_len = 64 - ptr;
            tmp[ptr as usize..].copy_from_slice(&input[..last_block_len as usize]);
            sha2::compress256(&mut words, &[*RcGenericArray::from_slice(&tmp)]);
            tmp.fill(0);
            ptr = L::U8 - last_block_len;
            tmp[..ptr as usize].copy_from_slice(&input[last_block_len as usize..]);
            tmp[ptr as usize] = 0x80;
        } else {
            tmp[ptr as usize..][..L::USIZE].copy_from_slice(&input);
            ptr += L::U8;
            tmp[ptr as usize] = 0x80;
        }

        if ptr >= 56 {
            sha2::compress256(&mut words, &[tmp]);
            tmp.fill(0);
        }
        tmp[(64 - 8)..].copy_from_slice(&(msg_len_bytes * 8).to_be_bytes());
        sha2::compress256(&mut words, &[tmp]);
        words
    }
}

#[derive(Clone, Copy)]
#[repr(align(64))]
/// A cheaply copyable HMAC-SHA256 state for PBKDF2-HMAC-SHA256, optimized for scrypt workloads
pub struct Pbkdf2HmacSha256State {
    inner_digest_words: [u32; 8],
    outer_digest_words: [u32; 8],
}

impl Pbkdf2HmacSha256State {
    #[inline(always)]
    /// Create a new PBKDF2-HMAC-SHA256 state from a password
    pub fn new(password: &[u8]) -> Self {
        let mut key_pad = crypto_common::Block::<sha2::Sha256>::default();
        if password.len() <= key_pad.len() {
            key_pad[..password.len()].copy_from_slice(password);
        } else {
            let key_hash = sha2::Sha256::digest(password);
            for i in 0..8 {
                key_pad[4 * i..4 * (i + 1)].copy_from_slice(&key_hash[i].to_be_bytes());
            }
        }
        let mut inner_words = IV;
        let mut outer_words = IV;
        key_pad.iter_mut().for_each(|b| *b ^= IPAD);
        sha2::compress256(&mut inner_words, &[key_pad]);
        key_pad.iter_mut().for_each(|b| *b ^= IPAD ^ OPAD);
        sha2::compress256(&mut outer_words, &[key_pad]);

        Self {
            inner_digest_words: inner_words,
            outer_digest_words: outer_words,
        }
    }

    #[inline(always)]
    /// Create a new PBKDF2-HMAC-SHA256 state from a password with a short key
    pub fn new_short(password: &[u8]) -> Option<Self> {
        if password.len() > 64 - 9 {
            return None;
        }

        let mut inner_words = IV;
        let mut outer_words = IV;
        let mut key_pad = unsafe {
            generic_array::const_transmute::<
                GenericArray<u8, generic_array::typenum::U64>,
                RcGenericArray<u8, rc_generic_array::typenum::U64>,
            >(GenericArray::from_array([IPAD; 64]))
        };
        key_pad
            .iter_mut()
            .zip(password)
            .for_each(|(o, i)| *o = *i ^ IPAD);
        sha2::compress256(&mut inner_words, &[key_pad]);
        key_pad.iter_mut().for_each(|b| *b ^= IPAD ^ OPAD);
        sha2::compress256(&mut outer_words, &[key_pad]);

        Some(Self {
            inner_digest_words: inner_words,
            outer_digest_words: outer_words,
        })
    }

    #[inline(always)]
    /// Gather salt from multiple RoMix buffers and emit the HMAC-SHA256 output
    pub fn emit_gather<R: ArrayLength + NonZero, T: AsRef<Align64<BlockU8<R>>>>(
        &self,
        salts: impl IntoIterator<Item = T>,
        output: &mut [u8],
    ) {
        let mut inner_digest_prefix = self.inner_digest_words;
        let mut count_blocks = 1u64;
        for salt in salts {
            let salt: &Align64<GenericArray<u8, Mul128<R>>> = salt.as_ref();
            count_blocks += Mul2::<R>::U64;

            // SAFETY: the type is guaranteed to be 64 * 2R bytes from the type constraint above
            // this is just to transform the new GenericArray to RustCrypto's older GenericArray
            // they are guaranteed to be the same representation ([0; 128R])
            let blocks = unsafe {
                core::slice::from_raw_parts::<RcGenericArray<u8, rc_generic_array::typenum::U64>>(
                    salt.as_ptr().cast(),
                    Mul2::<R>::USIZE,
                )
            };

            sha2::compress256(&mut inner_digest_prefix, blocks);
        }

        let mut tmp_block_inner = crypto_common::Block::<sha2::Sha256>::default();
        tmp_block_inner[4] = 0x80;
        tmp_block_inner[(64 - 8)..].copy_from_slice(&(count_blocks * 512 + 32).to_be_bytes());

        let mut tmp_block_outer = GenericArray::<u32, U16>::default();
        tmp_block_outer[8] = 0x80;
        tmp_block_outer[15] = u32::from_ne_bytes([0, 0, 3, 0]);

        for (i, block) in output.chunks_mut(32).enumerate() {
            let mut tmp = GenericArray::<u32, U8>::default();
            let idx = (i as u32 + 1).to_be_bytes();
            let mut inner_hash = inner_digest_prefix;

            tmp_block_inner[..4].copy_from_slice(&idx);
            sha2::compress256(&mut inner_hash, &[tmp_block_inner]);

            for i in 0..8 {
                tmp_block_outer[i] = u32::from_ne_bytes(inner_hash[i].to_be_bytes());
            }

            let mut outer_hash = self.outer_digest_words;
            sha2::compress256(
                &mut outer_hash,
                &[unsafe {
                    core::mem::transmute::<_, crypto_common::Block<sha2::Sha256>>(tmp_block_outer)
                }],
            );
            for i in 0..8 {
                tmp[i] = u32::from_ne_bytes(outer_hash[i].to_be_bytes());
            }
            unsafe {
                block.copy_from_slice(&core::slice::from_raw_parts(
                    tmp.as_ptr() as *const u8,
                    block.len(),
                ));
            }
        }
    }

    #[inline(always)]
    /// Compute the HMAC-SHA256 output for a given salt and scatter to an iterator of output RoMix buffers
    pub fn emit_scatter<R: ArrayLength + NonZero, T: AsMut<Align64<BlockU8<R>>>>(
        &self,
        salt: &[u8],
        output: impl IntoIterator<Item = T>,
    ) {
        let mut inner_digest = SoftSha256 {
            words: self.inner_digest_words,
            buf: Default::default(),
            ptr: 0,
            prev_blocks: 1,
        };
        inner_digest.update(salt);
        let mut tmp_block_outer = GenericArray::<u32, U16>::default();
        tmp_block_outer[8] = u32::from_ne_bytes([0x80, 0, 0, 0]);
        tmp_block_outer[15] = u32::from_ne_bytes([0, 0, 3, 0]);
        let mut tmp_block_outer = [tmp_block_outer; 4];

        let mut idx = 0u32;
        for mut output in output {
            let output_item = output.as_mut();

            // SAFETY: BlockU8 and Block are different views and align64 ensures maximum alignment
            let output_words = unsafe {
                core::mem::transmute::<&mut Align64<BlockU8<R>>, &mut Align64<Block<R>>>(
                    output_item,
                )
            };

            for i in (0..output_words.len()).step_by(8 * 4) {
                let mut inner_hash_soa = Align64([[0u32; 4]; 8]);

                repeat4!(j, {
                    idx += 1;
                    let inner_hash = inner_digest
                        .remainder_finalize(GenericArray::from_array(idx.to_be_bytes()));

                    repeat8!(k, {
                        inner_hash_soa[k][j] = inner_hash[k];
                        tmp_block_outer[j][k] = u32::from_ne_bytes(inner_hash[k].to_be_bytes());
                    });
                });

                #[cfg(all(
                    target_arch = "x86_64",
                    target_feature = "avx2",
                    not(target_feature = "sha")
                ))]
                {
                    use crate::sha2_mb::multiway_arx_mb4;
                    use core::arch::x86_64::*;
                    let mut state = core::array::from_fn(|i| unsafe {
                        _mm_set1_epi32(self.outer_digest_words[i] as _)
                    });
                    let block = unsafe {
                        [
                            _mm256_load_si256(inner_hash_soa[0].as_ptr().cast()),
                            _mm256_load_si256(inner_hash_soa[2].as_ptr().cast()),
                            _mm256_load_si256(inner_hash_soa[4].as_ptr().cast()),
                            _mm256_load_si256(inner_hash_soa[6].as_ptr().cast()),
                            _mm256_zextsi128_si256(_mm_set1_epi32(u32::from_be_bytes([
                                0x80, 0, 0, 0,
                            ])
                                as _)),
                            _mm256_setzero_si256(),
                            _mm256_setzero_si256(),
                            _mm256_setr_m128i(
                                _mm_setzero_si128(),
                                _mm_set1_epi32(u32::from_be_bytes([0, 0, 3, 0]) as _),
                            ),
                        ]
                    };

                    multiway_arx_mb4(&mut state, block);

                    repeat8!(i, {
                        state[i] = unsafe {
                            _mm_add_epi32(_mm_set1_epi32(self.outer_digest_words[i] as _), state[i])
                        };
                    });

                    repeat8!(k, {
                        let mut tmp = Align64([0u32; 4]);
                        unsafe {
                            _mm_storeu_si128(tmp.as_mut_ptr().cast(), state[k]);
                        }
                        repeat4!(j, {
                            output_words[i + j * 8 + k] = u32::from_ne_bytes(tmp[j].to_be_bytes());
                        });
                    });
                }

                #[cfg(any(
                    not(target_arch = "x86_64"),
                    not(target_feature = "avx2"),
                    target_feature = "sha"
                ))]
                {
                    let mut outer_hash = [self.outer_digest_words; 4];

                    repeat4!(j, {
                        sha2::compress256(
                            &mut outer_hash[j],
                            &[unsafe {
                                core::mem::transmute::<_, crypto_common::Block<sha2::Sha256>>(
                                    tmp_block_outer[j],
                                )
                            }],
                        );
                    });

                    repeat4!(j, {
                        repeat8!(k, {
                            output_words[i + j * 8 + k] =
                                u32::from_ne_bytes(outer_hash[j][k].to_be_bytes());
                        });
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::U2;

    use super::*;

    #[test]
    fn pbkdf2_hmac_sha256_reference() {
        let mut output_scatter = Align64::<BlockU8<U2>>::default();
        let mut output_gather = Align64::<BlockU8<U2>>::default();
        let mut expected = Align64::<BlockU8<U2>>::default();

        let hmac_state = Pbkdf2HmacSha256State::new(b"LetMeIn1234");
        hmac_state.emit_scatter(b"SodiumChloride", [&mut output_scatter]);
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"LetMeIn1234", b"SodiumChloride", 1, &mut expected);
        assert_eq!(output_scatter, expected);

        hmac_state.emit_gather([&output_scatter], &mut output_gather);
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"LetMeIn1234", &output_scatter, 1, &mut expected);

        assert_eq!(output_gather, expected);
    }

    #[test]
    fn test_pbkdf2_hmac_sha256_short() {
        let password = b"Thisisexactly55bytesyesitreallyis01234567890abcdefghijk";
        for password_len in 0..=password.len() {
            let state0 = Pbkdf2HmacSha256State::new_short(&password[..password_len]).unwrap();
            let state1 = Pbkdf2HmacSha256State::new(&password[..password_len]);
            assert_eq!(state0.inner_digest_words, state1.inner_digest_words);
            assert_eq!(state0.outer_digest_words, state1.outer_digest_words);
        }
    }
}
