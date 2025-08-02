use crate::{
    Align64, RoMix,
    fixed_r::{Block, BufferSet},
    pbkdf2_1::{CreatePbkdf2HmacSha256State, Pbkdf2HmacSha256State},
};
use core::num::{NonZeroU8, NonZeroU32, NonZeroU64};
use generic_array::{
    ArrayLength,
    typenum::{NonZero, U1},
};

/// Comparison operators for the pipeline
pub const CMP_EQ: u32 = 0x00000001;
/// Less than
pub const CMP_LT: u32 = 0x00000002;
/// Greater than
pub const CMP_GT: u32 = 0x00000004;
/// Less than or equal to
pub const CMP_LE: u32 = CMP_EQ | CMP_LT;
/// Greater than or equal to
pub const CMP_GE: u32 = CMP_EQ | CMP_GT;

#[cold]
fn unlikely() {}

/// A context for a pipeline computation.
///
/// It is already implemented for `(&'a Align64<Block<R>>, &'b mut BlockU8<R>)` and `(&'a Align64<Block<R>>, &'b mut Align64<BlockU8<R>>)`
pub trait PipelineContext<
    S,
    Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>,
    R: ArrayLength + NonZero,
    K,
>
{
    /// Called to initialize each computation.
    fn begin(&mut self, state: &mut S, buffer_set: &mut BufferSet<Q, R>);

    /// Called to process the result of each computation.
    ///
    /// Returns `Some(K)` if the computation should be terminated.
    fn drain(self, state: &mut S, buffer_set: &mut BufferSet<Q, R>) -> Option<K>;
}

impl<
    'a,
    'b,
    S,
    Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>,
    R: ArrayLength + NonZero,
> PipelineContext<S, Q, R, ()> for (&'a Align64<Block<R>>, &'b mut Align64<Block<R>>)
{
    #[inline(always)]
    fn begin(&mut self, _state: &mut S, buffer_set: &mut BufferSet<Q, R>) {
        buffer_set.input_buffer_mut().copy_from_slice(self.0);
    }

    #[inline(always)]
    fn drain(self, _state: &mut S, buffer_set: &mut BufferSet<Q, R>) -> Option<()> {
        self.1.copy_from_slice(buffer_set.raw_salt_output());
        None
    }
}

/// Brute force a masked test for a given target and nonce generator at a given offset with a compile-time R and a fixed P of 1.
pub fn test_static<
    const OP: u32,
    Q: AsRef<[Align64<crate::fixed_r::Block<R>>]> + AsMut<[Align64<crate::fixed_r::Block<R>>]>,
    R: ArrayLength + NonZero,
    N: CreatePbkdf2HmacSha256State,
>(
    buffer_sets: [&mut crate::fixed_r::BufferSet<Q, R>; 2],
    salt: &[u8],
    mask: NonZeroU64,
    target: u64,
    offset: usize,
    nonce_generator: impl IntoIterator<Item = N>,
) -> Option<(N, Pbkdf2HmacSha256State)> {
    match OP {
        CMP_EQ | CMP_LT | CMP_GT | CMP_LE | CMP_GE => {}
        _ => panic!("invalid OP: {}", OP),
    }

    struct State<'a, R: ArrayLength + NonZero> {
        mask: NonZeroU64,
        target: u64,
        offset: usize,
        salt: &'a [u8],
        _marker: core::marker::PhantomData<R>,
    }

    let mut state = State {
        mask,
        target,
        offset,
        salt,
        _marker: core::marker::PhantomData,
    };

    struct NonceState<R: ArrayLength + NonZero, const OP: u32, N> {
        nonce: N,
        hmac_state: Pbkdf2HmacSha256State,
        _marker: core::marker::PhantomData<R>,
    }

    impl<
        'a,
        const OP: u32,
        Q: AsRef<[Align64<crate::fixed_r::Block<R>>]> + AsMut<[Align64<crate::fixed_r::Block<R>>]>,
        R: ArrayLength + NonZero,
        N: CreatePbkdf2HmacSha256State,
    > PipelineContext<State<'a, R>, Q, R, (N, Pbkdf2HmacSha256State)> for NonceState<R, OP, N>
    {
        #[inline(always)]
        fn begin(
            &mut self,
            pipeline_state: &mut State<'a, R>,
            buffer_set: &mut crate::fixed_r::BufferSet<Q, R>,
        ) {
            buffer_set.set_input(&self.hmac_state, &pipeline_state.salt);
        }

        #[inline(always)]
        fn drain(
            self,
            pipeline_state: &mut State<'a, R>,
            buffer_set: &mut crate::fixed_r::BufferSet<Q, R>,
        ) -> Option<(N, Pbkdf2HmacSha256State)> {
            let mut output = [0u8; 8];
            self.hmac_state.partial_gather(
                [buffer_set.raw_salt_output()],
                pipeline_state.offset,
                &mut output,
            );

            let t = u64::from_be_bytes(output) & pipeline_state.mask.get();

            let succeeded = match OP {
                CMP_EQ => t == pipeline_state.target,
                CMP_LT => t < pipeline_state.target,
                CMP_GT => t > pipeline_state.target,
                CMP_LE => t <= pipeline_state.target,
                CMP_GE => t >= pipeline_state.target,
                _ => unreachable!(),
            };
            if succeeded {
                unlikely();
                let mut output_hmac_state = self.hmac_state.clone();
                output_hmac_state.ingest_salt(unsafe {
                    core::slice::from_raw_parts(
                        buffer_set
                            .raw_salt_output()
                            .as_ptr()
                            .cast::<Align64<crate::fixed_r::Block<R>>>(),
                        1,
                    )
                });
                return Some((self.nonce, output_hmac_state));
            }

            None
        }
    }

    let [buffer_set0, buffer_set1] = buffer_sets;

    buffer_set0.pipeline(
        buffer_set1,
        nonce_generator.into_iter().map(|i| NonceState::<R, OP, N> {
            hmac_state: i.create_pbkdf2_hmac_sha256_state(),
            nonce: i,
            _marker: core::marker::PhantomData,
        }),
        &mut state,
    )
}

/// Brute force a masked test for a given target and nonce generator at a given offset with a runtime R and P.
pub fn test<const OP: u32, N: CreatePbkdf2HmacSha256State>(
    buffer_sets: &mut [Align64<crate::fixed_r::Block<U1>>],
    cf: NonZeroU8,
    r: NonZeroU32,
    p: NonZeroU32,
    salt: &[u8],
    mask: NonZeroU64,
    target: u64,
    offset: usize,
    nonce_generator: impl IntoIterator<Item = N>,
) -> Option<(N, Pbkdf2HmacSha256State)> {
    match OP {
        CMP_EQ | CMP_LT | CMP_GT | CMP_LE | CMP_GE => {}
        _ => panic!("invalid OP: {}", OP),
    }

    let expected_len = (r.get() * ((1 << cf.get()) + 2)).try_into().unwrap();
    let [mut buffer_set0, mut buffer_set1] = buffer_sets
        .get_disjoint_mut([0..expected_len, expected_len..(expected_len * 2)])
        .expect("buffer_sets is not large enough, at least 2 * r * ((1 << cf) + 2) elements are required");

    let mut nonce_generator = nonce_generator.into_iter();

    let mut current_nonce = nonce_generator.next()?;
    let mut current_hmac_state = current_nonce.create_pbkdf2_hmac_sha256_state();
    let mut output_hmac_state = current_hmac_state.clone();

    // prologue of the global pipeline - hydrate the leading buffer set
    current_hmac_state.emit_scatter(
        salt,
        buffer_set0
            .ro_mix_input_buffer(r)
            .chunks_exact_mut(core::mem::size_of::<Align64<crate::fixed_r::Block<U1>>>())
            .map(|chunk| unsafe {
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<crate::fixed_r::Block<U1>>>()
                    .as_mut()
                    .unwrap()
            }),
    );
    buffer_set0.ro_mix_front(r, cf);

    loop {
        // complete the current chunk except the last RoMixBack
        for chunk_idx in 1..p.get() {
            current_hmac_state.emit_scatter_offset(
                salt,
                buffer_set1
                    .ro_mix_input_buffer(r)
                    .chunks_exact_mut(core::mem::size_of::<Align64<crate::fixed_r::Block<U1>>>())
                    .map(|chunk| unsafe {
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<crate::fixed_r::Block<U1>>>()
                            .as_mut()
                            .unwrap()
                    }),
                chunk_idx * 4 * r.get(),
            );

            let salt = buffer_set0.ro_mix_interleaved(&mut buffer_set1, r, cf);

            output_hmac_state.ingest_salt(unsafe {
                core::slice::from_raw_parts(
                    salt.as_ptr().cast::<Align64<crate::fixed_r::Block<U1>>>(),
                    salt.len() / core::mem::size_of::<Align64<crate::fixed_r::Block<U1>>>(),
                )
            });

            (buffer_set0, buffer_set1) = (buffer_set1, buffer_set0);
        }

        // figure out the next nonce and hmac state
        let (salt, new_state) = if let Some(next_nonce) = nonce_generator.next() {
            let new_hmac_state = next_nonce.create_pbkdf2_hmac_sha256_state();
            new_hmac_state.emit_scatter(
                salt,
                buffer_set1
                    .ro_mix_input_buffer(r)
                    .chunks_exact_mut(core::mem::size_of::<Align64<crate::fixed_r::Block<U1>>>())
                    .map(|chunk| unsafe {
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<crate::fixed_r::Block<U1>>>()
                            .as_mut()
                            .unwrap()
                    }),
            );

            (
                buffer_set0.ro_mix_interleaved(&mut buffer_set1, r, cf),
                Some((next_nonce, new_hmac_state)),
            )
        } else {
            (buffer_set0.ro_mix_back(r, cf), None)
        };

        let mut tmp_output = [0u8; 8];

        output_hmac_state.partial_gather(
            salt.chunks_exact(core::mem::size_of::<Align64<crate::fixed_r::Block<U1>>>())
                .map(|block| unsafe {
                    block
                        .as_ptr()
                        .cast::<Align64<crate::fixed_r::Block<U1>>>()
                        .as_ref()
                        .unwrap()
                }),
            offset,
            &mut tmp_output,
        );
        let t = u64::from_be_bytes(tmp_output) & mask.get();

        if match OP {
            CMP_EQ => t == target,
            CMP_LT => t < target,
            CMP_GT => t > target,
            CMP_LE => t <= target,
            CMP_GE => t >= target,
            _ => unreachable!(),
        } {
            unlikely();
            unsafe {
                output_hmac_state.ingest_salt(core::slice::from_raw_parts(
                    salt.as_ptr().cast::<Align64<crate::fixed_r::Block<U1>>>(),
                    salt.len() / core::mem::size_of::<Align64<crate::fixed_r::Block<U1>>>(),
                ));
            }
            return Some((current_nonce, output_hmac_state));
        }

        let Some((next_nonce, new_hmac_state)) = new_state else {
            return None;
        };

        {
            current_nonce = next_nonce;
            current_hmac_state = new_hmac_state;
            output_hmac_state = current_hmac_state.clone();

            (buffer_set0, buffer_set1) = (buffer_set1, buffer_set0);
        }
    }
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::{U1, U2, U3, U4, U8, U16};

    use super::*;

    #[test]
    fn test_pow_kat() {
        let target = "0002";

        let cf = NonZeroU8::new(3).unwrap();
        let r = NonZeroU32::new(8).unwrap();
        let p = NonZeroU32::new(1).unwrap();

        let mut target_u64 = 0u64;
        let mut target_mask = 0u64;

        for nibble in target.as_bytes().iter() {
            let addend = match nibble {
                b'0'..=b'9' => nibble - b'0',
                b'A'..=b'F' => nibble - b'A' + 10,
                b'a'..=b'f' => nibble - b'a' + 10,
                _ => panic!("invalid nibble: {}", nibble),
            } as u64;

            target_u64 <<= 4;
            target_u64 |= addend;
            target_mask <<= 4;
            target_mask |= 15;
        }

        target_u64 <<= (16 - target.len()) * 4;
        target_mask <<= (16 - target.len()) * 4;

        let expected_nonce = u64::from_le_bytes([0x11, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let mut buffer_sets = vec![
            Align64::<crate::fixed_r::Block<U1>>::default();
            2 * r.get() as usize * p.get() as usize * ((1 << cf.get()) + 2)
        ];
        for offset in -5..=5 {
            for len in 0..=8 {
                let includes_nonce = ((expected_nonce as i64 + offset)
                    ..(expected_nonce as i64 + offset + len as i64))
                    .contains(&(expected_nonce as i64));

                let static_result = test_static::<CMP_LE, _, U8, _>(
                    [
                        &mut *crate::fixed_r::BufferSet::new_boxed(cf),
                        &mut *crate::fixed_r::BufferSet::new_boxed(cf),
                    ],
                    &[0x29, 0x39, 0x66, 0x3c, 0x6f, 0x46, 0x15, 0xc3],
                    NonZeroU64::new(target_mask).unwrap(),
                    target_u64,
                    28 / 2,
                    ((expected_nonce as i64 + offset)..)
                        .map(|i| i as u64)
                        .take(len),
                );

                let dynamic_result = test::<CMP_LE, _>(
                    &mut buffer_sets,
                    cf,
                    r,
                    p,
                    &[0x29, 0x39, 0x66, 0x3c, 0x6f, 0x46, 0x15, 0xc3],
                    NonZeroU64::new(target_mask).unwrap(),
                    target_u64,
                    28 / 2,
                    ((expected_nonce as i64 + offset)..)
                        .map(|i| i as u64)
                        .take(len),
                );

                if !includes_nonce {
                    assert!(static_result.is_none(), "static_result is not none");
                    assert!(dynamic_result.is_none(), "dynamic_result is not none");
                    continue;
                }

                let (nonce, hmac_state_static) = static_result.unwrap();

                assert_eq!(nonce, expected_nonce);

                let (nonce, hmac_state_dynamic) = dynamic_result.unwrap();

                assert_eq!(nonce, expected_nonce);

                assert_eq!(hmac_state_static, hmac_state_dynamic);
            }
        }
    }

    #[test]
    fn test_pow_high_p() {
        let target = "002";
        const SALT: &[u8] = &[0x29, 0x39, 0x66, 0x3c, 0x6f, 0x46, 0x15, 0xc3];
        for p in 1..=6 {
            let cf = NonZeroU8::new(3).unwrap();
            let r = NonZeroU32::new(8).unwrap();
            let p = NonZeroU32::new(p).unwrap();
            let params = scrypt::Params::new(cf.get(), r.get(), p.get(), 16).unwrap();

            let mut buffer_sets =
                vec![
                    Align64::<crate::fixed_r::Block<U1>>::default();
                    2 * r.get() as usize * p.get() as usize * ((1 << cf.get()) + 2)
                ];

            let mut target_u64 = 0u64;
            let mut target_mask = 0u64;

            for nibble in target.as_bytes().iter() {
                let addend = match nibble {
                    b'0'..=b'9' => nibble - b'0',
                    b'A'..=b'F' => nibble - b'A' + 10,
                    b'a'..=b'f' => nibble - b'a' + 10,
                    _ => panic!("invalid nibble: {}", nibble),
                } as u64;

                target_u64 <<= 4;
                target_u64 |= addend;
                target_mask <<= 4;
                target_mask |= 15;
            }

            let expected_iterations = target_mask.div_ceil(target_u64 + 1);

            target_u64 <<= (16 - target.len()) * 4;
            target_mask <<= (16 - target.len()) * 4;

            let (nonce, hmac_state) = test::<CMP_LE, _>(
                &mut buffer_sets,
                cf,
                r,
                p,
                SALT,
                NonZeroU64::new(target_mask).unwrap(),
                target_u64,
                0,
                0..expected_iterations * 100,
            )
            .unwrap();

            let mut expected_output = [0u8; 16];

            scrypt::scrypt(&nonce.to_le_bytes(), SALT, &params, &mut expected_output).unwrap();

            let mut output = [0u8; 16];
            hmac_state.emit(&mut output);

            assert_eq!(output, expected_output);
            assert!(
                u64::from_be_bytes(output[0..8].try_into().unwrap()) & target_mask
                    <= u64::from_be_bytes([0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            );
        }
    }

    fn test_pow_consistency<R: ArrayLength + NonZero>() {
        for target in ["03", "005", "0030"] {
            let cf = NonZeroU8::new(3).unwrap();

            let mut target_u64 = 0u64;
            let mut target_mask = 0u64;

            for nibble in target.as_bytes().iter() {
                let addend = match nibble {
                    b'0'..=b'9' => nibble - b'0',
                    b'A'..=b'F' => nibble - b'A' + 10,
                    b'a'..=b'f' => nibble - b'a' + 10,
                    _ => panic!("invalid nibble: {}", nibble),
                } as u64;

                target_u64 <<= 4;
                target_u64 |= addend;
                target_mask <<= 4;
                target_mask |= 15;
            }

            let expected_iterations = target_mask.div_ceil(target_u64 + 1);

            target_u64 <<= (16 - target.len()) * 4;
            target_mask <<= (16 - target.len()) * 4;

            let mut buffer_sets = vec![
                Align64::<crate::fixed_r::Block<U1>>::default();
                2 * R::USIZE * 1 as usize * ((1 << cf.get()) + 2)
            ];
            let static_result = test_static::<CMP_LE, _, R, _>(
                [
                    &mut *crate::fixed_r::BufferSet::new_boxed(cf),
                    &mut *crate::fixed_r::BufferSet::new_boxed(cf),
                ],
                &[0x29, 0x39, 0x66, 0x3c, 0x6f, 0x46, 0x15, 0xc3],
                NonZeroU64::new(target_mask).unwrap(),
                target_u64,
                28 / 2,
                0..expected_iterations * 100,
            );

            let dynamic_result = test::<CMP_LE, _>(
                &mut buffer_sets,
                cf,
                R::U32.try_into().unwrap(),
                1.try_into().unwrap(),
                &[0x29, 0x39, 0x66, 0x3c, 0x6f, 0x46, 0x15, 0xc3],
                NonZeroU64::new(target_mask).unwrap(),
                target_u64,
                28 / 2,
                0..expected_iterations * 100,
            );

            let (nonce_static, hmac_state_static) = static_result.unwrap();

            let (nonce_dynamic, hmac_state_dynamic) = dynamic_result.unwrap();

            assert_eq!(nonce_static, nonce_dynamic);
            assert_eq!(hmac_state_static, hmac_state_dynamic);
        }
    }

    #[test]
    fn test_pow_consistency_r1() {
        test_pow_consistency::<U1>();
    }

    #[test]
    fn test_pow_consistency_r2() {
        test_pow_consistency::<U2>();
    }

    #[test]
    fn test_pow_consistency_r3() {
        test_pow_consistency::<U3>();
    }

    #[test]
    fn test_pow_consistency_r4() {
        test_pow_consistency::<U4>();
    }

    #[test]
    fn test_pow_consistency_r8() {
        test_pow_consistency::<U8>();
    }

    #[test]
    fn test_pow_consistency_r16() {
        test_pow_consistency::<U16>();
    }
}
