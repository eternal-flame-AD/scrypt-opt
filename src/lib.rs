#![doc = include_str!("../README.md")]
#![cfg_attr(
    all(not(test), not(feature = "std"), not(target_arch = "wasm32")),
    no_std
)]
#![cfg_attr(feature = "portable-simd", feature(portable_simd))]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[rustfmt::skip]
macro_rules! repeat2 {
    ($i:ident, $b:block) => {
        { let $i = 0; $b; }
        { let $i = 1; $b; }
    };
}

#[rustfmt::skip]
macro_rules! repeat4 {
    ($i:ident, $b:block) => {
        repeat2!(di, { let $i = di; $b });
        repeat2!(di, { let $i = di + 2; $b });
    };
}

#[rustfmt::skip]
macro_rules! repeat8 {
    ($i:ident, $b:block) => {{
        repeat4!(di, { let $i = di; $b });
        repeat4!(di, { let $i = di + 4; $b });
    }};
}

/// Re-export sha2
pub use sha2;

/// Re-export generic_array
pub use generic_array;

/// Algorithmic Self-Test (CAST)
pub mod self_test;

/// Memory utilities
pub mod memory;

/// Salsa20 kernels
pub mod salsa20;

/// SIMD utilities
pub(crate) mod simd;

/// PBKDF2-HMAC-SHA256 implementation (1 iteration special case)
pub mod pbkdf2_1;

/// Pipeline support
pub mod pipeline;

/// Multi-buffer SHA256 implementation
#[cfg(target_arch = "x86_64")]
pub(crate) mod sha2_mb;

/// Runtime feature detection
pub mod features;

/// Compat APIs
#[cfg(any(feature = "std", target_arch = "wasm32"))]
pub mod compat;

/// Fixed R buffer set
pub mod fixed_r;

use core::num::{NonZeroU8, NonZeroU32};

use generic_array::typenum::{
    B1, IsLess, IsLessOrEqual, PowerOfTwo, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13,
    U14, U15, U16, U17, U18, U19, U20, U21, U22, U23, U24, U25, U26, U27, U28, U29, U30, U31,
    U4294967296, Unsigned,
};

use generic_array::{ArrayLength, GenericArray, typenum::NonZero};

#[allow(unused_imports)]
use crate::features::Feature as _;

use crate::memory::Align64;
use crate::salsa20::{BlockType, Salsa20};

include!("block_mix.rs");

// rough order:
// 1. kernels that I know is optimal
// 2. portable simd
// 3. kernels that should work better than scalar
// 4. scalar
#[cfg(target_arch = "x86_64")]
cfg_if::cfg_if! {
    if #[cfg(target_feature = "avx512f")] {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::x86_64::BlockAvx512F;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::x86_64::BlockAvx512FMb2;
    } else if #[cfg(target_feature = "avx2")] {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::x86_64::BlockSse2<U1>;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::x86_64::BlockAvx2Mb2;
    } else if #[cfg(feature = "portable-simd")] {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::BlockPortableSimd;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::BlockPortableSimd2;
    } else {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::x86_64::BlockSse2<U1>;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::x86_64::BlockSse2<U2>;
    }
}

#[cfg(not(target_arch = "x86_64"))]
cfg_if::cfg_if! {
    if #[cfg(feature = "portable-simd")] {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::BlockPortableSimd;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::BlockPortableSimd2;
    } else {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::BlockScalar<U1>;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::BlockScalar<U2>;
    }
}

mod sealing {
    pub trait Sealed {}
}

/// A trait for valid cost factors
pub trait ValidCostFactor: Unsigned + NonZero + sealing::Sealed {
    /// The output type
    type Output: ArrayLength + PowerOfTwo + NonZero + IsLess<U4294967296, Output = B1>;

    /// The minimum number of blocks required for a given Cost Factor (log2(N))
    type MinimumBlocks: ArrayLength + NonZero + IsLessOrEqual<U4294967296, Output = B1>;
}

const MAX_CF: u8 = 31;
const MAX_N: u32 = 1 << MAX_CF;

macro_rules! impl_valid_cost_factor {
    ($($base:ty),*) => {
        $(
            impl sealing::Sealed for $base {}
            impl ValidCostFactor for $base {
                type Output = <U1 as core::ops::Shl<$base>>::Output;
                type MinimumBlocks = <<U1 as core::ops::Shl<$base>>::Output as core::ops::Add<U2>>::Output;
            }
        )*
    };
}

impl_valid_cost_factor!(
    U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, U16, U17, U18, U19, U20, U21,
    U22, U23, U24, U25, U26, U27, U28, U29, U30, U31
);

/// Generalized RoMix interface with a runtime R value
pub trait RoMix {
    /// Perform the front part of the $RoMix$ operation
    ///
    /// Buffer must be at least 128 * r * (n + 1) bytes long.
    fn ro_mix_front_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8);
    /// Perform the back part of the $RoMix$ operation
    ///
    /// Buffer must be at least 128 * r * (n + 2) bytes long.
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_back_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8) -> &[u8];
    /// Interleave the front and back parts of the $RoMix$ operation in two independent buffers
    ///
    /// Buffer must be at least 128 * r * (n + 2) bytes long.
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_interleaved_ex<'a, S: Salsa20<Lanes = U2>>(
        &'a mut self,
        front: &mut Self,
        r: NonZeroU32,
        cf: NonZeroU8,
    ) -> &'a [u8];

    /// Convenience method to get the input buffer for the $RoMix$ operation
    ///
    /// Always return the 128 * r bytes of the buffer
    fn ro_mix_input_buffer(&mut self, r: NonZeroU32) -> &mut [u8];

    /// Perform the front part of the $RoMix$ operation
    ///
    /// Buffer must be at least 128 * r * (n + 1) bytes long.
    fn ro_mix_front(&mut self, r: NonZeroU32, cf: NonZeroU8) {
        self.ro_mix_front_ex::<DefaultEngine1>(r, cf);
    }
    /// Perform the back part of the $RoMix$ operation
    ///
    /// Buffer must be at least 128 * r * (n + 2) bytes long.
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_back(&mut self, r: NonZeroU32, cf: NonZeroU8) -> &[u8] {
        self.ro_mix_back_ex::<DefaultEngine1>(r, cf)
    }
    /// Interleave the front and back parts of the $RoMix$ operation in two independent buffers
    ///
    /// Buffer must be at least 128 * r * (n + 2) bytes long.
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_interleaved(&mut self, front: &mut Self, r: NonZeroU32, cf: NonZeroU8) -> &[u8] {
        self.ro_mix_interleaved_ex::<DefaultEngine2>(front, r, cf)
    }
}

#[cfg_attr(
    all(target_arch = "x86_64", not(target_feature = "avx2")),
    scrypt_opt_derive::generate_target_variant("avx2")
)]
#[cfg_attr(
    not(all(target_arch = "x86_64", not(target_feature = "avx2"))),
    inline(always)
)]
fn ro_mix_front_ex_dyn<S: Salsa20<Lanes = U1>>(
    v: &mut [Align64<fixed_r::Block<U1>>],
    r: NonZeroU32,
    cf: NonZeroU8,
) {
    let r = r.get() as usize;
    let n = 1 << cf.get();
    assert!(
        v.len() >= r * (n + 1),
        "ro_mix_front_ex: v.len() < r * (n + 1)"
    );

    // SAFETY: n is at least 1, v is at least r long
    unsafe {
        v.get_unchecked_mut(..r).iter_mut().for_each(|chunk| {
            S::shuffle_in(
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<[u32; 16]>>()
                    .as_mut()
                    .unwrap(),
            );
            S::shuffle_in(
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<[u32; 16]>>()
                    .add(1)
                    .as_mut()
                    .unwrap(),
            );
        });
    }

    for i in 0..n {
        let [src, dst] = unsafe {
            v.get_disjoint_unchecked_mut([(i * r)..((i + 1) * r), ((i + 1) * r)..((i + 2) * r)])
        };
        block_mix!(r; [<S> &*src => &mut *dst]);
    }
}

#[cfg_attr(
    all(target_arch = "x86_64", not(target_feature = "avx2")),
    scrypt_opt_derive::generate_target_variant("avx2")
)]
#[cfg_attr(
    not(all(target_arch = "x86_64", not(target_feature = "avx2"))),
    inline(always)
)]
fn ro_mix_back_ex_dyn<S: Salsa20<Lanes = U1>>(
    v: &mut [Align64<fixed_r::Block<U1>>],
    r: NonZeroU32,
    cf: NonZeroU8,
) -> &[u8] {
    let r = r.get() as usize;
    let n = 1 << cf.get();
    assert!(
        v.len() >= r * (n + 2),
        "pipeline_end_ex: v.len() < r * (n + 2)"
    );

    for _ in (0..n).step_by(2) {
        let idx = unsafe {
            v.as_ptr()
                .add((n * r) as usize)
                .cast::<u32>()
                .add(r * 32 - 16)
                .read()
        } as usize;

        let j = idx & (n - 1);

        // SAFETY: the largest j value is n-1, so the largest index of the 3 is n+1, which is in bounds after the >=n+2 check
        let [in0, in1, out] = unsafe {
            v.get_disjoint_unchecked_mut([
                (n * r)..((n + 1) * r),
                (j * r)..((j + 1) * r),
                ((n + 1) * r)..((n + 2) * r),
            ])
        };
        block_mix!(r; [<S> &(&*in0, &*in1) => &mut *out]);
        let idx2 = unsafe {
            v.as_ptr()
                .add(((n + 1) * r) as usize)
                .cast::<u32>()
                .add(r * 32 - 16)
                .read()
        } as usize;

        let j2 = idx2 & (n - 1);

        // SAFETY: the largest j2 value is n-1, so the largest index of the 3 is n+1, which is in bounds after the >=n+2 check
        let [b, v, t] = unsafe {
            v.get_disjoint_unchecked_mut([
                (n * r)..((n + 1) * r),
                (j2 * r)..((j2 + 1) * r),
                ((n + 1) * r)..((n + 2) * r),
            ])
        };
        block_mix!(r; [<S> &(&*v, &*t) => &mut *b]);
    }

    // SAFETY: n is at least 1, v is at least r * (n + 2) long
    unsafe {
        v.get_unchecked_mut(r * n..r * (n + 1))
            .iter_mut()
            .for_each(|chunk| {
                S::shuffle_out(
                    chunk
                        .as_mut_ptr()
                        .cast::<Align64<[u32; 16]>>()
                        .as_mut()
                        .unwrap(),
                );
                S::shuffle_out(
                    chunk
                        .as_mut_ptr()
                        .cast::<Align64<[u32; 16]>>()
                        .add(1)
                        .as_mut()
                        .unwrap(),
                );
            });

        core::slice::from_raw_parts(v.as_ptr().add(r * n).cast::<u8>(), 128 * r)
    }
}

#[cfg_attr(
    all(target_arch = "x86_64", not(target_feature = "avx2")),
    scrypt_opt_derive::generate_target_variant("avx2")
)]
#[cfg_attr(
    not(all(target_arch = "x86_64", not(target_feature = "avx2"))),
    inline(always)
)]
fn ro_mix_interleaved_ex_dyn<'a, S: Salsa20<Lanes = U2>>(
    self_v: &mut [Align64<fixed_r::Block<U1>>],
    other_v: &mut [Align64<fixed_r::Block<U1>>],
    r: NonZeroU32,
    cf: NonZeroU8,
) -> &'a [u8] {
    let r = r.get() as usize;
    let n = 1 << cf.get();

    assert!(
        other_v.len() >= r * (n + 2),
        "ro_mix_interleaved_ex: other_v.len() < r * (n + 2)"
    );
    assert!(
        self_v.len() >= r * (n + 2),
        "ro_mix_interleaved_ex: self_v.len() < r * (n + 2)"
    );

    // SAFETY: other_v is always 64-byte aligned
    // SAFETY: other_v is at least r long
    unsafe {
        other_v.get_unchecked_mut(..r).iter_mut().for_each(|chunk| {
            S::shuffle_in(
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<[u32; 16]>>()
                    .as_mut()
                    .unwrap(),
            );
            S::shuffle_in(
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<[u32; 16]>>()
                    .add(1)
                    .as_mut()
                    .unwrap(),
            );
        });
    }

    for i in (0..n).step_by(2) {
        // SAFETY: the largest i value is n-1, so the largest index is n+1, which is in bounds after the >=n+2 check
        let [src, middle, dst] = unsafe {
            other_v.get_disjoint_unchecked_mut([
                (i * r)..((i + 1) * r),
                ((i + 1) * r)..((i + 2) * r),
                ((i + 2) * r)..((i + 3) * r),
            ])
        };

        {
            // Self: Compute T <- BlockMix(B ^ V[j])
            // Other: Compute V[i+1] <- BlockMix(V[i])
            let idx = unsafe {
                self_v
                    .as_ptr()
                    .add((n * r) as usize)
                    .cast::<u32>()
                    .add(r * 32 - 16)
                    .read()
            } as usize;

            let j = idx & (n - 1);

            let [in0, in1, out] = unsafe {
                self_v.get_disjoint_unchecked_mut([
                    (j * r)..((j + 1) * r),
                    (n * r)..((n + 1) * r),
                    ((n + 1) * r)..((n + 2) * r),
                ])
            };

            block_mix!(r; [<S> &&*src => &mut *middle, <S> &(&*in0, &*in1) => &mut *out]);
        }

        {
            // Self: Compute B <- BlockMix(T ^ V[j'])
            // Other: Compute V[i+2] <- BlockMix(V[i+1]) on last iteration it "naturally overflows" to V[n], so let B = V[n]
            let idx2 = unsafe {
                self_v
                    .as_ptr()
                    .add(((n + 1) * r) as usize)
                    .cast::<u32>()
                    .add(r * 32 - 16)
                    .read()
            } as usize;

            let j2 = idx2 & (n - 1);
            let [self_b, self_v, self_t] = unsafe {
                self_v.get_disjoint_unchecked_mut([
                    (n * r)..((n + 1) * r),
                    (j2 * r)..((j2 + 1) * r),
                    ((n + 1) * r)..((n + 2) * r),
                ])
            };

            block_mix!(r; [<S> &*middle => &mut *dst, <S> &(&*self_v, &*self_t) => &mut *self_b]);
        }
    }
    // SAFETY: n is at least 1, self_v is at least r * (n + 2) long
    unsafe {
        self_v
            .get_unchecked_mut(r * n..r * (n + 1))
            .iter_mut()
            .for_each(|chunk| {
                S::shuffle_out(
                    chunk
                        .as_mut_ptr()
                        .cast::<Align64<[u32; 16]>>()
                        .as_mut()
                        .unwrap(),
                );
                S::shuffle_out(
                    chunk
                        .as_mut_ptr()
                        .cast::<Align64<[u32; 16]>>()
                        .add(1)
                        .as_mut()
                        .unwrap(),
                );
            });

        core::slice::from_raw_parts(self_v.as_ptr().add(r * n).cast::<u8>(), 128 * r)
    }
}

impl<Q: AsRef<[Align64<fixed_r::Block<U1>>]> + AsMut<[Align64<fixed_r::Block<U1>>]>> RoMix for Q {
    fn ro_mix_input_buffer(&mut self, r: NonZeroU32) -> &mut [u8] {
        let r = r.get() as usize;
        let v = self.as_mut();
        assert!(v.len() >= r, "ro_mix_input_buffer: v.len() <  r");
        unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), 128 * r) }
    }

    fn ro_mix_front_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8) {
        let v = self.as_mut();

        #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe { ro_mix_front_ex_dyn_avx2::<salsa20::x86_64::BlockSse2<U1>>(v, r, cf) }
                return;
            }
        }

        ro_mix_front_ex_dyn::<S>(v, r, cf)
    }

    fn ro_mix_back_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8) -> &[u8] {
        let v = self.as_mut();

        #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                return unsafe {
                    ro_mix_back_ex_dyn_avx2::<salsa20::x86_64::BlockSse2<U1>>(v, r, cf)
                };
            }
        }

        ro_mix_back_ex_dyn::<S>(v, r, cf)
    }

    fn ro_mix_interleaved_ex<'a, S: Salsa20<Lanes = U2>>(
        &'a mut self,
        front: &mut Self,
        r: NonZeroU32,
        cf: NonZeroU8,
    ) -> &'a [u8] {
        let self_v = self.as_mut();
        let other_v = front.as_mut();

        #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                return unsafe {
                    ro_mix_interleaved_ex_dyn_avx2::<salsa20::x86_64::BlockAvx2Mb2>(
                        self_v, other_v, r, cf,
                    )
                };
            }
        }

        ro_mix_interleaved_ex_dyn::<S>(self_v, other_v, r, cf)
    }
}

/// Trait for loading a block from a buffer
pub trait ScryptBlockMixInput<'a, B: BlockType> {
    /// Load a block from the buffer
    unsafe fn load(&self, word_idx: usize) -> B;
}

impl<'a, B: BlockType> ScryptBlockMixInput<'a, B> for &'a [Align64<fixed_r::Block<U1>>] {
    #[inline(always)]
    unsafe fn load(&self, word_idx: usize) -> B {
        unsafe { B::read_from_ptr(self.as_ptr().cast::<[u8; 64]>().add(word_idx).cast()) }
    }
}

impl<'a, B: BlockType, Lhs: ScryptBlockMixInput<'a, B>, Rhs: ScryptBlockMixInput<'a, B>>
    ScryptBlockMixInput<'a, B> for (Lhs, Rhs)
{
    #[inline(always)]
    unsafe fn load(&self, word_idx: usize) -> B {
        let mut x0 = unsafe { self.0.load(word_idx) };
        let x1 = unsafe { self.1.load(word_idx) };
        x0.xor_with(x1);
        x0
    }
}

/// Trait for storing a block to a buffer
pub trait ScryptBlockMixOutput<'a, R: ArrayLength, B: BlockType> {
    /// Store even-numbered words
    fn store_even(&mut self, word_idx: usize, value: B);
    /// Store odd-numbered words
    fn store_odd(&mut self, word_idx: usize, value: B);
}

impl<
    'a,
    R: ArrayLength,
    B: BlockType,
    U: ScryptBlockMixOutput<'a, R, B>,
    V: ScryptBlockMixOutput<'a, R, B>,
> ScryptBlockMixOutput<'a, R, B> for (U, V)
{
    #[inline(always)]
    fn store_even(&mut self, word_idx: usize, value: B) {
        self.0.store_even(word_idx, value);
        self.1.store_even(word_idx, value);
    }
    #[inline(always)]
    fn store_odd(&mut self, word_idx: usize, value: B) {
        self.0.store_odd(word_idx, value);
        self.1.store_odd(word_idx, value);
    }
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::{U1, U2, U4, U8, U16};

    use super::*;
    use crate::{
        fixed_r::{Block, BufferSet},
        pbkdf2_1::Pbkdf2HmacSha256State,
        pipeline::PipelineContext,
    };

    macro_rules! write_test {
        ($name:ident, $test:ident, $($generic:ty),* $(,)?) => {
            #[test]
            fn $name() {
                $test::<$($generic),*>();
            }
        };
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    fn test_ro_mix_cas_zmm<R: ArrayLength + NonZero>() {
        const CF: u8 = 8;

        let password = b"password";
        let hmac = Pbkdf2HmacSha256State::new(password);
        let salt = b"salt";
        let mut expected = [0u8; 64];

        let params = scrypt::Params::new(CF, R::U32, 1, 64).unwrap();

        scrypt::scrypt(password, salt, &params, &mut expected).expect("scrypt failed");

        let mut buffers = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
        buffers.set_input(&hmac, salt);

        buffers.scrypt_ro_mix_ex_zmm::<salsa20::x86_64::BlockAvx512F>();

        let mut output = [0u8; 64];

        buffers.extract_output(&hmac, &mut output);

        assert_eq!(output, expected);
    }

    #[test]
    fn test_pipeline() {
        for cf in 1..=8 {
            let mut buffers0 = BufferSet::<_, U1>::new_boxed(cf.try_into().unwrap());
            let mut buffers1 = BufferSet::<_, U1>::new_boxed(cf.try_into().unwrap());

            let input_passwords = [
                b"password0".as_slice(),
                b"password1".as_slice(),
                b"password2".as_slice(),
                b"password3".as_slice(),
                b"password4".as_slice(),
                b"password5".as_slice(),
                b"password6".as_slice(),
                b"password7".as_slice(),
                b"password8".as_slice(),
                b"password9".as_slice(),
                b"password10".as_slice(),
            ];

            let input_salts = [
                b"salt0".as_slice(),
                b"salt1".as_slice(),
                b"salt2".as_slice(),
                b"salt3".as_slice(),
                b"salt4".as_slice(),
                b"salt5".as_slice(),
                b"salt6".as_slice(),
                b"salt7".as_slice(),
                b"salt8".as_slice(),
                b"salt9".as_slice(),
                b"salt10".as_slice(),
            ];

            struct Context<'a> {
                params: scrypt::Params,
                i: usize,
                total: usize,
                password: &'a [u8],
                salt: &'a [u8],
            }

            impl<'a, R: ArrayLength + NonZero> PipelineContext<usize, Vec<Align64<Block<R>>>, R, ()>
                for Context<'a>
            {
                fn begin(
                    &mut self,
                    _ratchet: &mut usize,
                    buffer_set: &mut BufferSet<Vec<Align64<Block<R>>>, R>,
                ) {
                    buffer_set.set_input(&Pbkdf2HmacSha256State::new(self.password), self.salt);
                }

                fn drain(
                    self,
                    ratchet: &mut usize,
                    buffer_set: &mut BufferSet<Vec<Align64<Block<R>>>, R>,
                ) -> Option<()> {
                    assert_eq!(*ratchet, self.i, "output should be in order");
                    assert!(*ratchet < self.total, "should have processed all passwords");
                    *ratchet += 1;
                    let mut output = [0u8; 64];
                    buffer_set
                        .extract_output(&Pbkdf2HmacSha256State::new(self.password), &mut output);
                    let mut expected = [0u8; 64];

                    scrypt::scrypt(self.password, self.salt, &self.params, &mut expected)
                        .expect("scrypt failed");

                    assert_eq!(output, expected, "unexpected output at round {}", self.i);

                    if *ratchet == self.total {
                        Some(())
                    } else {
                        None
                    }
                }
            }

            let params = scrypt::Params::new(cf, U1::U32, 1, 64).unwrap();

            // test all possible input counts
            for test_len in 0..input_passwords.len() {
                let mut ratchet = 0;
                let ret = buffers0.pipeline(
                    &mut buffers1,
                    input_passwords
                        .iter()
                        .zip(input_salts.iter())
                        .enumerate()
                        .map(|(i, (p, s))| Context {
                            params,
                            i,
                            total: test_len,
                            password: p,
                            salt: s,
                        })
                        .take(test_len),
                    &mut ratchet,
                );

                assert_eq!(
                    ret.is_some(),
                    test_len > 0,
                    "should have processed all passwords"
                );
            }
        }
    }

    fn test_ro_mix_cas<R: ArrayLength + NonZero>() {
        const CF: u8 = 8;

        let password = b"password";
        let salt = b"salt";
        let mut expected = [0u8; 64];

        let params = scrypt::Params::new(CF, R::U32, 1, 64).unwrap();

        scrypt::scrypt(password, salt, &params, &mut expected).expect("scrypt failed");

        let mut buffers = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());

        assert_eq!(buffers.n(), 1 << CF);

        buffers.set_input(&Pbkdf2HmacSha256State::new(password), salt);

        buffers.scrypt_ro_mix();

        let mut output = [0u8; 64];

        buffers.extract_output(&Pbkdf2HmacSha256State::new(password), &mut output);

        assert_eq!(output, expected);
    }

    fn test_ro_mix_cas_ex<R: ArrayLength + NonZero, S: Salsa20<Lanes = U1>>() {
        const CF: u8 = 8;

        let password = b"password";
        let salt = b"salt";
        let mut expected = [0u8; 64];

        let params = scrypt::Params::new(CF, R::U32, 1, 64).unwrap();

        scrypt::scrypt(password, salt, &params, &mut expected).expect("scrypt failed");

        let mut buffers = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());

        let mut buffer_dyn = vec![Default::default(); R::USIZE * ((1 << CF) + 2)];

        assert_eq!(buffers.n(), 1 << CF);

        buffers.set_input(&Pbkdf2HmacSha256State::new(password), salt);
        buffer_dyn
            .ro_mix_input_buffer(R::U32.try_into().unwrap())
            .copy_from_slice(buffers.input_buffer().as_slice());

        buffer_dyn.ro_mix_front_ex::<S>(R::U32.try_into().unwrap(), CF.try_into().unwrap());
        buffers.ro_mix_front_ex::<S>();
        let dyn_output =
            buffer_dyn.ro_mix_back_ex::<S>(R::U32.try_into().unwrap(), CF.try_into().unwrap());
        buffers.ro_mix_back_ex::<S>();

        assert_eq!(dyn_output, buffers.raw_salt_output().as_slice());

        let mut output = [0u8; 64];

        buffers.extract_output(&Pbkdf2HmacSha256State::new(password), &mut output);

        assert_eq!(output, expected);
    }

    fn test_ro_mix_cas_interleaved<R: ArrayLength + NonZero>() {
        const CF: u8 = 8;

        let passwords = [
            b"password0".as_slice(),
            b"password1".as_slice(),
            b"password2".as_slice(),
            b"password3".as_slice(),
            b"password4".as_slice(),
            b"password5".as_slice(),
            b"password6".as_slice(),
            b"password7".as_slice(),
            b"password8".as_slice(),
            b"password9".as_slice(),
            b"password10".as_slice(),
            b"password11".as_slice(),
            b"password12".as_slice(),
            b"password13".as_slice(),
            b"password14".as_slice(),
            b"password15".as_slice(),
        ];

        let mut expected = [[0u8; 64]; 16];

        for (i, password) in passwords.iter().enumerate() {
            let params = scrypt::Params::new(CF, R::U32, 1, 64).unwrap();
            scrypt::scrypt(password, b"salt", &params, &mut expected[i]).expect("scrypt failed");
        }

        let mut buffers0 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
        let mut buffers1 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());

        let mut output = [0u8; 64];
        buffers0.set_input(&Pbkdf2HmacSha256State::new(passwords[0]), b"salt");
        buffers1.set_input(&Pbkdf2HmacSha256State::new(passwords[1]), b"salt");
        buffers0.ro_mix_front();
        for i in 2..16 {
            buffers0.ro_mix_interleaved(&mut buffers1);
            buffers0.extract_output(&Pbkdf2HmacSha256State::new(passwords[i - 2]), &mut output);
            assert_eq!(output, expected[i - 2], "error at round {}", i);
            core::hint::black_box(&mut buffers0);
            (buffers0, buffers1) = (buffers1, buffers0);
            buffers1.set_input(&Pbkdf2HmacSha256State::new(passwords[i]), b"salt");
        }
        buffers0.ro_mix_back();
        buffers1.scrypt_ro_mix();
        buffers0.extract_output(&Pbkdf2HmacSha256State::new(passwords[14]), &mut output);
        assert_eq!(output, expected[14]);
        buffers1.extract_output(&Pbkdf2HmacSha256State::new(passwords[15]), &mut output);
        assert_eq!(output, expected[15]);
    }

    fn test_ro_mix_cas_interleaved_ex<
        R: ArrayLength + NonZero,
        S1: Salsa20<Lanes = U1>,
        S2: Salsa20<Lanes = U2>,
    >() {
        const CF: u8 = 8;

        let passwords = [
            b"password0".as_slice(),
            b"password1".as_slice(),
            b"password2".as_slice(),
            b"password3".as_slice(),
            b"password4".as_slice(),
            b"password5".as_slice(),
            b"password6".as_slice(),
            b"password7".as_slice(),
            b"password8".as_slice(),
            b"password9".as_slice(),
            b"password10".as_slice(),
            b"password11".as_slice(),
            b"password12".as_slice(),
            b"password13".as_slice(),
            b"password14".as_slice(),
            b"password15".as_slice(),
        ];

        let mut expected = [[0u8; 64]; 16];

        for (i, password) in passwords.iter().enumerate() {
            let params = scrypt::Params::new(CF, R::U32, 1, 64).unwrap();
            scrypt::scrypt(password, b"salt", &params, &mut expected[i]).expect("scrypt failed");
        }

        let mut buffers0 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
        let mut buffers1 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
        let mut buffers0_dyn = vec![Default::default(); R::USIZE * ((1 << CF) + 2)];
        let mut buffers1_dyn = vec![Default::default(); R::USIZE * ((1 << CF) + 2)];

        let mut output = [0u8; 64];
        buffers0.set_input(&Pbkdf2HmacSha256State::new(passwords[0]), b"salt");
        buffers1.set_input(&Pbkdf2HmacSha256State::new(passwords[1]), b"salt");
        buffers0_dyn
            .ro_mix_input_buffer(R::U32.try_into().unwrap())
            .copy_from_slice(buffers0.input_buffer().as_slice());
        buffers1_dyn
            .ro_mix_input_buffer(R::U32.try_into().unwrap())
            .copy_from_slice(buffers1.input_buffer().as_slice());

        buffers0.ro_mix_front_ex::<S1>();
        buffers0_dyn.ro_mix_front_ex::<S1>(R::U32.try_into().unwrap(), CF.try_into().unwrap());
        for i in 2..16 {
            buffers0.ro_mix_interleaved_ex::<S2>(&mut buffers1);
            let dyn_salt_output = buffers0_dyn.ro_mix_interleaved_ex::<S2>(
                &mut buffers1_dyn,
                R::U32.try_into().unwrap(),
                CF.try_into().unwrap(),
            );
            buffers0.extract_output(&Pbkdf2HmacSha256State::new(passwords[i - 2]), &mut output);
            assert_eq!(dyn_salt_output, buffers0.raw_salt_output().as_slice());

            assert_eq!(output, expected[i - 2], "error at round {}", i);
            core::hint::black_box(&mut buffers0);
            (buffers0, buffers1) = (buffers1, buffers0);
            (buffers0_dyn, buffers1_dyn) = (buffers1_dyn, buffers0_dyn);
            buffers1.set_input(&Pbkdf2HmacSha256State::new(passwords[i]), b"salt");
            buffers1_dyn
                .ro_mix_input_buffer(R::U32.try_into().unwrap())
                .copy_from_slice(buffers1.input_buffer().as_slice());
        }
        buffers0.ro_mix_back_ex::<S1>();
        let dyn_salt_output =
            buffers0_dyn.ro_mix_back_ex::<S1>(R::U32.try_into().unwrap(), CF.try_into().unwrap());
        assert_eq!(dyn_salt_output, buffers0.raw_salt_output().as_slice());

        buffers1.scrypt_ro_mix();
        buffers1_dyn.ro_mix_front_ex::<S1>(R::U32.try_into().unwrap(), CF.try_into().unwrap());
        let dyn_salt_output =
            buffers1_dyn.ro_mix_back_ex::<S1>(R::U32.try_into().unwrap(), CF.try_into().unwrap());
        assert_eq!(dyn_salt_output, buffers1.raw_salt_output().as_slice());

        buffers0.extract_output(&Pbkdf2HmacSha256State::new(passwords[14]), &mut output);
        assert_eq!(output, expected[14]);
        buffers1.extract_output(&Pbkdf2HmacSha256State::new(passwords[15]), &mut output);
        assert_eq!(output, expected[15]);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    mod avx512 {
        use super::*;

        fn test_ro_mix_cas_interleaved_zmm<R: ArrayLength + NonZero>() {
            const CF: u8 = 8;

            let passwords = [
                b"password0".as_slice(),
                b"password1".as_slice(),
                b"password2".as_slice(),
                b"password3".as_slice(),
                b"password4".as_slice(),
                b"password5".as_slice(),
                b"password6".as_slice(),
                b"password7".as_slice(),
                b"password8".as_slice(),
                b"password9".as_slice(),
                b"password10".as_slice(),
                b"password11".as_slice(),
                b"password12".as_slice(),
                b"password13".as_slice(),
                b"password14".as_slice(),
                b"password15".as_slice(),
            ];

            let hmacs: [Pbkdf2HmacSha256State; 16] =
                core::array::from_fn(|i| Pbkdf2HmacSha256State::new(passwords[i]));

            let mut expected = [[0u8; 64]; 16];

            for (i, password) in passwords.iter().enumerate() {
                let params = scrypt::Params::new(CF, R::U32, 1, 64).unwrap();
                scrypt::scrypt(password, b"salt", &params, &mut expected[i])
                    .expect("scrypt failed");
            }

            let mut buffers0 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
            let mut buffers1 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());

            let mut output = [0u8; 64];
            buffers0.set_input(&hmacs[0], b"salt");
            buffers1.set_input(&hmacs[1], b"salt");
            buffers0.ro_mix_front();
            for i in 2..16 {
                buffers0
                    .ro_mix_interleaved_ex_zmm::<salsa20::x86_64::BlockAvx512FMb2>(&mut buffers1);
                buffers0.extract_output(&hmacs[i - 2], &mut output);
                assert_eq!(output, expected[i - 2], "error at round {}", i);
                core::hint::black_box(&mut buffers0);
                (buffers0, buffers1) = (buffers1, buffers0);
                buffers1.set_input(&hmacs[i], b"salt");
            }
            buffers0.ro_mix_back();
            buffers1.scrypt_ro_mix();
            buffers0.extract_output(&hmacs[14], &mut output);
            assert_eq!(output, expected[14]);
            buffers1.extract_output(&hmacs[15], &mut output);
            assert_eq!(output, expected[15]);
        }

        write_test!(
            test_ro_mix_cas_avx512f_1,
            test_ro_mix_cas_ex,
            U1,
            salsa20::x86_64::BlockAvx512F
        );
        write_test!(
            test_ro_mix_cas_avx512f_2,
            test_ro_mix_cas_ex,
            U2,
            salsa20::x86_64::BlockAvx512F
        );
        write_test!(
            test_ro_mix_cas_avx512f_4,
            test_ro_mix_cas_ex,
            U4,
            salsa20::x86_64::BlockAvx512F
        );
        write_test!(
            test_ro_mix_cas_avx512f_8,
            test_ro_mix_cas_ex,
            U8,
            salsa20::x86_64::BlockAvx512F
        );

        write_test!(
            test_ro_mix_cas_avx512f_16,
            test_ro_mix_cas_ex,
            U16,
            salsa20::x86_64::BlockAvx512F
        );
        write_test!(
            test_ro_mix_cas_interleaved_avx512f_1,
            test_ro_mix_cas_interleaved_ex,
            U1,
            salsa20::x86_64::BlockAvx512F,
            salsa20::x86_64::BlockAvx512FMb2
        );
        write_test!(
            test_ro_mix_cas_interleaved_avx512f_2,
            test_ro_mix_cas_interleaved_ex,
            U2,
            salsa20::x86_64::BlockAvx512F,
            salsa20::x86_64::BlockAvx512FMb2
        );
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
        write_test!(
            test_ro_mix_cas_interleaved_avx512f_4,
            test_ro_mix_cas_interleaved_ex,
            U4,
            salsa20::x86_64::BlockAvx512F,
            salsa20::x86_64::BlockAvx512FMb2
        );
        write_test!(
            test_ro_mix_cas_interleaved_avx512f_8,
            test_ro_mix_cas_interleaved_ex,
            U8,
            salsa20::x86_64::BlockAvx512F,
            salsa20::x86_64::BlockAvx512FMb2
        );

        // AVX-512 register resident versions

        write_test!(test_ro_mix_cas_zmm_1, test_ro_mix_cas_zmm, U1);
        write_test!(test_ro_mix_cas_zmm_2, test_ro_mix_cas_zmm, U2);
        write_test!(test_ro_mix_cas_zmm_4, test_ro_mix_cas_zmm, U4);
        write_test!(test_ro_mix_cas_zmm_8, test_ro_mix_cas_zmm, U8);
        write_test!(
            test_ro_mix_cas_interleaved_zmm_1,
            test_ro_mix_cas_interleaved_zmm,
            U1
        );
        write_test!(
            test_ro_mix_cas_interleaved_zmm_2,
            test_ro_mix_cas_interleaved_zmm,
            U2
        );
        write_test!(
            test_ro_mix_cas_interleaved_zmm_4,
            test_ro_mix_cas_interleaved_zmm,
            U4
        );
        write_test!(
            test_ro_mix_cas_interleaved_zmm_8,
            test_ro_mix_cas_interleaved_zmm,
            U8
        );
    }

    // tests for whatever is the default/publicly visible version
    write_test!(test_ro_mix_cas_1, test_ro_mix_cas, U1);
    write_test!(test_ro_mix_cas_2, test_ro_mix_cas, U2);
    write_test!(test_ro_mix_cas_4, test_ro_mix_cas, U4);
    write_test!(test_ro_mix_cas_8, test_ro_mix_cas, U8);
    write_test!(test_ro_mix_cas_16, test_ro_mix_cas, U16);

    write_test!(
        test_ro_mix_cas_interleaved_1,
        test_ro_mix_cas_interleaved,
        U1
    );

    write_test!(
        test_ro_mix_cas_interleaved_2,
        test_ro_mix_cas_interleaved,
        U2
    );

    write_test!(
        test_ro_mix_cas_interleaved_4,
        test_ro_mix_cas_interleaved,
        U4
    );

    write_test!(
        test_ro_mix_cas_interleaved_8,
        test_ro_mix_cas_interleaved,
        U8
    );

    write_test!(
        test_ro_mix_cas_interleaved_16,
        test_ro_mix_cas_interleaved,
        U16
    );

    // AVX-2 versions
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    mod avx2 {
        use super::*;

        write_test!(
            test_ro_mix_cas_interleaved_1_avx2,
            test_ro_mix_cas_interleaved_ex,
            U1,
            salsa20::x86_64::BlockSse2<U1>,
            salsa20::x86_64::BlockAvx2Mb2
        );

        write_test!(
            test_ro_mix_cas_interleaved_2_avx2,
            test_ro_mix_cas_interleaved_ex,
            U2,
            salsa20::x86_64::BlockSse2<U1>,
            salsa20::x86_64::BlockAvx2Mb2
        );

        write_test!(
            test_ro_mix_cas_interleaved_4_avx2,
            test_ro_mix_cas_interleaved_ex,
            U4,
            salsa20::x86_64::BlockSse2<U1>,
            salsa20::x86_64::BlockAvx2Mb2
        );

        write_test!(
            test_ro_mix_cas_interleaved_8_avx2,
            test_ro_mix_cas_interleaved_ex,
            U8,
            salsa20::x86_64::BlockSse2<U1>,
            salsa20::x86_64::BlockAvx2Mb2
        );

        write_test!(
            test_ro_mix_cas_interleaved_16_avx2,
            test_ro_mix_cas_interleaved_ex,
            U16,
            salsa20::x86_64::BlockSse2<U1>,
            salsa20::x86_64::BlockAvx2Mb2
        );
    }

    #[cfg(target_arch = "x86_64")]
    write_test!(
        test_ro_mix_cas_1_sse2,
        test_ro_mix_cas_ex,
        U1,
        salsa20::x86_64::BlockSse2<U1>,
    );
    #[cfg(target_arch = "x86_64")]
    write_test!(
        test_ro_mix_cas_2_sse2,
        test_ro_mix_cas_ex,
        U2,
        salsa20::x86_64::BlockSse2<U1>,
    );
    #[cfg(target_arch = "x86_64")]
    write_test!(
        test_ro_mix_cas_4_sse2,
        test_ro_mix_cas_ex,
        U4,
        salsa20::x86_64::BlockSse2<U1>,
    );
    #[cfg(target_arch = "x86_64")]
    write_test!(
        test_ro_mix_cas_8_sse2,
        test_ro_mix_cas_ex,
        U8,
        salsa20::x86_64::BlockSse2<U1>,
    );
    #[cfg(target_arch = "x86_64")]
    write_test!(
        test_ro_mix_cas_16_sse2,
        test_ro_mix_cas_ex,
        U16,
        salsa20::x86_64::BlockSse2<U1>,
    );

    // scalar versions

    write_test!(
        test_ro_mix_cas_scalar_1,
        test_ro_mix_cas_ex,
        U1,
        salsa20::BlockScalar<U1>
    );

    write_test!(
        test_ro_mix_cas_scalar_2,
        test_ro_mix_cas_ex,
        U2,
        salsa20::BlockScalar<U1>
    );

    write_test!(
        test_ro_mix_cas_scalar_4,
        test_ro_mix_cas_ex,
        U4,
        salsa20::BlockScalar<U1>
    );

    write_test!(
        test_ro_mix_cas_scalar_8,
        test_ro_mix_cas_ex,
        U8,
        salsa20::BlockScalar<U1>
    );

    write_test!(
        test_ro_mix_cas_scalar_16,
        test_ro_mix_cas_ex,
        U16,
        salsa20::BlockScalar<U1>
    );

    write_test!(
        test_ro_mix_cas_scalar_interleaved_1,
        test_ro_mix_cas_interleaved_ex,
        U1,
        salsa20::BlockScalar<U1>,
        salsa20::BlockScalar<U2>
    );

    write_test!(
        test_ro_mix_cas_scalar_interleaved_2,
        test_ro_mix_cas_interleaved_ex,
        U2,
        salsa20::BlockScalar<U1>,
        salsa20::BlockScalar<U2>
    );

    write_test!(
        test_ro_mix_cas_scalar_interleaved_4,
        test_ro_mix_cas_interleaved_ex,
        U4,
        salsa20::BlockScalar<U1>,
        salsa20::BlockScalar<U2>
    );

    write_test!(
        test_ro_mix_cas_scalar_interleaved_8,
        test_ro_mix_cas_interleaved_ex,
        U8,
        salsa20::BlockScalar<U1>,
        salsa20::BlockScalar<U2>
    );

    write_test!(
        test_ro_mix_cas_scalar_interleaved_16,
        test_ro_mix_cas_interleaved_ex,
        U16,
        salsa20::BlockScalar<U1>,
        salsa20::BlockScalar<U2>
    );

    // portable SIMD versions

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_1,
        test_ro_mix_cas_ex,
        U1,
        salsa20::BlockPortableSimd
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_2,
        test_ro_mix_cas_ex,
        U2,
        salsa20::BlockPortableSimd
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_4,
        test_ro_mix_cas_ex,
        U4,
        salsa20::BlockPortableSimd
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_8,
        test_ro_mix_cas_ex,
        U8,
        salsa20::BlockPortableSimd
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_16,
        test_ro_mix_cas_ex,
        U16,
        salsa20::BlockPortableSimd
    );

    // portable SIMD interleaved versions

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_interleaved_1,
        test_ro_mix_cas_interleaved_ex,
        U1,
        salsa20::BlockPortableSimd,
        salsa20::BlockPortableSimd2
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_interleaved_2,
        test_ro_mix_cas_interleaved_ex,
        U2,
        salsa20::BlockPortableSimd,
        salsa20::BlockPortableSimd2
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_interleaved_4,
        test_ro_mix_cas_interleaved_ex,
        U4,
        salsa20::BlockPortableSimd,
        salsa20::BlockPortableSimd2
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_interleaved_8,
        test_ro_mix_cas_interleaved_ex,
        U8,
        salsa20::BlockPortableSimd,
        salsa20::BlockPortableSimd2
    );

    #[cfg(feature = "portable-simd")]
    write_test!(
        test_ro_mix_cas_portable_simd_interleaved_16,
        test_ro_mix_cas_interleaved_ex,
        U16,
        salsa20::BlockPortableSimd,
        salsa20::BlockPortableSimd2
    );
}
