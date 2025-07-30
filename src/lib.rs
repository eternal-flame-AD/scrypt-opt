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
macro_rules! repeat4 {
    ($i:ident, $c:block) => {
        { let $i = 0; $c; }
        { let $i = 1; $c; }
        { let $i = 2; $c; }
        { let $i = 3; $c; }
    };
}

#[rustfmt::skip]
macro_rules! repeat8 {
    ($i:ident, $b:block) => {{
        repeat4!(di, { let $i = di; $b });
        repeat4!(di, { let $i = di + 4; $b });
    }};
}

macro_rules! integerify {
    (<$r:ty> $x:expr) => {{
        let input: &crate::Block<R> = $x;

        debug_assert_eq!(
            input.as_ptr().align_offset(64),
            0,
            "unexpected input alignment"
        );
        debug_assert_eq!(input.len(), Mul128::<R>::USIZE, "unexpected input length");
        #[allow(unused_unsafe)]
        unsafe {
            input
                .as_ptr()
                .cast::<u8>()
                .add(Mul128::<R>::USIZE - 64)
                .cast::<u32>()
                .read() as usize
        }
    }};
}

#[rustfmt::skip]
macro_rules! match_r {
    ($r:expr, $b:ident, $c:block) => {{
        use generic_array::typenum::*;

        match $r {
            1 => { type $b = U1; Some($c) },
            2 => { type $b = U2; Some($c) },
            3 => { type $b = U3; Some($c) },
            4 => { type $b = U4; Some($c) },
            5 => { type $b = U5; Some($c) },
            6 => { type $b = U6; Some($c) },
            7 => { type $b = U7; Some($c) },
            8 => { type $b = U8; Some($c) },
            9 => { type $b = U9; Some($c) },
            10 => { type $b = U10; Some($c) },
            11 => { type $b = U11; Some($c) },
            12 => { type $b = U12; Some($c) },
            13 => { type $b = U13; Some($c) },
            14 => { type $b = U14; Some($c) },
            15 => { type $b = U15; Some($c) },
            16 => { type $b = U16; Some($c) },
            17 => { type $b = U17; Some($c) },
            18 => { type $b = U18; Some($c) },
            19 => { type $b = U19; Some($c) },
            20 => { type $b = U20; Some($c) },
            21 => { type $b = U21; Some($c) },
            22 => { type $b = U22; Some($c) },
            23 => { type $b = U23; Some($c) },
            24 => { type $b = U24; Some($c) },
            25 => { type $b = U25; Some($c) },
            26 => { type $b = U26; Some($c) },
            27 => { type $b = U27; Some($c) },
            28 => { type $b = U28; Some($c) },
            29 => { type $b = U29; Some($c) },
            30 => { type $b = U30; Some($c) },
            31 => { type $b = U31; Some($c) },
            32 => { type $b = U32; Some($c) },
            _ => None,
        }
    }};
}

/// Re-export sha2
pub use sha2;

/// Re-export hmac
pub use hmac;

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
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) mod sha2_mb;

/// Runtime feature detection
pub mod features;

/// Compat APIs
#[cfg(any(feature = "std", target_arch = "wasm32"))]
pub mod compat;

use core::num::{NonZeroU8, NonZeroU32};

use generic_array::typenum::{
    B1, IsLess, IsLessOrEqual, PowerOfTwo, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13,
    U14, U15, U16, U17, U18, U19, U20, U21, U22, U23, U24, U25, U26, U27, U28, U29, U30, U31,
    U4294967296, Unsigned,
};

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{B0, NonZero, UInt},
};

#[allow(unused_imports)]
use crate::features::Feature as _;

use crate::memory::Align64;
use crate::pbkdf2_1::Pbkdf2HmacSha256State;
use crate::pipeline::PipelineContext;
use crate::salsa20::{BlockType, Salsa20};

include!("block_mix.rs");

type Mul2<U> = UInt<U, B0>;
type Mul4<U> = UInt<Mul2<U>, B0>;
type Mul8<U> = UInt<Mul4<U>, B0>;
type Mul16<U> = UInt<Mul8<U>, B0>;
type Mul32<U> = UInt<Mul16<U>, B0>;
type Mul64<U> = UInt<Mul32<U>, B0>;
type Mul128<U> = UInt<Mul64<U>, B0>;

#[cfg(target_arch = "x86_64")]
cfg_if::cfg_if! {
    if #[cfg(target_feature = "avx512f")] {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::x86_64::BlockAvx512F;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::x86_64::BlockAvx512FMb2;
    } else if #[cfg(target_feature = "avx2")] {
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine1 = salsa20::x86_64::BlockAvx2;
        /// The default engine for this architecture that is guaranteed to be available
        pub type DefaultEngine2 = salsa20::x86_64::BlockAvx2Mb2;
    } else if #[cfg(feature = "portable-simd")] {
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
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
const MAX_R_FOR_FULL_INTERLEAVED_ZMM: usize = 6; // 6 * 2 * 2 = 24 registers
const MAX_R_FOR_UNROLLING: usize = 8;

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

/// The type for one block for scrypt BlockMix operation (128 bytes/1R)
pub type Block<R> = GenericArray<u8, Mul128<R>>;

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
/// Scrypt with a fixed R value
pub struct BufferSet<
    Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>,
    R: ArrayLength + NonZero,
> {
    v: Q,
    _r: core::marker::PhantomData<R>,
}

impl<Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]> + Default, R: ArrayLength + NonZero>
    Default for BufferSet<Q, R>
{
    #[inline(always)]
    fn default() -> Self {
        Self::new(Q::default())
    }
}

impl<Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>, R: ArrayLength + NonZero> AsRef<Q>
    for BufferSet<Q, R>
{
    fn as_ref(&self) -> &Q {
        &self.v
    }
}

impl<Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>, R: ArrayLength + NonZero> AsMut<Q>
    for BufferSet<Q, R>
{
    fn as_mut(&mut self) -> &mut Q {
        &mut self.v
    }
}

#[cfg(feature = "alloc")]
impl<R: ArrayLength + NonZero> BufferSet<alloc::vec::Vec<Align64<Block<R>>>, R> {
    /// Create a new buffer set in a box with a given Cost Factor (log2(N))
    #[inline(always)]
    pub fn new_boxed(cf: core::num::NonZeroU8) -> alloc::boxed::Box<Self> {
        let mut v = alloc::vec::Vec::new();
        v.resize(minimum_blocks(cf), Align64::<Block<R>>::default());
        alloc::boxed::Box::new(Self {
            v,
            _r: core::marker::PhantomData,
        })
    }
}

#[cfg(feature = "alloc")]
impl<R: ArrayLength + NonZero> BufferSet<memory::MaybeHugeSlice<Align64<Block<R>>>, R> {
    /// Create a new buffer set in a huge page with a given Cost Factor (log2(N))
    #[inline(always)]
    pub fn new_maybe_huge_slice(
        cf: core::num::NonZeroU8,
    ) -> BufferSet<memory::MaybeHugeSlice<Align64<Block<R>>>, R> {
        BufferSet {
            v: memory::MaybeHugeSlice::new_maybe(minimum_blocks(cf)),
            _r: core::marker::PhantomData,
        }
    }

    /// Create a new buffer set in a huge page with a given Cost Factor (log2(N))
    #[inline(always)]
    #[cfg(feature = "std")]
    pub fn new_maybe_huge_slice_ex(
        cf: core::num::NonZeroU8,
    ) -> (
        BufferSet<memory::MaybeHugeSlice<Align64<Block<R>>>, R>,
        Option<std::io::Error>,
    ) {
        let (v, e) = memory::MaybeHugeSlice::new(minimum_blocks(cf));
        (
            BufferSet {
                v,
                _r: core::marker::PhantomData,
            },
            e,
        )
    }
}

#[inline(always)]
/// Convert a number of blocks to a Cost Factor (log2(N - 2))
pub const fn length_to_cf(l: usize) -> u8 {
    let v = (l.saturating_sub(2)) as u32;
    ((32 - v.leading_zeros()) as u8).saturating_sub(1)
}

/// Get the minimum number of blocks required for a given Cost Factor ((1 << cf) + 2)
#[inline(always)]
pub const fn minimum_blocks(cf: NonZeroU8) -> usize {
    let r = 1 << cf.get();
    r + 2
}

/// Generalized RoMix interface with a runtime R value
pub trait RoMix {
    /// Perform the front part of the $RoMix$ operation
    fn ro_mix_front_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8);
    /// Perform the back part of the $RoMix$ operation
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_back_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8) -> &[u8];
    /// Interleave the front and back parts of the $RoMix$ operation in two independent buffers
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_interleaved_ex<'a, S: Salsa20<Lanes = U2>>(
        &'a mut self,
        front: &mut Self,
        r: NonZeroU32,
        cf: NonZeroU8,
    ) -> &'a [u8];

    /// Get the input buffer for the $RoMix$ operation
    fn ro_mix_input_buffer(&mut self, r: NonZeroU32) -> &mut [u8];

    /// Perform the front part of the $RoMix$ operation
    fn ro_mix_front(&mut self, r: NonZeroU32, cf: NonZeroU8) {
        self.ro_mix_front_ex::<DefaultEngine1>(r, cf);
    }
    /// Perform the back part of the $RoMix$ operation
    ///
    /// Return: the raw salt output for the completed $RoMix$ operation
    fn ro_mix_back(&mut self, r: NonZeroU32, cf: NonZeroU8) -> &[u8] {
        self.ro_mix_back_ex::<DefaultEngine1>(r, cf)
    }
    /// Interleave the front and back parts of the $RoMix$ operation in two independent buffers
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
    v: &mut [Align64<[u8; 64]>],
    r: NonZeroU32,
    cf: NonZeroU8,
) {
    let r = r.get() as usize;
    let n = 1 << cf.get();
    assert!(
        v.len() >= 2 * r * (n + 1),
        "ro_mix_front_ex: v.len() < 2 * r * (n + 1)"
    );

    unsafe {
        v[..(2 * r)].iter_mut().for_each(|chunk| {
            S::shuffle_in(
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<[u32; 16]>>()
                    .as_mut()
                    .unwrap(),
            );
        });
    }

    for i in 0..n {
        let [src, dst] = unsafe {
            v.get_disjoint_unchecked_mut([
                (i * (2 * r))..((i + 1) * (2 * r)),
                ((i + 1) * (2 * r))..((i + 2) * (2 * r)),
            ])
        };
        block_mix_dyn!(r; [<S> &*src => &mut *dst]);
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
    v: &mut [Align64<[u8; 64]>],
    r: NonZeroU32,
    cf: NonZeroU8,
) -> &[u8] {
    let r = r.get() as usize;
    let n = 1 << cf.get();
    assert!(
        v.len() >= 2 * r * (n + 2),
        "pipeline_end_ex: v.len() < 2n + 2"
    );

    for _ in (0..n).step_by(2) {
        let idx = unsafe {
            v.as_ptr()
                .add((n * 2 * r) as usize)
                .cast::<u32>()
                .add(r * 32 - 16)
                .read()
        } as usize;

        let j = idx & (n - 1);

        // SAFETY: the largest j value is n-1, so the largest index of the 3 is n+1, which is in bounds after the >=n+2 check
        let [in0, in1, out] = unsafe {
            v.get_disjoint_unchecked_mut([
                (n * (2 * r))..((n + 1) * (2 * r)),
                (j * (2 * r))..((j + 1) * (2 * r)),
                ((n + 1) * (2 * r))..((n + 2) * (2 * r)),
            ])
        };
        block_mix_dyn!(r; [<S> &(&*in0, &*in1) => &mut *out]);
        let idx2 = unsafe {
            v.as_ptr()
                .add(((n + 1) * 2 * r) as usize)
                .cast::<u32>()
                .add(r * 32 - 16)
                .read()
        } as usize;

        let j2 = idx2 & (n - 1);

        // SAFETY: the largest j2 value is n-1, so the largest index of the 3 is n+1, which is in bounds after the >=n+2 check
        let [b, v, t] = unsafe {
            v.get_disjoint_unchecked_mut([
                (n * (2 * r))..((n + 1) * (2 * r)),
                (j2 * (2 * r))..((j2 + 1) * (2 * r)),
                ((n + 1) * (2 * r))..((n + 2) * (2 * r)),
            ])
        };
        block_mix_dyn!(r; [<S> &(&*v, &*t) => &mut *b]);
    }

    unsafe {
        v[(2 * r * n)..(2 * r * (n + 1))]
            .iter_mut()
            .for_each(|chunk| {
                S::shuffle_out(
                    chunk
                        .as_mut_ptr()
                        .cast::<Align64<[u32; 16]>>()
                        .as_mut()
                        .unwrap(),
                );
            });

        core::slice::from_raw_parts(v.as_ptr().add(2 * r * n).cast::<u8>(), 128 * r)
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
    self_v: &mut [Align64<[u8; 64]>],
    other_v: &mut [Align64<[u8; 64]>],
    r: NonZeroU32,
    cf: NonZeroU8,
) -> &'a [u8] {
    let r = r.get() as usize;
    let n = 1 << cf.get();

    assert!(
        other_v.len() >= 2 * r * (n + 2),
        "ro_mix_interleaved_ex: other_v.len() < 2 * r * (n + 2)"
    );
    assert!(
        self_v.len() >= 2 * r * (n + 2),
        "ro_mix_interleaved_ex: self_v.len() < 2 * r * (n + 2)"
    );

    // SAFETY: other_v is always 64-byte aligned
    unsafe {
        other_v[..(2 * r)].iter_mut().for_each(|chunk| {
            S::shuffle_in(
                chunk
                    .as_mut_ptr()
                    .cast::<Align64<[u32; 16]>>()
                    .as_mut()
                    .unwrap(),
            );
        });
    }

    for i in (0..n).step_by(2) {
        // SAFETY: the largest i value is n-1, so the largest index is n+1, which is in bounds after the >=n+2 check
        let [src, middle, dst] = unsafe {
            other_v.get_disjoint_unchecked_mut([
                (i * (2 * r))..((i + 1) * (2 * r)),
                ((i + 1) * (2 * r))..((i + 2) * (2 * r)),
                ((i + 2) * (2 * r))..((i + 3) * (2 * r)),
            ])
        };

        {
            // Self: Compute T <- BlockMix(B ^ V[j])
            // Other: Compute V[i+1] <- BlockMix(V[i])
            let idx = unsafe {
                self_v
                    .as_ptr()
                    .add((n * 2 * r) as usize)
                    .cast::<u32>()
                    .add(r * 32 - 16)
                    .read()
            } as usize;

            let j = idx & (n - 1);

            let [in0, in1, out] = unsafe {
                self_v.get_disjoint_unchecked_mut([
                    (j * (2 * r))..((j + 1) * (2 * r)),
                    (n * (2 * r))..((n + 1) * (2 * r)),
                    ((n + 1) * (2 * r))..((n + 2) * (2 * r)),
                ])
            };

            block_mix_dyn!(r; [<S> &&*src => &mut *middle, <S> &(&*in0, &*in1) => &mut *out]);
        }

        {
            // Self: Compute B <- BlockMix(T ^ V[j'])
            // Other: Compute V[i+2] <- BlockMix(V[i+1]) on last iteration it "naturally overflows" to V[n], so let B = V[n]
            let idx2 = unsafe {
                self_v
                    .as_ptr()
                    .add(((n + 1) * 2 * r) as usize)
                    .cast::<u32>()
                    .add(r * 32 - 16)
                    .read()
            } as usize;

            let j2 = idx2 & (n - 1);
            let [self_b, self_v, self_t] = unsafe {
                self_v.get_disjoint_unchecked_mut([
                    (n * (2 * r))..((n + 1) * (2 * r)),
                    (j2 * (2 * r))..((j2 + 1) * (2 * r)),
                    ((n + 1) * (2 * r))..((n + 2) * (2 * r)),
                ])
            };

            block_mix_dyn!(r; [<S> &*middle => &mut *dst, <S> &(&*self_v, &*self_t) => &mut *self_b]);
        }
    }
    unsafe {
        self_v[(2 * r * n)..(2 * r * (n + 1))]
            .iter_mut()
            .for_each(|chunk| {
                S::shuffle_out(
                    chunk
                        .as_mut_ptr()
                        .cast::<Align64<[u32; 16]>>()
                        .as_mut()
                        .unwrap(),
                );
            });

        core::slice::from_raw_parts(self_v.as_ptr().add(2 * r * n).cast::<u8>(), 128 * r)
    }
}

impl<Q: AsRef<[Align64<[u8; 64]>]> + AsMut<[Align64<[u8; 64]>]>> RoMix for Q {
    fn ro_mix_input_buffer(&mut self, r: NonZeroU32) -> &mut [u8] {
        let r = r.get() as usize;
        let v = self.as_mut();
        assert!(v.len() >= 2 * r, "ro_mix_input_buffer: v.len() < 2 * r");
        unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), 128 * r) }
    }

    fn ro_mix_front_ex<S: Salsa20<Lanes = U1>>(&mut self, r: NonZeroU32, cf: NonZeroU8) {
        let v = self.as_mut();

        #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe { ro_mix_front_ex_dyn_avx2::<salsa20::x86_64::BlockAvx2>(v, r, cf) }
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
                return unsafe { ro_mix_back_ex_dyn_avx2::<salsa20::x86_64::BlockAvx2>(v, r, cf) };
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

impl<Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>, R: ArrayLength + NonZero>
    BufferSet<Q, R>
{
    /// Create a new buffer set
    ///
    /// # Panics
    ///
    /// Panics if the number of blocks is less than 4 or greater than MAX_N + 2.
    pub fn new(q: Q) -> Self {
        let l = q.as_ref().len();
        assert!(l >= 4, "number of blocks must be at least 4");
        assert!(
            l - 2 <= MAX_N as usize,
            "number of blocks must be at most MAX_N + 2"
        );
        Self {
            v: q,
            _r: core::marker::PhantomData,
        }
    }

    /// Create a new buffer set if the number of blocks is between 4 and MAX_N + 2
    ///
    /// # Returns
    ///
    /// None if the number of blocks is less than 4 or greater than MAX_N + 2
    pub fn try_new(q: Q) -> Option<Self> {
        let l = q.as_ref().len();
        if l < 4 {
            return None;
        }
        if l > MAX_N as usize + 2 {
            return None;
        }
        Some(Self {
            v: q,
            _r: core::marker::PhantomData,
        })
    }

    /// Consume the buffer set and return the inner buffer
    pub fn into_inner(self) -> Q {
        self.v
    }

    /// Get the block buffer as 32-bit words
    pub fn input_buffer(&self) -> &Align64<Block<R>> {
        &self.v.as_ref()[0]
    }

    /// Get the block buffer mutably as 32-bit words
    pub fn input_buffer_mut(&mut self) -> &mut Align64<Block<R>> {
        &mut self.v.as_mut()[0]
    }

    /// Set the input for the block buffer
    #[inline(always)]
    pub fn set_input(&mut self, hmac_state: &Pbkdf2HmacSha256State, salt: &[u8]) {
        hmac_state.emit_scatter(salt, [self.input_buffer_mut()]);
    }

    #[inline(always)]
    /// Get the effective Cost Factor (log2(N)) for the buffer set
    pub fn cf(&self) -> u8 {
        let l = self.v.as_ref().len();

        length_to_cf(l)
    }

    #[inline(always)]
    /// Get the effective N value for the buffer set
    pub fn n(&self) -> usize {
        let cf = self.cf();
        1 << cf
    }

    /// Get the raw salt output, useful for concatenation for P>1 cases
    #[inline(always)]
    pub fn raw_salt_output(&self) -> &Align64<Block<R>> {
        unsafe { self.v.as_ref().get_unchecked(self.n()) }
    }

    /// Extract the output from the block buffer
    #[inline(always)]
    pub fn extract_output(&self, hmac_state: &Pbkdf2HmacSha256State, output: &mut [u8]) {
        hmac_state.emit_gather([self.raw_salt_output()], output);
    }

    /// Shorten the buffer set into a smaller buffer set and return the remainder as a slice,
    /// handy if you want to make a large allocation for the largest N you want to use and reuse it for multiple Cost Factors.
    ///
    /// # Returns
    ///
    /// None if the number of blocks is less than the minimum number of blocks for the given Cost Factor.
    #[inline(always)]
    pub fn shorten(
        &mut self,
        cf: NonZeroU8,
    ) -> Option<(
        BufferSet<&mut [Align64<Block<R>>], R>,
        &mut [Align64<Block<R>>],
    )> {
        let min_blocks = minimum_blocks(cf);
        let (set, rest) = self.v.as_mut().split_at_mut_checked(min_blocks)?;
        Some((
            BufferSet {
                v: set,
                _r: core::marker::PhantomData,
            },
            rest,
        ))
    }

    /// Start an interleaved pipeline.
    #[cfg_attr(
        all(target_arch = "x86_64", not(target_feature = "avx2")),
        scrypt_opt_derive::generate_target_variant("avx2")
    )]
    fn ro_mix_front_ex<S: Salsa20<Lanes = U1>>(&mut self) {
        let v = self.v.as_mut();
        let n = 1 << length_to_cf(v.len());

        // at least n+1 long, this is already enforced by length_to_cf so we can disable it for release builds
        debug_assert!(v.len() > n, "ro_mix_front_ex: v.len() < n");

        unsafe {
            v.get_unchecked_mut(0)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_in(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap(),
                    );
                });
        }

        for i in 0..n {
            let [src, dst] = unsafe { v.get_disjoint_unchecked_mut([i, i + 1]) };
            block_mix!(R::USIZE; [<S> &*src => &mut *dst]);
        }
    }

    /// Drain an interleaved pipeline.
    #[cfg_attr(
        all(target_arch = "x86_64", not(target_feature = "avx2")),
        scrypt_opt_derive::generate_target_variant("avx2")
    )]
    fn ro_mix_back_ex<S: Salsa20<Lanes = U1>>(&mut self) {
        let v = self.v.as_mut();
        let n = 1 << length_to_cf(v.len());
        // at least n+2 long, this is already enforced by length_to_cf so we can disable it for release builds
        debug_assert!(v.len() >= n + 2, "pipeline_end_ex: v.len() < n + 2");

        for _ in (0..n).step_by(2) {
            let idx = integerify!(<R> unsafe { v.get_unchecked(n) });

            let j = idx & (n - 1);

            // SAFETY: the largest j value is n-1, so the largest index of the 3 is n+1, which is in bounds after the >=n+2 check
            let [in0, in1, out] = unsafe { v.get_disjoint_unchecked_mut([n, j, n + 1]) };
            block_mix!(R::USIZE; [<S> (&*in0, &*in1) => &mut *out]);
            let idx2 = integerify!(<R> unsafe { v.get_unchecked(n + 1) });

            let j2 = idx2 & (n - 1);

            // SAFETY: the largest j2 value is n-1, so the largest index of the 3 is n+1, which is in bounds after the >=n+2 check
            let [b, v, t] = unsafe { v.get_disjoint_unchecked_mut([n, j2, n + 1]) };
            block_mix!(R::USIZE; [<S> (&*v, &*t) => &mut *b]);
        }

        unsafe {
            v.get_unchecked_mut(n)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_out(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap(),
                    );
                });
        }
    }

    #[cfg_attr(
        all(target_arch = "x86_64", not(target_feature = "avx2")),
        scrypt_opt_derive::generate_target_variant("avx2")
    )]
    /// Interleaved RoMix operation.
    ///
    /// $RoMix_{Back}$ is performed on self and $RoMix_{Front}$ is performed on other.
    ///
    /// # Panics
    ///
    /// Panics if the buffers are of different equivalent Cost Factors.
    fn ro_mix_interleaved_ex<S: Salsa20<Lanes = U2>>(&mut self, other: &mut Self) {
        let self_v = self.v.as_mut();
        let other_v = other.v.as_mut();
        let self_cf = length_to_cf(self_v.len());
        let other_cf = length_to_cf(other_v.len());
        assert_eq!(
            self_cf, other_cf,
            "ro_mix_interleaved_ex: self_cf != other_cf, are you passing two buffers of the same size?"
        );
        let n = 1 << self_cf;

        // at least n+2 long, this is already enforced by n() so we can disable it for release builds
        debug_assert!(
            other_v.len() >= n + 2,
            "ro_mix_interleaved_ex: other_v.len() < n + 2"
        );
        // at least n+2 long, this is already enforced by n() so we can disable it for release builds
        debug_assert!(
            other_v.len() >= n + 2,
            "ro_mix_interleaved_ex: other_v.len() < n + 2"
        );

        // SAFETY: other_v is always 64-byte aligned
        unsafe {
            other_v
                .get_unchecked_mut(0)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_in(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap_unchecked(),
                    );
                });
        }

        for i in (0..n).step_by(2) {
            // SAFETY: the largest i value is n-1, so the largest index is n+1, which is in bounds after the >=n+2 check
            let [src, middle, dst] =
                unsafe { other_v.get_disjoint_unchecked_mut([i, i + 1, i + 2]) };

            {
                // Self: Compute T <- BlockMix(B ^ V[j])
                // Other: Compute V[i+1] <- BlockMix(V[i])
                let idx = integerify!(<R> unsafe { self_v.get_unchecked(n) });

                let j = idx & (n - 1);

                let [in0, in1, out] = unsafe { self_v.get_disjoint_unchecked_mut([j, n, n + 1]) };

                block_mix!(R::USIZE; [<S> &*src => &mut *middle, <S> (&*in0, &*in1) => &mut *out]);
            }

            {
                // Self: Compute B <- BlockMix(T ^ V[j'])
                // Other: Compute V[i+2] <- BlockMix(V[i+1]) on last iteration it "naturally overflows" to V[n], so let B = V[n]
                let idx2 = integerify!(<R> unsafe { self_v.get_unchecked(n + 1) });

                let j2 = idx2 & (n - 1);
                let [self_b, self_v, self_t] =
                    unsafe { self_v.get_disjoint_unchecked_mut([n, j2, n + 1]) };

                block_mix!(R::USIZE; [<S> &*middle => &mut *dst, <S> (&*self_v, &*self_t) => &mut *self_b]);
            }
        }

        // SAFETY: self_v is always 64-byte aligned
        unsafe {
            self_v
                .get_unchecked_mut(n)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_out(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap_unchecked(),
                    );
                });
        }
    }

    /// Start an interleaved pipeline using the default engine by performing the $RoMix_{Front}$ operation.
    #[inline(always)]
    pub fn ro_mix_front(&mut self) {
        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe {
                    self.ro_mix_front_ex_avx2::<crate::salsa20::x86_64::BlockAvx2>();
                }
                return;
            }
        }

        self.ro_mix_front_ex::<DefaultEngine1>();
    }

    /// Drain an interleaved pipeline using the default engine by performing the $RoMix_{Back}$ operation.
    #[inline(always)]
    pub fn ro_mix_back(&mut self) {
        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe {
                    self.ro_mix_back_ex_avx2::<crate::salsa20::x86_64::BlockAvx2>();
                }
                return;
            }
        }

        self.ro_mix_back_ex::<DefaultEngine1>();
    }

    /// Perform the RoMix operation using the default engine.
    pub fn scrypt_ro_mix(&mut self) {
        // If possible, redirect to the register resident implementation to avoid data access thrashing.
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
        if R::USIZE <= MAX_R_FOR_UNROLLING {
            self.scrypt_ro_mix_ex_zmm::<salsa20::x86_64::BlockAvx512F>();
            return;
        }

        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe {
                    self.ro_mix_front_ex_avx2::<crate::salsa20::x86_64::BlockAvx2>();
                    self.ro_mix_back_ex_avx2::<crate::salsa20::x86_64::BlockAvx2>();
                }
                return;
            }
        }

        self.ro_mix_front_ex::<DefaultEngine1>();
        self.ro_mix_back_ex::<DefaultEngine1>();
    }

    /// Perform the RoMix operation with interleaved buffers.
    ///
    /// $RoMix_{Back}$ is performed on self and $RoMix_{Front}$ is performed on other.
    ///
    /// # Panics
    ///
    /// Panics if the buffers are of different equivalent Cost Factors.
    pub fn ro_mix_interleaved(&mut self, other: &mut Self) {
        // If possible, steer to the register-resident AVX-512 implementation to avoid cache line thrashing.
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
        if R::USIZE <= MAX_R_FOR_UNROLLING {
            self.ro_mix_interleaved_ex_zmm::<salsa20::x86_64::BlockAvx512FMb2>(other);
            return;
        }

        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe {
                    self.ro_mix_interleaved_ex_avx2::<crate::salsa20::x86_64::BlockAvx2Mb2>(other);
                }
                return;
            }
        }

        self.ro_mix_interleaved_ex::<DefaultEngine2>(other);
    }

    /// Pipeline RoMix operations on an iterator of inputs.
    pub fn pipeline<K, S, C: PipelineContext<S, Q, R, K>, I: IntoIterator<Item = C>>(
        &mut self,
        other: &mut Self,
        iter: I,
        state: &mut S,
    ) -> Option<K> {
        let mut iter = iter.into_iter();

        let (mut buffers0, mut buffers1) = (&mut *self, &mut *other);
        let Some(mut input_m2) = iter.next() else {
            return None;
        };
        input_m2.begin(state, buffers0);
        let Some(mut input_m1) = iter.next() else {
            buffers0.scrypt_ro_mix();
            return input_m2.drain(state, buffers0);
        };
        input_m1.begin(state, buffers1);

        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if features::Avx2.check() {
                unsafe {
                    buffers0.ro_mix_front_ex_avx2::<crate::salsa20::x86_64::BlockAvx2>();
                    loop {
                        buffers0
                            .ro_mix_interleaved_ex_avx2::<crate::salsa20::x86_64::BlockAvx2Mb2>(
                                buffers1,
                            );
                        if let Some(k) = input_m2.drain(state, buffers0) {
                            return Some(k);
                        }

                        (buffers0, buffers1) = (buffers1, buffers0);

                        let Some(mut input) = iter.next() else {
                            break;
                        };

                        input.begin(state, buffers1);

                        input_m2 = input_m1;
                        input_m1 = input;
                    }
                    buffers0.ro_mix_back_ex_avx2::<crate::salsa20::x86_64::BlockAvx2>();
                    return input_m1.drain(state, buffers0);
                }
            }
        }

        buffers0.ro_mix_front();
        loop {
            buffers0.ro_mix_interleaved(buffers1);
            if let Some(k) = input_m2.drain(state, buffers0) {
                return Some(k);
            }

            (buffers0, buffers1) = (buffers1, buffers0);

            let Some(mut input) = iter.next() else {
                break;
            };

            input.begin(state, buffers1);

            input_m2 = input_m1;
            input_m1 = input;
        }
        buffers0.ro_mix_back();
        input_m1.drain(state, buffers0)
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl<Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>, R: ArrayLength + NonZero>
    BufferSet<Q, R>
{
    /// Perform the RoMix operation using AVX-512 registers as temporary storage.
    #[inline(always)]
    fn scrypt_ro_mix_ex_zmm<S: Salsa20<Lanes = U1, Block = core::arch::x86_64::__m512i>>(
        &mut self,
    ) {
        assert!(
            R::USIZE <= MAX_R_FOR_UNROLLING,
            "scrypt_ro_mix_ex_zmm: R > {}",
            MAX_R_FOR_UNROLLING
        );
        let v = self.v.as_mut();
        let n = 1 << length_to_cf(v.len());
        // at least n+1 long, this is checked by length_to_cf
        debug_assert!(v.len() > n, "scrypt_ro_mix_ex_zmm: v.len() <= n");

        unsafe {
            v.get_unchecked_mut(0)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_in(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap(),
                    );
                });

            let mut input_b = InRegisterAdapter::<R>::new();
            for i in 0..(n - 1) {
                let [src, dst] = v.get_disjoint_unchecked_mut([i, i + 1]);
                block_mix!(R::USIZE; [<S> &*src => &mut *dst]);
            }
            block_mix!(R::USIZE; [<S> v.get_unchecked(n - 1) => &mut input_b]);

            let mut idx = input_b.extract_idx() as usize & (n - 1);

            for _ in (0..n).step_by(2) {
                // for some reason this doesn't spill, so let's leave it as is
                let mut input_t = InRegisterAdapter::<R>::new();
                block_mix!(R::USIZE; [<S> (&input_b, v.get_unchecked(idx) ) => &mut input_t]);

                idx = input_t.extract_idx() as usize & (n - 1);

                block_mix!(R::USIZE; [<S> (&input_t, v.get_unchecked(idx)) => &mut input_b]);

                idx = input_b.extract_idx() as usize & (n - 1);
            }

            // SAFETY: n is in bounds after the >=n+1 check
            input_b.write_back(v.get_unchecked_mut(n));

            v.get_unchecked_mut(n)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_out(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap(),
                    );
                });
        }
    }

    /// Perform a paired-halves RoMix operation with interleaved buffers using AVX-512 registers as temporary storage for the latter (this) half pipeline.
    ///
    /// The former half is performed on `other` and the latter half is performed on `self`.
    ///
    /// # Panics
    ///
    /// Panics if the buffers are of different equivalent Cost Factors.
    #[inline(always)]
    fn ro_mix_interleaved_ex_zmm<S: Salsa20<Lanes = U2, Block = core::arch::x86_64::__m512i>>(
        &mut self,
        other: &mut Self,
    ) {
        assert!(
            R::USIZE <= MAX_R_FOR_UNROLLING,
            "ro_mix_interleaved_ex_zmm: R > {}",
            MAX_R_FOR_UNROLLING
        );
        let self_v = self.v.as_mut();
        let other_v = other.v.as_mut();

        let self_cf = length_to_cf(self_v.len());
        let other_cf = length_to_cf(other_v.len());
        assert_eq!(
            self_cf, other_cf,
            "ro_mix_interleaved_ex_zmm: self_cf != other_cf, are you passing two buffers of the same size?"
        );
        let n = 1 << self_cf;

        // at least n+2 long, this is already enforced by n() so we can disable it for release builds
        debug_assert!(
            other_v.len() >= n + 1,
            "ro_mix_interleaved_ex_zmm: other.v.len() < n + 1"
        );
        // at least n+2 long, this is already enforced by n() so we can disable it for release builds
        debug_assert!(
            self_v.len() >= n + 1,
            "ro_mix_interleaved_ex_zmm: self.v.len() < n + 1"
        );

        unsafe {
            other_v
                .get_unchecked_mut(0)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_in(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap(),
                    );
                });
        }

        let mut idx = integerify!(<R> unsafe { self_v.get_unchecked(n) });
        idx = idx & (n - 1);
        let mut input_b =
            InRegisterAdapter::<R>::init_with_block(unsafe { self_v.get_unchecked(n) });

        for i in (0..n).step_by(2) {
            let mut input_t = InRegisterAdapter::<R>::new();
            // SAFETY: the largest i value is n-2, so the largest index is n, which is in bounds after the >=n+1 check
            let [src, middle, dst] =
                unsafe { other_v.get_disjoint_unchecked_mut([i, i + 1, i + 2]) };

            let [self_vj, self_t] = unsafe { self_v.get_disjoint_unchecked_mut([idx, n + 1]) };
            if R::USIZE <= MAX_R_FOR_FULL_INTERLEAVED_ZMM {
                block_mix!(R::USIZE; [<S> &*src => &mut *middle, <S> (&*self_vj, &input_b) => &mut input_t]);
                idx = input_t.extract_idx() as usize & (n - 1);
            } else {
                block_mix!(
                    R::USIZE; [<S> &*src => &mut *middle, <S> (&*self_vj, &input_b) => &mut *self_t]
                );
                idx = integerify!(<R> self_t ) & (n - 1);
            }

            let [self_vj, self_t] = unsafe { self_v.get_disjoint_unchecked_mut([idx, n + 1]) };
            {
                if R::USIZE <= MAX_R_FOR_FULL_INTERLEAVED_ZMM {
                    block_mix!(R::USIZE; [<S> &*middle => &mut *dst, <S> (&*self_vj, &input_t) => &mut input_b]);
                } else {
                    block_mix!(R::USIZE; [<S> &*middle => &mut *dst, <S> (&*self_vj, &*self_t) => &mut input_b]);
                }

                idx = input_b.extract_idx() as usize & (n - 1);
            }
        }

        input_b.write_back(unsafe { self_v.get_unchecked_mut(n) });

        unsafe {
            self_v
                .get_unchecked_mut(n)
                .chunks_exact_mut(64)
                .for_each(|chunk| {
                    S::shuffle_out(
                        chunk
                            .as_mut_ptr()
                            .cast::<Align64<[u32; 16]>>()
                            .as_mut()
                            .unwrap(),
                    );
                });
        }
    }
}

/// Trait for loading a block from a buffer
pub trait ScryptBlockMixInput<'a, B: BlockType> {
    /// Load a block from the buffer
    unsafe fn load(&self, word_idx: usize) -> B;
}

impl<'a, B: BlockType> ScryptBlockMixInput<'a, B> for &'a [Align64<[u8; 64]>] {
    #[inline(always)]
    unsafe fn load(&self, word_idx: usize) -> B {
        unsafe { B::read_from_ptr(self[word_idx].as_ptr().cast()) }
    }
}

impl<'a, R: ArrayLength, B: BlockType> ScryptBlockMixInput<'a, B> for &'a Align64<Block<R>> {
    #[inline(always)]
    unsafe fn load(&self, word_idx: usize) -> B {
        unsafe { B::read_from_ptr(self.as_ptr().add(word_idx * 64).cast()) }
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

impl<'a, R: ArrayLength, B: BlockType> ScryptBlockMixOutput<'a, R, B>
    for &'a mut Align64<Block<R>>
{
    #[inline(always)]
    fn store_even(&mut self, word_idx: usize, value: B) {
        debug_assert!(word_idx * 64 < self.len() / 2);
        unsafe { B::write_to_ptr(value, self.as_mut_ptr().add(word_idx * 64).cast()) }
    }
    #[inline(always)]
    fn store_odd(&mut self, word_idx: usize, value: B) {
        debug_assert!(Mul64::<R>::USIZE + word_idx * 64 < self.len());
        unsafe {
            B::write_to_ptr(
                value,
                self.as_mut_ptr()
                    .add(Mul64::<R>::USIZE + word_idx * 64)
                    .cast(),
            )
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[repr(align(64))]
struct InRegisterAdapter<R: ArrayLength> {
    words: GenericArray<core::arch::x86_64::__m512i, Mul2<R>>,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl<R: ArrayLength> InRegisterAdapter<R> {
    #[inline(always)]
    fn new() -> Self {
        Self {
            words: unsafe { core::mem::MaybeUninit::uninit().assume_init() },
        }
    }

    #[inline(always)]
    fn init_with_block(block: &Align64<Block<R>>) -> Self {
        use generic_array::sequence::GenericSequence;
        Self {
            words: unsafe {
                GenericArray::generate(|i| {
                    core::arch::x86_64::_mm512_load_si512(block.as_ptr().add(i * 64).cast())
                })
            },
        }
    }

    #[inline(always)]
    fn write_back(&mut self, output: &mut Align64<Block<R>>) {
        use core::arch::x86_64::*;
        unsafe {
            for i in 0..R::USIZE {
                _mm512_store_si512(output.as_mut_ptr().add(i * 128).cast(), self.words[i * 2]);
                _mm512_store_si512(
                    output.as_mut_ptr().add(i * 128 + 64).cast(),
                    self.words[i * 2 + 1],
                );
            }
        }
    }

    #[inline(always)]
    fn extract_idx(&self) -> u32 {
        unsafe {
            core::arch::x86_64::_mm_cvtsi128_si32(core::arch::x86_64::_mm512_castsi512_si128(
                self.words[R::USIZE * 2 - 1],
            )) as u32
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl<'a, R: ArrayLength> ScryptBlockMixInput<'a, core::arch::x86_64::__m512i>
    for &'a InRegisterAdapter<R>
{
    #[inline(always)]
    unsafe fn load(&self, word_idx: usize) -> core::arch::x86_64::__m512i {
        self.words[word_idx]
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl<'a, R: ArrayLength> ScryptBlockMixOutput<'a, R, core::arch::x86_64::__m512i>
    for &'a mut InRegisterAdapter<R>
{
    #[inline(always)]
    fn store_even(&mut self, word_idx: usize, value: core::arch::x86_64::__m512i) {
        self.words[word_idx] = value;
    }
    #[inline(always)]
    fn store_odd(&mut self, word_idx: usize, value: core::arch::x86_64::__m512i) {
        self.words[R::USIZE + word_idx] = value;
    }
}

#[cfg(test)]
mod tests {
    use generic_array::{
        sequence::GenericSequence,
        typenum::{U1, U2, U4, U8, U16},
    };

    use super::*;

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

    #[test]
    fn test_block_mix() {
        type R = U4;

        let input0: Align64<Block<R>> = Align64(GenericArray::generate(|i| i as u8));
        let input1: Align64<Block<R>> = Align64(GenericArray::generate(|i| (i + 1) as u8));
        let mut input0_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE];
        input0_dyn
            .iter_mut()
            .map(|r| r.as_mut_slice())
            .flatten()
            .zip(input0.as_slice().iter())
            .for_each(|(a, b)| *a = *b);
        let mut input1_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE];
        input1_dyn
            .iter_mut()
            .map(|r| r.as_mut_slice())
            .flatten()
            .zip(input1.as_slice().iter())
            .for_each(|(a, b)| *a = *b);

        let mut output_0: Align64<Block<R>> = Align64(GenericArray::default());
        let mut output_1: Align64<Block<R>> = Align64(GenericArray::default());
        let mut output_0_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE];
        let mut output_1_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE];

        let mut output_0_v = Align64(GenericArray::default());
        let mut output_1_v = Align64(GenericArray::default());

        block_mix!(R::USIZE; [<DefaultEngine1> &input0 => &mut output_0]);
        block_mix!(R::USIZE; [<DefaultEngine1> &input1 => &mut output_1]);
        block_mix!(R::USIZE; [<DefaultEngine2> &input0 => &mut output_0_v, <DefaultEngine2> &input1 => &mut output_1_v]);
        block_mix_dyn::<_, DefaultEngine1, _>(&input0_dyn.as_slice(), &mut output_0_dyn);
        let output_0_dyn_bytes = output_0_dyn
            .iter()
            .map(|r| r.as_slice())
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(output_0.as_slice(), output_0_dyn_bytes);

        output_0_dyn.fill(Align64([0u8; 64]));

        block_mix_dyn_mb2::<_, DefaultEngine2, _, _>(
            &input0_dyn.as_slice(),
            &mut output_0_dyn,
            &input1_dyn.as_slice(),
            &mut output_1_dyn,
        );
        let output_0_dyn_bytes = output_0_dyn
            .iter()
            .map(|r| r.as_slice())
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let output_1_dyn_bytes = output_1_dyn
            .iter()
            .map(|r| r.as_slice())
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(output_0.as_slice(), output_0_dyn_bytes);
        assert_eq!(output_1.as_slice(), output_1_dyn_bytes);

        assert_eq!(output_0, output_0_v);
        assert_eq!(output_1, output_1_v);
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

        let mut buffer_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE * ((1 << CF) + 2)];

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
        let mut buffers0_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE * ((1 << CF) + 2)];
        let mut buffers1_dyn = vec![Align64([0u8; 64]); 2 * R::USIZE * ((1 << CF) + 2)];

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
            scrypt::scrypt(password, b"salt", &params, &mut expected[i]).expect("scrypt failed");
        }

        let mut buffers0 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
        let mut buffers1 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());

        let mut output = [0u8; 64];
        buffers0.set_input(&hmacs[0], b"salt");
        buffers1.set_input(&hmacs[1], b"salt");
        buffers0.ro_mix_front();
        for i in 2..16 {
            buffers0.ro_mix_interleaved_ex_zmm::<salsa20::x86_64::BlockAvx512FMb2>(&mut buffers1);
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

    macro_rules! write_test {
        ($name:ident, $test:ident, $($generic:ty),* $(,)?) => {
            #[test]
            fn $name() {
                $test::<$($generic),*>();
            }
        };
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
    write_test!(
        test_ro_mix_cas_interleaved_1_avx2,
        test_ro_mix_cas_interleaved_ex,
        U1,
        salsa20::x86_64::BlockAvx2,
        salsa20::x86_64::BlockAvx2Mb2
    );

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_interleaved_2_avx2,
        test_ro_mix_cas_interleaved_ex,
        U2,
        salsa20::x86_64::BlockAvx2,
        salsa20::x86_64::BlockAvx2Mb2
    );

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_interleaved_4_avx2,
        test_ro_mix_cas_interleaved_ex,
        U4,
        salsa20::x86_64::BlockAvx2,
        salsa20::x86_64::BlockAvx2Mb2
    );

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_interleaved_8_avx2,
        test_ro_mix_cas_interleaved_ex,
        U8,
        salsa20::x86_64::BlockAvx2,
        salsa20::x86_64::BlockAvx2Mb2
    );

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_interleaved_16_avx2,
        test_ro_mix_cas_interleaved_ex,
        U16,
        salsa20::x86_64::BlockAvx2,
        salsa20::x86_64::BlockAvx2Mb2
    );

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_1_avx2,
        test_ro_mix_cas_ex,
        U1,
        salsa20::x86_64::BlockAvx2,
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_2_avx2,
        test_ro_mix_cas_ex,
        U2,
        salsa20::x86_64::BlockAvx2,
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_4_avx2,
        test_ro_mix_cas_ex,
        U4,
        salsa20::x86_64::BlockAvx2,
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_8_avx2,
        test_ro_mix_cas_ex,
        U8,
        salsa20::x86_64::BlockAvx2,
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    write_test!(
        test_ro_mix_cas_16_avx2,
        test_ro_mix_cas_ex,
        U16,
        salsa20::x86_64::BlockAvx2,
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

    // AVX-512 versions

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_avx512f_1,
        test_ro_mix_cas_ex,
        U1,
        salsa20::x86_64::BlockAvx512F
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_avx512f_2,
        test_ro_mix_cas_ex,
        U2,
        salsa20::x86_64::BlockAvx512F
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_avx512f_4,
        test_ro_mix_cas_ex,
        U4,
        salsa20::x86_64::BlockAvx512F
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_avx512f_8,
        test_ro_mix_cas_ex,
        U8,
        salsa20::x86_64::BlockAvx512F
    );

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_avx512f_16,
        test_ro_mix_cas_ex,
        U16,
        salsa20::x86_64::BlockAvx512F
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_interleaved_avx512f_1,
        test_ro_mix_cas_interleaved_ex,
        U1,
        salsa20::x86_64::BlockAvx512F,
        salsa20::x86_64::BlockAvx512FMb2
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
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
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_interleaved_avx512f_8,
        test_ro_mix_cas_interleaved_ex,
        U8,
        salsa20::x86_64::BlockAvx512F,
        salsa20::x86_64::BlockAvx512FMb2
    );

    // AVX-512 register resident versions

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(test_ro_mix_cas_zmm_1, test_ro_mix_cas_zmm, U1);
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(test_ro_mix_cas_zmm_2, test_ro_mix_cas_zmm, U2);
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(test_ro_mix_cas_zmm_4, test_ro_mix_cas_zmm, U4);
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(test_ro_mix_cas_zmm_8, test_ro_mix_cas_zmm, U8);

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_interleaved_zmm_1,
        test_ro_mix_cas_interleaved_zmm,
        U1
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_interleaved_zmm_2,
        test_ro_mix_cas_interleaved_zmm,
        U2
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_interleaved_zmm_4,
        test_ro_mix_cas_interleaved_zmm,
        U4
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    write_test!(
        test_ro_mix_cas_interleaved_zmm_8,
        test_ro_mix_cas_interleaved_zmm,
        U8
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
