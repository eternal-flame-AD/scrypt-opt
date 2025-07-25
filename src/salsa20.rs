#![cfg_attr(
    any(
        all(
            target_arch = "x86_64",
            target_feature = "avx512f",
            feature = "portable-simd"
        ),
        all(
            not(feature = "portable-simd"),
            not(all(target_arch = "x86_64", target_feature = "avx512f"))
        )
    ),
    allow(
        unused,
        reason = "APIs that allow switching cores in code are not exposed to the public API, yet"
    )
)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(unused_imports)]
use generic_array::{
    ArrayLength, GenericArray,
    sequence::GenericSequence,
    typenum::{U1, U2},
};

#[cfg(feature = "portable-simd")]
#[allow(unused_imports)]
use core::simd::{Swizzle as _, num::SimdUint, u32x4, u32x8, u32x16};

#[allow(
    unused_imports,
    reason = "rust-analyzer doesn't consider -Ctarget-feature, silencing warnings"
)]
use crate::{
    Align64,
    simd::{Compose, ConcatLo, ExtractU32x2, Inverse, Swizzle},
};

#[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
macro_rules! mm_rol_epi32x {
    ($w:expr, $amt:literal) => {
        _mm_rol_epi32($w, $amt)
    };
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
macro_rules! mm256_rol_epi32x {
    ($w:expr, $amt:literal) => {
        _mm256_rol_epi32($w, $amt)
    };
}

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx512vl")))]
#[allow(unused_macros)]
// LLVM can rewrite this as _mm512_rol_epi32(_mm512_zextsi128_si512(w), $amt) automatically on AVX512F
macro_rules! mm_rol_epi32x {
    ($w:expr, $amt:literal) => {{
        let w = $w;
        _mm_or_si128(_mm_slli_epi32(w, $amt), _mm_srli_epi32(w, 32 - $amt))
    }};
}

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx512vl")))]
#[allow(unused_macros)]
// LLVM can rewrite this as _mm512_rol_epi32(_mm512_zextsi256_si512(w), $amt) automatically on AVX512F
macro_rules! mm256_rol_epi32x {
    ($w:expr, $amt:literal) => {{
        let w = $w;
        _mm256_or_si256(_mm256_slli_epi32(w, $amt), _mm256_srli_epi32(w, 32 - $amt))
    }};
}

macro_rules! quarter_words {
    ($w:expr, $a:literal, $b:literal, $c:literal, $d:literal) => {
        $w[$b] ^= $w[$a].wrapping_add($w[$d]).rotate_left(7);
        $w[$c] ^= $w[$b].wrapping_add($w[$a]).rotate_left(9);
        $w[$d] ^= $w[$c].wrapping_add($w[$b]).rotate_left(13);
        $w[$a] ^= $w[$d].wrapping_add($w[$c]).rotate_left(18);
    };
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
macro_rules! quarter_xmmwords {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $b = _mm_xor_si128($b, mm_rol_epi32x!(_mm_add_epi32($a, $d), 7));
        $c = _mm_xor_si128($c, mm_rol_epi32x!(_mm_add_epi32($b, $a), 9));
        $d = _mm_xor_si128($d, mm_rol_epi32x!(_mm_add_epi32($c, $b), 13));
        $a = _mm_xor_si128($a, mm_rol_epi32x!(_mm_add_epi32($d, $c), 18));
    };
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
macro_rules! quarter_ymmwords {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $b = _mm256_xor_si256($b, mm256_rol_epi32x!(_mm256_add_epi32($a, $d), 7));
        $c = _mm256_xor_si256($c, mm256_rol_epi32x!(_mm256_add_epi32($b, $a), 9));
        $d = _mm256_xor_si256($d, mm256_rol_epi32x!(_mm256_add_epi32($c, $b), 13));
        $a = _mm256_xor_si256($a, mm256_rol_epi32x!(_mm256_add_epi32($d, $c), 18));
    };
}

/// Pivot to column-major order
struct Pivot;

impl Swizzle<16> for Pivot {
    const INDEX: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
}

/// Pivot two independent blocks into column-major order, extract A and B
struct Pivot2Ab;

impl Swizzle<16> for Pivot2Ab {
    const INDEX: [usize; 16] = const {
        let mut index = [0; 16];
        let mut i = 0;
        while i < 16 {
            let offset = if (i / 4) % 2 == 0 { 0 } else { 16 };
            index[i] = <Pivot as Swizzle<16>>::INDEX[i / 8 * 4 + i % 4] + offset;
            i += 1;
        }
        index
    };
}

/// Pivot two independent blocks into column-major order, extract C and D
struct Pivot2CdFlipped;

impl Swizzle<16> for Pivot2CdFlipped {
    const INDEX: [usize; 16] = const {
        let mut index = [0; 16];
        let mut i = 0;
        while i < 16 {
            let offset = if (i / 4) % 2 == 1 { 0 } else { 16 };
            index[i] = <Pivot as Swizzle<16>>::INDEX[8 + i / 8 * 4 + i % 4] + offset;
            i += 1;
        }
        index
    };
}

/// Round shuffle the first 4 lanes of a vector of u32
#[allow(unused, reason = "rust-analyzer spam, actually used")]
struct RoundShuffleAbcd;

impl Swizzle<16> for RoundShuffleAbcd {
    const INDEX: [usize; 16] = const {
        let mut index = [0; 16];
        let mut i = 0;
        while i < 4 {
            index[i] = i;
            i += 1;
        }
        while i < 8 {
            index[i] = 12 + (i + 1) % 4;
            i += 1;
        }
        while i < 12 {
            index[i] = 8 + (i + 2) % 4;
            i += 1;
        }
        while i < 16 {
            index[i] = 4 + (i + 3) % 4;
            i += 1;
        }
        index
    };
}

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Pivot {
    const INDEX: [usize; 16] = <Self as Swizzle<16>>::INDEX;
}

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Pivot2Ab {
    const INDEX: [usize; 16] = <Self as Swizzle<16>>::INDEX;
}

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Pivot2CdFlipped {
    const INDEX: [usize; 16] = <Self as Swizzle<16>>::INDEX;
}

/// A trait for block types
pub trait BlockType: Clone + Copy {
    /// Read a block from a pointer
    unsafe fn read_from_ptr(ptr: *const Self) -> Self;
    /// Write a block to a pointer
    unsafe fn write_to_ptr(self, ptr: *mut Self);
    /// XOR a block with another block
    fn xor_with(&mut self, other: Self);
}

#[cfg(target_arch = "x86_64")]
impl BlockType for __m512i {
    unsafe fn read_from_ptr(ptr: *const Self) -> Self {
        unsafe { _mm512_load_si512(ptr.cast::<__m512i>()) }
    }
    unsafe fn write_to_ptr(self, ptr: *mut Self) {
        unsafe { _mm512_store_si512(ptr.cast::<__m512i>(), self) }
    }
    fn xor_with(&mut self, other: Self) {
        unsafe {
            *self = _mm512_xor_si512(*self, other);
        }
    }
}

#[allow(unused_mut)]
impl BlockType for Align64<[u32; 16]> {
    unsafe fn read_from_ptr(ptr: *const Self) -> Self {
        let mut ret = unsafe { ptr.read() };

        #[cfg(target_endian = "big")]
        for i in 0..16 {
            ret.0[i] = ret.0[i].swap_bytes();
        }

        #[cfg(target_endian = "little")]
        return ret;
    }
    unsafe fn write_to_ptr(mut self, ptr: *mut Self) {
        #[cfg(target_endian = "big")]
        for i in 0..16 {
            self.0[i] = self.0[i].swap_bytes();
        }

        unsafe { ptr.write(self) }
    }
    fn xor_with(&mut self, other: Self) {
        for i in 0..16 {
            self.0[i] ^= other.0[i];
        }
    }
}

#[cfg(feature = "portable-simd")]
impl BlockType for core::simd::u32x16 {
    unsafe fn read_from_ptr(ptr: *const Self) -> Self {
        let ret = unsafe { ptr.read() };

        #[cfg(target_endian = "big")]
        return ret.swap_bytes();

        #[cfg(target_endian = "little")]
        return ret;
    }
    unsafe fn write_to_ptr(self, ptr: *mut Self) {
        #[cfg(target_endian = "big")]
        unsafe {
            ptr.write(self.swap_bytes())
        };

        #[cfg(target_endian = "little")]
        unsafe {
            ptr.write(self)
        };
    }
    fn xor_with(&mut self, other: Self) {
        *self ^= other;
    }
}

/// A trait for salsa20 block types
pub(crate) trait Salsa20 {
    /// The number of lanes
    type Lanes: ArrayLength;
    /// The block type
    type Block: BlockType;

    /// Read block(s)
    fn read(ptr: GenericArray<&Self::Block, Self::Lanes>) -> Self;
    /// Write block(s) back
    fn write(&self, ptr: GenericArray<&mut Self::Block, Self::Lanes>);
    /// Apply the keystream to the block(s)
    fn keystream<const ROUND_PAIRS: usize>(&mut self);
}

/// A scalar solution
#[allow(unused, reason = "Currently unused, but handy for testing")]
pub struct BlockScalar<Lanes: ArrayLength> {
    w: GenericArray<[u32; 16], Lanes>,
}

impl<Lanes: ArrayLength> Salsa20 for BlockScalar<Lanes> {
    type Lanes = Lanes;
    type Block = Align64<[u32; 16]>;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, Lanes>) -> Self {
        Self {
            w: GenericArray::generate(|i| **ptr[i]),
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, Lanes>) {
        for i in 0..Lanes::USIZE {
            for j in 0..16 {
                ptr[i][j] = self.w[i][j];
            }
        }
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        if ROUND_PAIRS == 0 {
            return;
        }

        let mut w = self.w.clone();

        for i in 0..Lanes::USIZE {
            for _ in 0..ROUND_PAIRS {
                quarter_words!(w[i], 0, 4, 8, 12);
                quarter_words!(w[i], 5, 9, 13, 1);
                quarter_words!(w[i], 10, 14, 2, 6);
                quarter_words!(w[i], 15, 3, 7, 11);

                quarter_words!(w[i], 0, 1, 2, 3);
                quarter_words!(w[i], 5, 6, 7, 4);
                quarter_words!(w[i], 10, 11, 8, 9);
                quarter_words!(w[i], 15, 12, 13, 14);
            }
        }

        for i in 0..Lanes::USIZE {
            for j in 0..16 {
                self.w[i][j] = self.w[i][j].wrapping_add(w[i][j]);
            }
        }
    }
}

/// A solution for 1 lane of 512-bit blocks
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub struct BlockAvx512F {
    save: __m512i,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl Salsa20 for BlockAvx512F {
    type Lanes = U1;
    type Block = __m512i;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U1>) -> Self {
        let w = *ptr[0];

        Self { save: w }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U1>) {
        *ptr[0] = self.save;
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        if ROUND_PAIRS == 0 {
            return;
        }

        unsafe {
            let t = _mm512_permutexvar_epi32(Pivot::INDEX_ZMM, self.save);
            let mut a = _mm512_extracti32x4_epi32(t, 0);
            let mut b = _mm512_extracti32x4_epi32(t, 1);
            let mut c = _mm512_extracti32x4_epi32(t, 2);
            let mut d = _mm512_extracti32x4_epi32(t, 3);

            for _ in 0..(ROUND_PAIRS * 2 - 1) {
                quarter_xmmwords!(a, b, c, d);

                // a stays in place
                // b = left shuffle d by 1 element
                let newb = _mm_shuffle_epi32(d, 0b00111001);
                // c = left shuffle c by 2 elements
                c = _mm_shuffle_epi32(c, 0b01001110);
                // d = left shuffle b by 3 elements
                d = _mm_shuffle_epi32(b, 0b10010011);
                b = newb;
            }

            quarter_xmmwords!(a, b, c, d);

            self.save = _mm512_add_epi32(
                self.save,
                _mm512_permutex2var_epi32(
                    _mm512_zextsi256_si512(_mm256_setr_m128i(a, b)),
                    ConcatLo::<_, Compose<_, RoundShuffleAbcd, Inverse<_, Pivot>>>::INDEX_ZMM,
                    _mm512_zextsi256_si512(_mm256_setr_m128i(c, d)),
                ),
            );
        }
    }
}

/// A solution for 2 lanes of 512-bit blocks
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub struct BlockAvx512F2 {
    buf0: __m512i,
    buf1: __m512i,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl Salsa20 for BlockAvx512F2 {
    type Lanes = U2;
    type Block = __m512i;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U2>) -> Self {
        Self {
            buf0: *ptr[0],
            buf1: *ptr[1],
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U2>) {
        *ptr[0] = self.buf0;
        *ptr[1] = self.buf1;
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        if ROUND_PAIRS == 0 {
            return;
        }

        unsafe {
            use crate::simd::{Compose, ExtractU32x2, Inverse};

            // has initial value for buffer 0 and takes output AB
            let mut save_0_ab_out = self.buf0;
            // has initial value for buffer 1 and takes output CD
            let mut save_1_cd_out = self.buf1;

            let mut b: __m256i;
            let mut d: __m256i;

            // force a more compact version for stability, sometimes LLVM generates a 4xvpermt2d version
            // that isn't as good and takes away registers that could be used for keeping a temporary buffer
            // in registers
            //
            // SAFETY: gated behind target_feature = "avx512f"
            core::arch::asm!(
                "vpermt2d {save_0_ab_out}, {perm_ab}, {save_1_cd_out}",
                "vextracti64x4 {b}, {save_0_ab_out}, 1",
                "vpermt2d {save_1_cd_out}, {perm_cd_flipped}, {save_0_alias}",
                "vextracti64x4 {d}, {save_1_cd_out}, 1",
                save_0_ab_out = inout(zmm_reg) save_0_ab_out,
                save_0_alias = in(zmm_reg) self.buf0,
                save_1_cd_out = inout(zmm_reg) save_1_cd_out,
                perm_ab = in(zmm_reg) Pivot2Ab::INDEX_ZMM,
                perm_cd_flipped = in(zmm_reg) Pivot2CdFlipped::INDEX_ZMM,
                b = out(ymm_reg) b,
                d = out(ymm_reg) d,
                options(pure, nomem, nostack),
            );

            let mut a = _mm512_castsi512_si256(save_0_ab_out);
            let mut c = _mm512_castsi512_si256(save_1_cd_out);

            for _ in 0..(ROUND_PAIRS * 2 - 1) {
                quarter_ymmwords!(a, b, c, d);

                // a stays in place
                // b = left shuffle d by 1 element
                let newb = _mm256_shuffle_epi32(d, 0b00111001);
                // c = left shuffle c by 2 elements
                c = _mm256_shuffle_epi32(c, 0b01001110);
                // d = left shuffle b by 3 elements
                d = _mm256_shuffle_epi32(b, 0b10010011);
                b = newb;
            }

            quarter_ymmwords!(a, b, c, d);

            let a0a1b0b1 = _mm512_inserti64x4(_mm512_zextsi256_si512(a), b, 1);
            let c0c1d0d1 = _mm512_inserti64x4(_mm512_zextsi256_si512(c), d, 1);

            let buf0_output =
                _mm512_permutex2var_epi32(
                    a0a1b0b1,
                    Compose::<
                        _,
                        ExtractU32x2<_, false>,
                        Compose<_, RoundShuffleAbcd, Inverse<_, Pivot>>,
                    >::INDEX_ZMM,
                    c0c1d0d1,
                );
            let buf1_output =
                _mm512_permutex2var_epi32(
                    a0a1b0b1,
                    Compose::<
                        _,
                        ExtractU32x2<_, true>,
                        Compose<_, RoundShuffleAbcd, Inverse<_, Pivot>>,
                    >::INDEX_ZMM,
                    c0c1d0d1,
                );

            self.buf0 = _mm512_add_epi32(self.buf0, buf0_output);
            self.buf1 = _mm512_add_epi32(self.buf1, buf1_output);
        }
    }
}

#[cfg(feature = "portable-simd")]
/// A solution for 1 lane of 128-bit blocks using portable SIMD
pub struct BlockPortableSimd {
    save: u32x16,
}

#[cfg(feature = "portable-simd")]
#[inline(always)]
fn simd_rotate_left<const N: usize, const D: u32>(
    x: core::simd::Simd<u32, N>,
) -> core::simd::Simd<u32, N>
where
    core::simd::LaneCount<N>: core::simd::SupportedLaneCount,
{
    let shifted = x << D;
    let shifted2 = x >> (32 - D);
    shifted | shifted2
}

#[cfg(feature = "portable-simd")]
impl Salsa20 for BlockPortableSimd {
    type Lanes = U1;
    type Block = u32x16;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U1>) -> Self {
        Self { save: *ptr[0] }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U1>) {
        *ptr[0] = self.save;
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        use crate::simd::{Identity, Inverse};

        if ROUND_PAIRS == 0 {
            return;
        }

        let pivoted = Pivot::swizzle(self.save);

        let mut a = pivoted.extract::<0, 4>();
        let mut b = pivoted.extract::<4, 4>();
        let mut c = pivoted.extract::<8, 4>();
        let mut d = pivoted.extract::<12, 4>();

        for _ in 0..(ROUND_PAIRS * 2 - 1) {
            b ^= simd_rotate_left::<_, 7>(a + d);
            c ^= simd_rotate_left::<_, 9>(b + a);
            d ^= simd_rotate_left::<_, 13>(c + b);
            a ^= simd_rotate_left::<_, 18>(d + c);

            let newb = d.rotate_elements_left::<1>();
            c = c.rotate_elements_left::<2>();
            d = b.rotate_elements_left::<3>();
            b = newb;
        }

        b ^= simd_rotate_left::<_, 7>(a + d);
        c ^= simd_rotate_left::<_, 9>(b + a);
        d ^= simd_rotate_left::<_, 13>(c + b);
        a ^= simd_rotate_left::<_, 18>(d + c);

        // straighten vectors
        let ab = Identity::<8>::concat_swizzle(a, b);
        let cd = Identity::<8>::concat_swizzle(c, d);
        let abcd = Identity::<16>::concat_swizzle(ab, cd);

        self.save += Compose::<_, RoundShuffleAbcd, Inverse<_, Pivot>>::swizzle(abcd);
    }
}

#[cfg(feature = "portable-simd")]
/// A solution for 2 lanes of 128-bit blocks using portable SIMD
pub struct BlockPortableSimd2 {
    save0: u32x16,
    save1: u32x16,
}

#[cfg(feature = "portable-simd")]
impl Salsa20 for BlockPortableSimd2 {
    type Lanes = U2;
    type Block = u32x16;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U2>) -> Self {
        Self {
            save0: *ptr[0],
            save1: *ptr[1],
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U2>) {
        *ptr[0] = self.save0;
        *ptr[1] = self.save1;
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        use crate::simd::Inverse;

        if ROUND_PAIRS == 0 {
            return;
        }

        let aabb = Pivot2Ab::concat_swizzle(self.save0, self.save1);
        let ccdd = Pivot2CdFlipped::concat_swizzle(self.save1, self.save0);

        let mut a = aabb.extract::<0, 8>();
        let mut b = aabb.extract::<8, 8>();
        let mut c = ccdd.extract::<0, 8>();
        let mut d = ccdd.extract::<8, 8>();

        for _ in 0..(ROUND_PAIRS * 2 - 1) {
            b ^= simd_rotate_left::<_, 7>(a + d);
            c ^= simd_rotate_left::<_, 9>(b + a);
            d ^= simd_rotate_left::<_, 13>(c + b);
            a ^= simd_rotate_left::<_, 18>(d + c);

            let newb = core::simd::simd_swizzle!(d, [1, 2, 3, 0, 5, 6, 7, 4]);
            c = core::simd::simd_swizzle!(c, [2, 3, 0, 1, 6, 7, 4, 5]);
            d = core::simd::simd_swizzle!(b, [3, 0, 1, 2, 7, 4, 5, 6]);
            b = newb;
        }

        b ^= simd_rotate_left::<_, 7>(a + d);
        c ^= simd_rotate_left::<_, 9>(b + a);
        d ^= simd_rotate_left::<_, 13>(c + b);
        a ^= simd_rotate_left::<_, 18>(d + c);

        // this shuffle automatically gets combined on 512-bit platforms
        // we will try to keep them in 128-bit lanes as much as possible
        // so that it does not explode on platforms with only narrow SIMD
        // the vast majority of 512-bit platforms is AVX512F which uses the dedicated
        // core
        // this shuffle automatically gets combined on 512-bit platforms
        // this shuffle automatically gets combined on 512-bit platforms
        let a0b0 = core::simd::simd_swizzle!(a, b, [0, 1, 2, 3, 8, 9, 10, 11]);
        let a1b1 = core::simd::simd_swizzle!(a, b, [4, 5, 6, 7, 12, 13, 14, 15]);
        let c0d0 = core::simd::simd_swizzle!(c, d, [0, 1, 2, 3, 8, 9, 10, 11]);
        let c1d1 = core::simd::simd_swizzle!(c, d, [4, 5, 6, 7, 12, 13, 14, 15]);

        let abcd = Compose::<_, RoundShuffleAbcd, Inverse<_, Pivot>>::concat_swizzle(a0b0, c0d0);
        let abcd1 = Compose::<_, RoundShuffleAbcd, Inverse<_, Pivot>>::concat_swizzle(a1b1, c1d1);

        self.save0 = self.save0 + abcd;
        self.save1 = self.save1 + abcd1;
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use generic_array::{GenericArray, typenum::U1};

    use super::*;

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    fn test_keystream<const ROUND_PAIRS: usize>() {
        let test_input: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32));
        let mut expected = test_input.clone();

        let mut block = BlockScalar::<U1>::read(GenericArray::from_array([&test_input]));
        block.keystream::<ROUND_PAIRS>();
        block.write(GenericArray::from_array([&mut expected]));

        let mut result = unsafe { _mm512_load_si512(test_input.as_ptr().cast::<__m512i>()) };

        let mut block_v = BlockAvx512F::read(GenericArray::from_array([&result]));
        block_v.keystream::<ROUND_PAIRS>();
        block_v.write(GenericArray::from_array([&mut result]));

        let mut output = [0u32; 16];
        unsafe {
            _mm512_storeu_si512(output.as_mut_ptr().cast::<__m512i>(), result);
        }

        assert_eq!(output, *expected);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    fn test_keystream_mb2<const ROUND_PAIRS: usize>() {
        let test_input0: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32));
        let test_input1: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32 + 16));
        let mut expected0 = test_input0.clone();
        let mut expected1 = test_input1.clone();

        let mut block0 = BlockScalar::<U1>::read(GenericArray::from_array([&test_input0]));
        let mut block1 = BlockScalar::<U1>::read(GenericArray::from_array([&test_input1]));
        block0.keystream::<ROUND_PAIRS>();
        block1.keystream::<ROUND_PAIRS>();
        block0.write(GenericArray::from_array([&mut expected0]));
        block1.write(GenericArray::from_array([&mut expected1]));

        let mut output0 = unsafe { _mm512_setzero_si512() };
        let mut output1 = unsafe { _mm512_setzero_si512() };

        let test_input0 = unsafe { _mm512_load_si512(test_input0.as_ptr().cast::<__m512i>()) };
        let test_input1 = unsafe { _mm512_load_si512(test_input1.as_ptr().cast::<__m512i>()) };

        let mut block_v0 =
            BlockAvx512F2::read(GenericArray::from_array([&test_input0, &test_input1]));
        block_v0.keystream::<ROUND_PAIRS>();
        block_v0.write(GenericArray::from_array([&mut output0, &mut output1]));

        let mut result0 = [0u32; 16];
        let mut result1 = [0u32; 16];
        unsafe {
            _mm512_storeu_si512(result0.as_mut_ptr().cast::<__m512i>(), output0);
            _mm512_storeu_si512(result1.as_mut_ptr().cast::<__m512i>(), output1);
        }

        assert_eq!(result0, *expected0);
        assert_eq!(result1, *expected1);
    }

    #[cfg(feature = "portable-simd")]
    fn test_keystream_portable_simd<const ROUND_PAIRS: usize>() {
        let test_input: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32));
        let mut expected = test_input.clone();

        let mut block = BlockScalar::<U1>::read(GenericArray::from_array([&test_input]));
        block.keystream::<ROUND_PAIRS>();
        block.write(GenericArray::from_array([&mut expected]));

        let mut result = u32x16::from_array(*test_input);

        let mut block_v = BlockPortableSimd::read(GenericArray::from_array([&result]));
        block_v.keystream::<ROUND_PAIRS>();
        block_v.write(GenericArray::from_array([&mut result]));

        let output = result.to_array();

        assert_eq!(output, *expected);
    }

    #[cfg(feature = "portable-simd")]
    fn test_keystream_portable_simd2<const ROUND_PAIRS: usize>() {
        let test_input0: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32));
        let test_input1: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32 + 16));
        let mut expected0 = test_input0.clone();
        let mut expected1 = test_input1.clone();

        let mut block0 = BlockScalar::<U1>::read(GenericArray::from_array([&test_input0]));
        let mut block1 = BlockScalar::<U1>::read(GenericArray::from_array([&test_input1]));
        block0.keystream::<ROUND_PAIRS>();
        block1.keystream::<ROUND_PAIRS>();
        block0.write(GenericArray::from_array([&mut expected0]));
        block1.write(GenericArray::from_array([&mut expected1]));

        let mut result0 = u32x16::from_array(*test_input0);
        let mut result1 = u32x16::from_array(*test_input1);

        let mut block_v0 = BlockPortableSimd2::read(GenericArray::from_array([&result0, &result1]));
        block_v0.keystream::<ROUND_PAIRS>();
        block_v0.write(GenericArray::from_array([&mut result0, &mut result1]));

        let output0 = result0.to_array();
        let output1 = result1.to_array();

        assert_eq!(output0, *expected0);
        assert_eq!(output1, *expected1);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_0() {
        test_keystream::<1>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_2() {
        test_keystream::<1>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_8() {
        test_keystream::<4>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_10() {
        test_keystream::<5>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_mb2_2() {
        test_keystream_mb2::<1>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_mb2_8() {
        test_keystream_mb2::<4>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_mb2_10() {
        test_keystream_mb2::<5>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[test]
    fn test_keystream_mb2_0() {
        test_keystream_mb2::<0>();
    }

    #[cfg(feature = "portable-simd")]
    #[test]
    fn test_keystream_portable_simd_2() {
        test_keystream_portable_simd::<1>();
    }

    #[cfg(feature = "portable-simd")]
    #[test]
    fn test_keystream_portable_simd_8() {
        test_keystream_portable_simd::<4>();
    }

    #[cfg(feature = "portable-simd")]
    #[test]
    fn test_keystream_portable_simd_10() {
        test_keystream_portable_simd::<5>();
    }

    #[cfg(feature = "portable-simd")]
    #[test]
    fn test_keystream_portable_simd2_2() {
        test_keystream_portable_simd2::<1>();
    }

    #[cfg(feature = "portable-simd")]
    #[test]
    fn test_keystream_portable_simd2_8() {
        test_keystream_portable_simd2::<4>();
    }

    #[cfg(feature = "portable-simd")]
    #[test]
    fn test_keystream_portable_simd2_10() {
        test_keystream_portable_simd2::<5>();
    }
}
