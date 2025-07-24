#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use generic_array::{
    ArrayLength, GenericArray,
    sequence::GenericSequence,
    typenum::{U1, U2},
};

#[cfg(feature = "portable-simd")]
#[allow(unused_imports)]
use core::simd::{Swizzle, num::SimdUint, u32x4, u32x8, u32x16};

use crate::Align64;

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
macro_rules! mm_rol_epi32x {
    ($w:expr, $amt:literal) => {{
        let w = $w;
        _mm_or_si128(_mm_slli_epi32(w, $amt), _mm_srli_epi32(w, 32 - $amt))
    }};
}

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx512vl")))]
#[allow(unused_macros)]
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
        $b = _mm_xor_epi32($b, mm_rol_epi32x!(_mm_add_epi32($a, $d), 7));
        $c = _mm_xor_epi32($c, mm_rol_epi32x!(_mm_add_epi32($b, $a), 9));
        $d = _mm_xor_epi32($d, mm_rol_epi32x!(_mm_add_epi32($c, $b), 13));
        $a = _mm_xor_epi32($a, mm_rol_epi32x!(_mm_add_epi32($d, $c), 18));
    };
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
macro_rules! quarter_ymmwords {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $b = _mm256_xor_epi32($b, mm256_rol_epi32x!(_mm256_add_epi32($a, $d), 7));
        $c = _mm256_xor_epi32($c, mm256_rol_epi32x!(_mm256_add_epi32($b, $a), 9));
        $d = _mm256_xor_epi32($d, mm256_rol_epi32x!(_mm256_add_epi32($c, $b), 13));
        $a = _mm256_xor_epi32($a, mm256_rol_epi32x!(_mm256_add_epi32($d, $c), 18));
    };
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
// AVX only sequence, doesn't matter for now but if we want an AVX only solution we can reuse this
macro_rules! mm256_shuffle_epi32 {
    ($a:expr,$imm:literal) => {
        _mm256_castps_si256(_mm256_permute_ps(_mm256_castsi256_ps($a), $imm))
    };
}

// pivot to column-major order
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
static PIVOT: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([
        0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
    ])
};
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
static PIVOT2_AB: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([
        0, 5, 10, 15, 16, 21, 26, 31, 4, 9, 14, 3, 20, 25, 30, 19,
    ])
};
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
static PIVOT2_CD: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([
        8, 13, 2, 7, 24, 29, 18, 23, 12, 1, 6, 11, 28, 17, 22, 27,
    ])
};

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
static SHUFFLE_UNPIVOT2: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([
        0, 4, 16, 20, 21, 1, 5, 17, 18, 22, 2, 6, 7, 19, 23, 3,
    ])
};

#[cfg(feature = "portable-simd")]
struct Pivot;

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Pivot {
    const INDEX: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
}

#[cfg(feature = "portable-simd")]
struct Pivot2Ab;

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Pivot2Ab {
    const INDEX: [usize; 16] = [0, 5, 10, 15, 16, 21, 26, 31, 4, 9, 14, 3, 20, 25, 30, 19];
}

#[cfg(feature = "portable-simd")]
struct Pivot2Cd;

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Pivot2Cd {
    const INDEX: [usize; 16] = [8, 13, 2, 7, 24, 29, 18, 23, 12, 1, 6, 11, 28, 17, 22, 27];
}

#[cfg(feature = "portable-simd")]
struct Unpivot;

#[cfg(feature = "portable-simd")]
impl core::simd::Swizzle<16> for Unpivot {
    const INDEX: [usize; 16] = [0, 4, 8, 12, 13, 1, 5, 9, 10, 14, 2, 6, 7, 11, 15, 3];
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
#[allow(unused)]
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
                ptr[i][j] = ptr[i][j].wrapping_add(self.w[i][j]);
            }
        }
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        if ROUND_PAIRS == 0 {
            return;
        }

        for i in 0..Lanes::USIZE {
            for _ in 0..ROUND_PAIRS {
                quarter_words!(self.w[i], 0, 4, 8, 12);
                quarter_words!(self.w[i], 5, 9, 13, 1);
                quarter_words!(self.w[i], 10, 14, 2, 6);
                quarter_words!(self.w[i], 15, 3, 7, 11);

                quarter_words!(self.w[i], 0, 1, 2, 3);
                quarter_words!(self.w[i], 5, 6, 7, 4);
                quarter_words!(self.w[i], 10, 11, 8, 9);
                quarter_words!(self.w[i], 15, 12, 13, 14);
            }
        }
    }
}

/// A solution for 1 lane of 512-bit blocks
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub struct BlockAvx512F {
    save: __m512i,
    a: __m128i,
    b: __m128i,
    c: __m128i,
    d: __m128i,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl Salsa20 for BlockAvx512F {
    type Lanes = U1;
    type Block = __m512i;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U1>) -> Self {
        unsafe {
            let w = *ptr[0];
            let w_out = _mm512_permutexvar_epi32(PIVOT, w);
            let a = _mm512_extracti32x4_epi32(w_out, 0);
            let b = _mm512_extracti32x4_epi32(w_out, 1);
            let c = _mm512_extracti32x4_epi32(w_out, 2);
            let d = _mm512_extracti32x4_epi32(w_out, 3);

            Self {
                save: w,
                a,
                b,
                c,
                d,
            }
        }
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
            for _ in 0..(ROUND_PAIRS * 2 - 1) {
                quarter_xmmwords!(self.a, self.b, self.c, self.d);

                // a stays in place
                // b = left shuffle d by 1 element
                let newb = _mm_shuffle_epi32(self.d, 0b00111001);
                // c = left shuffle c by 2 elements
                self.c = _mm_shuffle_epi32(self.c, 0b01001110);
                // d = left shuffle b by 3 elements
                self.d = _mm_shuffle_epi32(self.b, 0b10010011);
                self.b = newb;
            }

            quarter_xmmwords!(self.a, self.b, self.c, self.d);

            self.save = _mm512_add_epi32(
                self.save,
                _mm512_permutex2var_epi32(
                    _mm512_zextsi256_si512(_mm256_setr_m128i(self.a, self.b)),
                    SHUFFLE_UNPIVOT2,
                    _mm512_zextsi256_si512(_mm256_setr_m128i(self.c, self.d)),
                ),
            );
        }
    }
}

/// A solution for 2 lanes of 512-bit blocks
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub struct BlockAvx512F2 {
    save0: __m512i,
    save1: __m512i,
    a: __m256i,
    b: __m256i,
    c: __m256i,
    d: __m256i,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
impl Salsa20 for BlockAvx512F2 {
    type Lanes = U2;
    type Block = __m512i;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U2>) -> Self {
        unsafe {
            let w0 = *ptr[0];
            let w1 = *ptr[1];

            let aabb = _mm512_permutex2var_epi32(w0, PIVOT2_AB, w1);
            let ccdd = _mm512_permutex2var_epi32(w0, PIVOT2_CD, w1);

            let a = _mm512_extracti64x4_epi64(aabb, 0);
            let b = _mm512_extracti64x4_epi64(aabb, 1);
            let c = _mm512_extracti64x4_epi64(ccdd, 0);
            let d = _mm512_extracti64x4_epi64(ccdd, 1);

            Self {
                save0: w0,
                save1: w1,
                a,
                b,
                c,
                d,
            }
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U2>) {
        *ptr[0] = self.save0;
        *ptr[1] = self.save1;
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        if ROUND_PAIRS == 0 {
            return;
        }

        unsafe {
            for _ in 0..(ROUND_PAIRS * 2 - 1) {
                quarter_ymmwords!(self.a, self.b, self.c, self.d);

                // a stays in place
                // b = left shuffle d by 1 element
                let newb = mm256_shuffle_epi32!(self.d, 0b00111001);
                // c = left shuffle c by 2 elements
                self.c = mm256_shuffle_epi32!(self.c, 0b01001110);
                // d = left shuffle b by 3 elements
                self.d = mm256_shuffle_epi32!(self.b, 0b10010011);
                self.b = newb;
            }

            quarter_ymmwords!(self.a, self.b, self.c, self.d);

            let a0b0 = _mm256_shuffle_i64x2(self.a, self.b, 0b00);
            let a1b1 = _mm256_shuffle_i64x2(self.a, self.b, 0b11);
            let c0d0 = _mm256_shuffle_i64x2(self.c, self.d, 0b00);
            let c1d1 = _mm256_shuffle_i64x2(self.c, self.d, 0b11);

            self.save0 = _mm512_add_epi32(
                self.save0,
                _mm512_permutex2var_epi32(
                    _mm512_zextsi256_si512(a0b0),
                    SHUFFLE_UNPIVOT2,
                    _mm512_zextsi256_si512(c0d0),
                ),
            );
            self.save1 = _mm512_add_epi32(
                self.save1,
                _mm512_permutex2var_epi32(
                    _mm512_zextsi256_si512(a1b1),
                    SHUFFLE_UNPIVOT2,
                    _mm512_zextsi256_si512(c1d1),
                ),
            );
        }
    }
}

#[cfg(feature = "portable-simd")]
/// A solution for 1 lane of 128-bit blocks using portable SIMD
pub struct BlockPortableSimd {
    save: u32x16,
    a: u32x4,
    b: u32x4,
    c: u32x4,
    d: u32x4,
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
        let w = *ptr[0];

        let w_out = Pivot::swizzle(w);
        let a = w_out.extract::<0, 4>();
        let b = w_out.extract::<4, 4>();
        let c = w_out.extract::<8, 4>();
        let d = w_out.extract::<12, 4>();

        Self {
            save: w,
            a,
            b,
            c,
            d,
        }
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

        for _ in 0..(ROUND_PAIRS * 2 - 1) {
            self.b ^= simd_rotate_left::<_, 7>(self.a + self.d);
            self.c ^= simd_rotate_left::<_, 9>(self.b + self.a);
            self.d ^= simd_rotate_left::<_, 13>(self.c + self.b);
            self.a ^= simd_rotate_left::<_, 18>(self.d + self.c);

            let newb = self.d.rotate_elements_left::<1>();
            self.c = self.c.rotate_elements_left::<2>();
            self.d = self.b.rotate_elements_left::<3>();
            self.b = newb;
        }

        self.b ^= simd_rotate_left::<_, 7>(self.a + self.d);
        self.c ^= simd_rotate_left::<_, 9>(self.b + self.a);
        self.d ^= simd_rotate_left::<_, 13>(self.c + self.b);
        self.a ^= simd_rotate_left::<_, 18>(self.d + self.c);

        let ab = core::simd::simd_swizzle!(self.a, self.b, [0, 1, 2, 3, 4, 5, 6, 7]);
        let cd = core::simd::simd_swizzle!(self.c, self.d, [0, 1, 2, 3, 4, 5, 6, 7]);
        let abcd = core::simd::simd_swizzle!(ab, cd, Unpivot::INDEX);

        self.save = self.save + abcd;
    }
}

#[cfg(feature = "portable-simd")]
/// A solution for 2 lanes of 128-bit blocks using portable SIMD
pub struct BlockPortableSimd2 {
    save0: u32x16,
    save1: u32x16,
    a: u32x8,
    b: u32x8,
    c: u32x8,
    d: u32x8,
}

#[cfg(feature = "portable-simd")]
impl Salsa20 for BlockPortableSimd2 {
    type Lanes = U2;
    type Block = u32x16;

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U2>) -> Self {
        let w0 = *ptr[0];
        let w1 = *ptr[1];

        let aabb = Pivot2Ab::concat_swizzle(w0, w1);
        let ccdd = Pivot2Cd::concat_swizzle(w0, w1);

        let a = aabb.extract::<0, 8>();
        let b = aabb.extract::<8, 8>();
        let c = ccdd.extract::<0, 8>();
        let d = ccdd.extract::<8, 8>();

        Self {
            save0: w0,
            save1: w1,
            a,
            b,
            c,
            d,
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U2>) {
        *ptr[0] = self.save0;
        *ptr[1] = self.save1;
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        if ROUND_PAIRS == 0 {
            return;
        }

        for _ in 0..(ROUND_PAIRS * 2 - 1) {
            self.b ^= simd_rotate_left::<_, 7>(self.a + self.d);
            self.c ^= simd_rotate_left::<_, 9>(self.b + self.a);
            self.d ^= simd_rotate_left::<_, 13>(self.c + self.b);
            self.a ^= simd_rotate_left::<_, 18>(self.d + self.c);

            let newb = core::simd::simd_swizzle!(self.d, [1, 2, 3, 0, 5, 6, 7, 4]);
            self.c = core::simd::simd_swizzle!(self.c, [2, 3, 0, 1, 6, 7, 4, 5]);
            self.d = core::simd::simd_swizzle!(self.b, [3, 0, 1, 2, 7, 4, 5, 6]);
            self.b = newb;
        }

        self.b ^= simd_rotate_left::<_, 7>(self.a + self.d);
        self.c ^= simd_rotate_left::<_, 9>(self.b + self.a);
        self.d ^= simd_rotate_left::<_, 13>(self.c + self.b);
        self.a ^= simd_rotate_left::<_, 18>(self.d + self.c);

        let a0b0 = core::simd::simd_swizzle!(self.a, self.b, [0, 1, 2, 3, 8, 9, 10, 11]);
        let a1b1 = core::simd::simd_swizzle!(self.a, self.b, [4, 5, 6, 7, 12, 13, 14, 15]);
        let c0d0 = core::simd::simd_swizzle!(self.c, self.d, [0, 1, 2, 3, 8, 9, 10, 11]);
        let c1d1 = core::simd::simd_swizzle!(self.c, self.d, [4, 5, 6, 7, 12, 13, 14, 15]);

        let abcd = core::simd::simd_swizzle!(a0b0, c0d0, Unpivot::INDEX);
        let abcd1 = core::simd::simd_swizzle!(a1b1, c1d1, Unpivot::INDEX);

        self.save0 = self.save0 + abcd;
        self.save1 = self.save1 + abcd1;
    }
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::U1;

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

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
    #[test]
    fn test_keystream_2() {
        test_keystream::<1>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
    #[test]
    fn test_keystream_8() {
        test_keystream::<4>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
    #[test]
    fn test_keystream_10() {
        test_keystream::<5>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
    #[test]
    fn test_keystream_mb2_2() {
        test_keystream_mb2::<1>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
    #[test]
    fn test_keystream_mb2_8() {
        test_keystream_mb2::<4>();
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vl"))]
    #[test]
    fn test_keystream_mb2_10() {
        test_keystream_mb2::<5>();
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
