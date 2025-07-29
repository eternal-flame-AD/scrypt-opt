use core::arch::x86_64::*;

use super::*;
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{U1, U2},
};

use crate::{
    Align64,
    simd::{Compose, ConcatLo, ExtractU32x2, FlipTable16, Inverse, Swizzle},
};

#[cfg(target_feature = "avx512vl")]
macro_rules! mm_rol_epi32x {
    ($w:expr, $amt:literal) => {
        _mm_rol_epi32($w, $amt)
    };
}

#[cfg(target_feature = "avx512vl")]
macro_rules! mm256_rol_epi32x {
    ($w:expr, $amt:literal) => {
        _mm256_rol_epi32($w, $amt)
    };
}

#[cfg(all(target_feature = "avx2", not(target_feature = "avx512vl")))]
#[allow(unused_macros)]
// LLVM can rewrite this as _mm512_rol_epi32(_mm512_zextsi128_si512(w), $amt) automatically on AVX512F
macro_rules! mm_rol_epi32x {
    ($w:expr, $amt:literal) => {{
        let w = $w;
        _mm_or_si128(_mm_slli_epi32(w, $amt), _mm_srli_epi32(w, 32 - $amt))
    }};
}

#[cfg(all(target_feature = "avx2", not(target_feature = "avx512vl")))]
#[allow(unused_macros)]
// LLVM can rewrite this as _mm512_rol_epi32(_mm512_zextsi256_si512(w), $amt) automatically on AVX512F
macro_rules! mm256_rol_epi32x {
    ($w:expr, $amt:literal) => {{
        let w = $w;
        _mm256_or_si256(_mm256_slli_epi32(w, $amt), _mm256_srli_epi32(w, 32 - $amt))
    }};
}

macro_rules! quarter_xmmwords {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $b = _mm_xor_si128($b, mm_rol_epi32x!(_mm_add_epi32($a, $d), 7));
        $c = _mm_xor_si128($c, mm_rol_epi32x!(_mm_add_epi32($b, $a), 9));
        $d = _mm_xor_si128($d, mm_rol_epi32x!(_mm_add_epi32($c, $b), 13));
        $a = _mm_xor_si128($a, mm_rol_epi32x!(_mm_add_epi32($d, $c), 18));
    };
}

#[cfg(target_feature = "avx2")]
macro_rules! quarter_ymmwords {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $b = _mm256_xor_si256($b, mm256_rol_epi32x!(_mm256_add_epi32($a, $d), 7));
        $c = _mm256_xor_si256($c, mm256_rol_epi32x!(_mm256_add_epi32($b, $a), 9));
        $d = _mm256_xor_si256($d, mm256_rol_epi32x!(_mm256_add_epi32($c, $b), 13));
        $a = _mm256_xor_si256($a, mm256_rol_epi32x!(_mm256_add_epi32($d, $c), 18));
    };
}

/// A solution for 1 lane of 512-bit blocks
#[cfg(target_feature = "avx512f")]
pub struct BlockAvx512F {
    a: __m128i,
    b: __m128i,
    c: __m128i,
    d: __m128i,
}

#[cfg(target_feature = "avx512f")]
impl Salsa20 for BlockAvx512F {
    type Lanes = U1;
    type Block = __m512i;

    #[inline(always)]
    fn shuffle_in(ptr: &mut Align64<[u32; 16]>) {
        unsafe {
            _mm512_store_si512(
                ptr.as_mut_ptr().cast::<__m512i>(),
                _mm512_permutexvar_epi32(
                    <Pivot as Swizzle<16>>::INDEX_ZMM,
                    _mm512_load_si512(ptr.as_ptr().cast::<__m512i>()),
                ),
            )
        }
    }

    #[inline(always)]
    fn shuffle_out(ptr: &mut Align64<[u32; 16]>) {
        unsafe {
            _mm512_store_si512(
                ptr.as_mut_ptr().cast::<__m512i>(),
                _mm512_permutexvar_epi32(
                    <Inverse<_, Pivot> as Swizzle<16>>::INDEX_ZMM,
                    _mm512_load_si512(ptr.as_ptr().cast::<__m512i>()),
                ),
            )
        }
    }

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U1>) -> Self {
        unsafe {
            let t = *ptr[0];
            let b = _mm512_extracti32x4_epi32(t, 1);
            let d = _mm512_extracti32x4_epi32(t, 2);
            let c = _mm512_extracti32x4_epi32(t, 3);

            Self {
                a: _mm512_castsi512_si128(t),
                b,
                c,
                d,
            }
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U1>) {
        unsafe {
            *ptr[0] = _mm512_add_epi32(
                *ptr[0],
                _mm512_permutex2var_epi32(
                    _mm512_castsi256_si512(_mm256_setr_m128i(self.a, self.b)),
                    ConcatLo::<_, RoundShuffleAbdc>::INDEX_ZMM,
                    _mm512_castsi256_si512(_mm256_setr_m128i(self.d, self.c)),
                ),
            );
        }
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        unsafe {
            if ROUND_PAIRS == 0 {
                // Special handling for the 0-round case:
                // The shuffling operations below are used to ensure that the
                // state variables (a, b, c, d) are permuted in a way that
                // maintains consistency with the expected output format.
                // This is necessary because the 0-round case does not perform
                // any quarter-round transformations, so we apply these
                // shuffles to simulate the effect of a no-op transformation
                // and ensure compatibility with downstream processing.
                self.b = _mm_shuffle_epi32(self.b, 0b10_01_00_11);
                self.c = _mm_shuffle_epi32(self.c, 0b01_00_11_10);
                self.d = _mm_shuffle_epi32(self.d, 0b00_11_10_01);
                (self.b, self.d) = (self.d, self.b);
                return;
            }

            for _ in 0..(ROUND_PAIRS * 2 - 1) {
                quarter_xmmwords!(self.a, self.b, self.c, self.d);

                // a stays in place
                // b = left shuffle d by 1 element
                self.d = _mm_shuffle_epi32(self.d, 0b00_11_10_01);
                // c = left shuffle c by 2 elements
                self.c = _mm_shuffle_epi32(self.c, 0b01_00_11_10);
                // d = left shuffle b by 3 elements
                self.b = _mm_shuffle_epi32(self.b, 0b10_01_00_11);
                (self.b, self.d) = (self.d, self.b);
            }

            quarter_xmmwords!(self.a, self.b, self.c, self.d);
        }
    }
}

/// A solution for 1 lane of 512-bit blocks
#[cfg(target_feature = "avx2")]
pub struct BlockAvx2 {
    a: __m128i,
    b: __m128i,
    c: __m128i,
    d: __m128i,
}

#[cfg(target_feature = "avx2")]
impl Salsa20 for BlockAvx2 {
    type Lanes = U1;
    type Block = [__m256i; 2];

    #[inline(always)]
    fn shuffle_in(ptr: &mut Align64<[u32; 16]>) {
        unsafe {
            let tmp = ptr.clone();
            for i in 0..16 {
                ptr[i] = tmp[<Pivot as Swizzle<16>>::INDEX[i]];
            }
        }
    }

    #[inline(always)]
    fn shuffle_out(ptr: &mut Align64<[u32; 16]>) {
        unsafe {
            let tmp = ptr.clone();
            for i in 0..16 {
                ptr[i] = tmp[<Inverse<_, Pivot> as Swizzle<16>>::INDEX[i]];
            }
        }
    }

    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U1>) -> Self {
        unsafe {
            let [ab, dc] = *ptr[0];
            let a = _mm256_castsi256_si128(ab);
            let b = _mm256_extracti128_si256(ab, 1);
            let d = _mm256_castsi256_si128(dc);
            let c = _mm256_extracti128_si256(dc, 1);

            Self { a, b, c, d }
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U1>) {
        unsafe {
            let ab = _mm256_setr_m128i(self.a, self.b);
            let dc = _mm256_setr_m128i(self.d, self.c);
            ptr[0][0] = _mm256_add_epi32(ptr[0][0], ab);
            ptr[0][1] = _mm256_add_epi32(ptr[0][1], dc);
        }
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        unsafe {
            if ROUND_PAIRS == 0 {
                return;
            }

            for _ in 0..(ROUND_PAIRS * 2) {
                quarter_xmmwords!(self.a, self.b, self.c, self.d);

                // a stays in place
                // b = left shuffle d by 1 element
                self.d = _mm_shuffle_epi32(self.d, 0b00_11_10_01);
                // c = left shuffle c by 2 elements
                self.c = _mm_shuffle_epi32(self.c, 0b01_00_11_10);
                // d = left shuffle b by 3 elements
                self.b = _mm_shuffle_epi32(self.b, 0b10_01_00_11);
                (self.b, self.d) = (self.d, self.b);
            }
        }
    }
}

/// A solution for 2 lanes of 512-bit blocks
#[cfg(target_feature = "avx512f")]
pub struct BlockAvx512FMb2 {
    a: __m256i,
    b: __m256i,
    c: __m256i,
    d: __m256i,
}

#[cfg(target_feature = "avx512f")]
impl Salsa20 for BlockAvx512FMb2 {
    type Lanes = U2;
    type Block = __m512i;

    #[inline(always)]
    fn shuffle_in(ptr: &mut Align64<[u32; 16]>) {
        BlockAvx512F::shuffle_in(ptr);
    }

    #[inline(always)]
    fn shuffle_out(ptr: &mut Align64<[u32; 16]>) {
        BlockAvx512F::shuffle_out(ptr);
    }

    // this is a more ILP version that is slightly faster (~2%) and doesn't need 2 more registers
    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U2>) -> Self {
        unsafe {
            let buf0_dc = _mm512_extracti64x4_epi64(*ptr[0], 1);
            let buf1_dc = _mm512_extracti64x4_epi64(*ptr[1], 1);
            let buf0_ab = _mm512_castsi512_si256(*ptr[0]);
            let buf1_ab = _mm512_castsi512_si256(*ptr[1]);

            // the first operation is a + d, so we place them at the beginning
            let a = _mm256_setr_m128i(
                _mm256_castsi256_si128(buf0_ab),
                _mm256_castsi256_si128(buf1_ab),
            );

            let d = _mm256_setr_m128i(
                _mm256_castsi256_si128(buf0_dc),
                _mm256_castsi256_si128(buf1_dc),
            );

            let mut c;
            let mut b;

            // C must come last because it is used last (~3% penalty when flipped)
            //
            // SAFETY: this is AVX2 code gated behind AVX512F
            core::arch::asm!(
                "vperm2i128 {b}, {buf0_ab}, {buf1_ab}, {imm}",
                "vperm2i128 {c}, {buf0_dc}, {buf1_dc}, {imm}",
                b = out(ymm_reg) b,
                buf1_ab = in(ymm_reg) buf1_ab,
                buf0_ab = in(ymm_reg) buf0_ab,
                c = lateout(ymm_reg) c,
                buf1_dc = in(ymm_reg) buf1_dc,
                buf0_dc = in(ymm_reg) buf0_dc,
                imm = const 0b0011_0001,
                options(pure, nomem, nostack, preserves_flags),
            );

            Self { a, b, c, d }
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U2>) {
        unsafe {
            let a0a1b0b1 = _mm512_inserti64x4(_mm512_castsi256_si512(self.a), self.b, 1);
            let d0d1c0c1 = _mm512_inserti64x4(_mm512_castsi256_si512(self.d), self.c, 1);

            let buf0_output = _mm512_permutex2var_epi32(
                a0a1b0b1,
                Compose::<_, ExtractU32x2<_, false>, RoundShuffleAbdc>::INDEX_ZMM,
                d0d1c0c1,
            );
            // use a flipped table for smaller register pressure
            let buf1_output = _mm512_permutex2var_epi32(
                d0d1c0c1,
                FlipTable16::<Compose<_, ExtractU32x2<_, true>, RoundShuffleAbdc>>::INDEX_ZMM,
                a0a1b0b1,
            );

            *ptr[0] = _mm512_add_epi32(*ptr[0], buf0_output);
            *ptr[1] = _mm512_add_epi32(*ptr[1], buf1_output);
        }
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        unsafe {
            if ROUND_PAIRS == 0 {
                // This block is executed when ROUND_PAIRS is zero, which is a special case
                // not part of the main keystream generation algorithm. It ensures that the
                // state variables (self.b, self.c, self.d) are shuffled in a specific way
                // to maintain consistency or prepare for subsequent operations. This is
                // necessary for correctness but does not contribute to the core algorithm.
                self.b = _mm256_shuffle_epi32(self.b, 0b10_01_00_11);
                self.c = _mm256_shuffle_epi32(self.c, 0b01_00_11_10);
                self.d = _mm256_shuffle_epi32(self.d, 0b00_11_10_01);
                (self.b, self.d) = (self.d, self.b);

                return;
            }

            for _ in 0..(ROUND_PAIRS * 2 - 1) {
                quarter_ymmwords!(self.a, self.b, self.c, self.d);

                // a stays in place
                // b = left shuffle d by 1 element
                self.d = _mm256_shuffle_epi32(self.d, 0b00_11_10_01);
                // c = left shuffle c by 2 elements
                self.c = _mm256_shuffle_epi32(self.c, 0b01_00_11_10);
                // d = left shuffle b by 3 elements
                self.b = _mm256_shuffle_epi32(self.b, 0b10_01_00_11);
                (self.b, self.d) = (self.d, self.b);
            }

            quarter_ymmwords!(self.a, self.b, self.c, self.d);
        }
    }
}

/// A solution for 2 lanes of 256-bit blocks
#[cfg(target_feature = "avx2")]
pub struct BlockAvx2Mb2 {
    a: __m256i,
    b: __m256i,
    c: __m256i,
    d: __m256i,
}

#[cfg(target_feature = "avx2")]
impl Salsa20 for BlockAvx2Mb2 {
    type Lanes = U2;
    type Block = [__m256i; 2];

    #[inline(always)]
    fn shuffle_in(ptr: &mut Align64<[u32; 16]>) {
        BlockAvx2::shuffle_in(ptr);
    }

    #[inline(always)]
    fn shuffle_out(ptr: &mut Align64<[u32; 16]>) {
        BlockAvx2::shuffle_out(ptr);
    }

    // this is a more ILP version that is slightly faster (~2%) and doesn't need 2 more registers
    #[inline(always)]
    fn read(ptr: GenericArray<&Self::Block, U2>) -> Self {
        unsafe {
            let [buf0_ab, buf0_dc] = *ptr[0];
            let [buf1_ab, buf1_dc] = *ptr[1];

            let a = _mm256_setr_m128i(
                _mm256_castsi256_si128(buf0_ab),
                _mm256_castsi256_si128(buf1_ab),
            );

            let d = _mm256_setr_m128i(
                _mm256_castsi256_si128(buf0_dc),
                _mm256_castsi256_si128(buf1_dc),
            );

            let b = _mm256_permute2x128_si256(buf0_ab, buf1_ab, 0b0011_0001);
            let c = _mm256_permute2x128_si256(buf0_dc, buf1_dc, 0b0011_0001);

            Self { a, b, c, d }
        }
    }

    #[inline(always)]
    fn write(&self, mut ptr: GenericArray<&mut Self::Block, U2>) {
        unsafe {
            let a1b1 = _mm256_permute2x128_si256(self.a, self.b, 0b0011_0001);
            let d1c1 = _mm256_permute2x128_si256(self.d, self.c, 0b0011_0001);

            ptr[1][0] = _mm256_add_epi32(ptr[1][0], a1b1);
            ptr[1][1] = _mm256_add_epi32(ptr[1][1], d1c1);

            let a0b0 = _mm256_setr_m128i(
                _mm256_castsi256_si128(self.a),
                _mm256_castsi256_si128(self.b),
            );
            let d0c0 = _mm256_setr_m128i(
                _mm256_castsi256_si128(self.d),
                _mm256_castsi256_si128(self.c),
            );

            ptr[0][0] = _mm256_add_epi32(ptr[0][0], a0b0);
            ptr[0][1] = _mm256_add_epi32(ptr[0][1], d0c0);
        }
    }

    #[inline(always)]
    fn keystream<const ROUND_PAIRS: usize>(&mut self) {
        unsafe {
            if ROUND_PAIRS == 0 {
                return;
            }

            for _ in 0..(ROUND_PAIRS * 2) {
                quarter_ymmwords!(self.a, self.b, self.c, self.d);

                // a stays in place
                // b = left shuffle d by 1 element
                self.d = _mm256_shuffle_epi32(self.d, 0b00_11_10_01);
                // c = left shuffle c by 2 elements
                self.c = _mm256_shuffle_epi32(self.c, 0b01_00_11_10);
                // d = left shuffle b by 3 elements
                self.b = _mm256_shuffle_epi32(self.b, 0b10_01_00_11);
                (self.b, self.d) = (self.d, self.b);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::salsa20::BlockScalar;
    use crate::salsa20::tests::test_shuffle_in_out_identity;

    #[cfg(target_feature = "avx512f")]
    fn test_keystream_avx512f<const ROUND_PAIRS: usize>() {
        test_shuffle_in_out_identity::<BlockAvx512F>();

        let test_input: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32));
        let mut expected = test_input.clone();

        let mut block = BlockScalar::<U1>::read(GenericArray::from_array([&test_input]));
        block.keystream::<ROUND_PAIRS>();
        block.write(GenericArray::from_array([&mut expected]));

        let mut core_input = test_input.clone();
        BlockAvx512F::shuffle_in(&mut core_input);
        let mut result = unsafe { _mm512_load_si512(core_input.as_ptr().cast::<__m512i>()) };
        let mut block_v = BlockAvx512F::read(GenericArray::from_array([&result]));
        block_v.keystream::<ROUND_PAIRS>();
        block_v.write(GenericArray::from_array([&mut result]));

        let mut output = Align64([0u32; 16]);
        unsafe {
            _mm512_store_si512(output.as_mut_ptr().cast::<__m512i>(), result);
        }
        BlockAvx512F::shuffle_out(&mut output);

        assert_eq!(output, expected);
    }

    #[cfg(target_feature = "avx2")]
    fn test_keystream_avx2<const ROUND_PAIRS: usize>() {
        test_shuffle_in_out_identity::<BlockAvx2>();

        let test_input: Align64<[u32; 16]> = Align64(core::array::from_fn(|i| i as u32));
        let mut expected = test_input.clone();

        let mut block = BlockScalar::<U1>::read(GenericArray::from_array([&test_input]));
        block.keystream::<ROUND_PAIRS>();
        block.write(GenericArray::from_array([&mut expected]));

        let mut core_input = test_input.clone();
        BlockAvx2::shuffle_in(&mut core_input);
        let mut result = unsafe {
            [
                _mm256_load_si256(core_input.as_ptr().cast::<__m256i>()),
                _mm256_load_si256(core_input.as_ptr().cast::<__m256i>().add(1)),
            ]
        };
        let mut block_v = BlockAvx2::read(GenericArray::from_array([&result]));
        block_v.keystream::<ROUND_PAIRS>();
        block_v.write(GenericArray::from_array([&mut result]));

        let mut output = Align64([0u32; 16]);
        unsafe {
            _mm256_store_si256(output.as_mut_ptr().cast::<__m256i>(), result[0]);
            _mm256_store_si256(output.as_mut_ptr().cast::<__m256i>().add(1), result[1]);
        }
        BlockAvx2::shuffle_out(&mut output);

        assert_eq!(output, expected);
    }

    #[cfg(target_feature = "avx512f")]
    fn test_keystream_mb2_avx512f<const ROUND_PAIRS: usize>() {
        test_shuffle_in_out_identity::<BlockAvx512FMb2>();

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

        let mut test_input0_shuffled = test_input0.clone();
        let mut test_input1_shuffled = test_input1.clone();
        BlockAvx512FMb2::shuffle_in(&mut test_input0_shuffled);
        BlockAvx512FMb2::shuffle_in(&mut test_input1_shuffled);

        let mut test_input0 =
            unsafe { _mm512_load_si512(test_input0_shuffled.as_ptr().cast::<__m512i>()) };
        let mut test_input1 =
            unsafe { _mm512_load_si512(test_input1_shuffled.as_ptr().cast::<__m512i>()) };

        let mut block_v0 =
            BlockAvx512FMb2::read(GenericArray::from_array([&test_input0, &test_input1]));
        block_v0.keystream::<ROUND_PAIRS>();
        block_v0.write(GenericArray::from_array([
            &mut test_input0,
            &mut test_input1,
        ]));

        let mut result0 = Align64([0u32; 16]);
        let mut result1 = Align64([0u32; 16]);

        unsafe {
            _mm512_store_si512(result0.as_mut_ptr().cast::<__m512i>(), test_input0);
            _mm512_store_si512(result1.as_mut_ptr().cast::<__m512i>(), test_input1);
        }

        BlockAvx512FMb2::shuffle_out(&mut result0);
        BlockAvx512FMb2::shuffle_out(&mut result1);

        assert_eq!(result0, expected0);
        assert_eq!(result1, expected1);
    }

    #[cfg(target_feature = "avx2")]
    fn test_keystream_mb2_avx2<const ROUND_PAIRS: usize>() {
        test_shuffle_in_out_identity::<BlockAvx2Mb2>();

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

        let mut test_input0_shuffled = test_input0.clone();
        let mut test_input1_shuffled = test_input1.clone();
        BlockAvx2Mb2::shuffle_in(&mut test_input0_shuffled);
        BlockAvx2Mb2::shuffle_in(&mut test_input1_shuffled);

        let mut test_input0 = unsafe {
            [
                _mm256_load_si256(test_input0_shuffled.as_ptr().cast::<__m256i>()),
                _mm256_load_si256(test_input0_shuffled.as_ptr().cast::<__m256i>().add(1)),
            ]
        };
        let mut test_input1 = unsafe {
            [
                _mm256_load_si256(test_input1_shuffled.as_ptr().cast::<__m256i>()),
                _mm256_load_si256(test_input1_shuffled.as_ptr().cast::<__m256i>().add(1)),
            ]
        };

        let mut block_v0 =
            BlockAvx2Mb2::read(GenericArray::from_array([&test_input0, &test_input1]));
        block_v0.keystream::<ROUND_PAIRS>();
        block_v0.write(GenericArray::from_array([
            &mut test_input0,
            &mut test_input1,
        ]));

        let mut result0 = Align64([0u32; 16]);
        let mut result1 = Align64([0u32; 16]);

        unsafe {
            _mm256_store_si256(result0.as_mut_ptr().cast::<__m256i>(), test_input0[0]);
            _mm256_store_si256(
                result0.as_mut_ptr().cast::<__m256i>().add(1),
                test_input0[1],
            );
            _mm256_store_si256(result1.as_mut_ptr().cast::<__m256i>(), test_input1[0]);
            _mm256_store_si256(
                result1.as_mut_ptr().cast::<__m256i>().add(1),
                test_input1[1],
            );
        }

        BlockAvx2Mb2::shuffle_out(&mut result0);
        BlockAvx2Mb2::shuffle_out(&mut result1);

        assert_eq!(result0, expected0);
        assert_eq!(result1, expected1);
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_0() {
        test_keystream_avx512f::<0>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_2() {
        test_keystream_avx512f::<1>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_8() {
        test_keystream_avx512f::<4>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_10() {
        test_keystream_avx512f::<5>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_mb2_0() {
        test_keystream_mb2_avx512f::<0>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_mb2_2() {
        test_keystream_mb2_avx512f::<1>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_mb2_8() {
        test_keystream_mb2_avx512f::<4>();
    }

    #[cfg(target_feature = "avx512f")]
    #[test]
    fn test_keystream_avx512f_mb2_10() {
        test_keystream_mb2_avx512f::<5>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_0() {
        test_keystream_avx2::<0>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_2() {
        test_keystream_avx2::<1>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_8() {
        test_keystream_avx2::<4>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_10() {
        test_keystream_avx2::<5>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_mb2_0() {
        test_keystream_mb2_avx2::<0>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_mb2_2() {
        test_keystream_mb2_avx2::<1>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_mb2_8() {
        test_keystream_mb2_avx2::<4>();
    }

    #[cfg(target_feature = "avx2")]
    #[test]
    fn test_keystream_avx2_mb2_10() {
        test_keystream_mb2_avx2::<5>();
    }
}
