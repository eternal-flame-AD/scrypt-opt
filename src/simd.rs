#![allow(
    dead_code,
    reason = "some are only used in certain core configurations"
)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub trait Swizzle<const N: usize> {
    const INDEX: [usize; N];

    #[cfg(target_arch = "x86_64")]
    const INDEX_YMM: __m256i = unsafe {
        const {
            let mut index = [0; 8];
            let mut i = 0;
            while i < 8 {
                index[i] = Self::INDEX[i] as u32;
                i += 1;
            }
            core::mem::transmute::<[u32; 8], __m256i>(index)
        }
    };

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    const INDEX_ZMM: __m512i = unsafe {
        const {
            let mut index = [0; 16];
            let mut i = 0;
            while i < 16 {
                index[i] = Self::INDEX[i] as u32;
                i += 1;
            }
            core::mem::transmute::<[u32; 16], __m512i>(index)
        }
    };
}

pub struct Identity<const N: usize>;

impl<const N: usize> Swizzle<N> for Identity<N> {
    const INDEX: [usize; N] = const {
        let mut index = [0; N];
        let mut i = 0;
        while i < N {
            index[i] = i;
            i += 1;
        }
        index
    };
}

#[cfg(feature = "portable-simd")]
impl<const N: usize> core::simd::Swizzle<N> for Identity<N>
where
    core::simd::LaneCount<N>: core::simd::SupportedLaneCount,
{
    const INDEX: [usize; N] = <Self as Swizzle<N>>::INDEX;
}

/// Flip the lower 16 lanes with the upper 16 lanes of a permutation table
pub struct FlipTable16<T: Swizzle<16>> {
    _marker: core::marker::PhantomData<T>,
}

impl<T: Swizzle<16>> Swizzle<16> for FlipTable16<T> {
    const INDEX: [usize; 16] = const {
        let mut index = [0; 16];
        let mut i = 0;
        while i < 16 {
            let original_index = T::INDEX[i];
            index[i] = if original_index >= 16 {
                original_index - 16
            } else {
                original_index + 16
            };
            i += 1;
        }
        index
    };
}

#[cfg(feature = "portable-simd")]
impl<T: Swizzle<16>> core::simd::Swizzle<16> for FlipTable16<T>
where
    core::simd::LaneCount<16>: core::simd::SupportedLaneCount,
{
    const INDEX: [usize; 16] = <Self as Swizzle<16>>::INDEX;
}

/// Map the inner indices to the lower half of the two lower halves of the output vector
pub struct ConcatLo<const N: usize, T: Swizzle<N>> {
    _marker: core::marker::PhantomData<T>,
}

impl<const N: usize, T: Swizzle<N>> Swizzle<N> for ConcatLo<N, T> {
    const INDEX: [usize; N] = const {
        let mut index = [0; N];
        let mut i = 0;
        while i < N {
            index[i] = T::INDEX[i];
            if index[i] >= N / 2 {
                index[i] += N / 2;
            }
            i += 1;
        }
        index
    };
}

pub struct Inverse<const N: usize, T: Swizzle<N>> {
    _marker: core::marker::PhantomData<T>,
}

impl<const N: usize, T: Swizzle<N>> Swizzle<N> for Inverse<N, T> {
    const INDEX: [usize; N] = const {
        let mut index = [0; N];
        let mut i = 0;
        while i < N {
            let mut inverse = 0;
            while inverse < N {
                if T::INDEX[inverse] == i {
                    index[i] = inverse;
                    break;
                }
                inverse += 1;
            }
            i += 1;
        }
        index
    };
}

#[cfg(feature = "portable-simd")]
impl<const N: usize, T: Swizzle<N>> core::simd::Swizzle<N> for Inverse<N, T>
where
    core::simd::LaneCount<N>: core::simd::SupportedLaneCount,
{
    const INDEX: [usize; N] = <Self as Swizzle<N>>::INDEX;
}

/// Compose two swizzles, the second swizzle is applied to the output of the first swizzle
pub struct Compose<const N: usize, T: Swizzle<N>, U: Swizzle<N>> {
    _marker: core::marker::PhantomData<(T, U)>,
}

impl<const N: usize, T: Swizzle<N>, U: Swizzle<N>> Swizzle<N> for Compose<N, T, U> {
    const INDEX: [usize; N] = const {
        let mut index = [0; N];
        let mut i = 0;
        while i < N {
            index[i] = T::INDEX[U::INDEX[i]];
            i += 1;
        }
        index
    };
}

#[cfg(feature = "portable-simd")]
impl<const N: usize, T: Swizzle<N>, U: Swizzle<N>> core::simd::Swizzle<N> for Compose<N, T, U>
where
    core::simd::LaneCount<N>: core::simd::SupportedLaneCount,
{
    const INDEX: [usize; N] = const {
        let mut index = [0; N];
        let mut i = 0;
        while i < N {
            index[i] = T::INDEX[U::INDEX[i]];
            i += 1;
        }
        index
    };
}

/// Extract u32 vectors from a vector of interleaved u32, extract higher numbered lanes if HIGH is true
pub struct ExtractU32x2<const N: usize, const HIGH: bool>;

impl<const N: usize, const HIGH: bool> Swizzle<N> for ExtractU32x2<N, HIGH> {
    const INDEX: [usize; N] = const {
        let mut index = [0; N];
        let mut i = 0;
        while i < N {
            index[i] = i / 4 * 8 + i % 4;
            if HIGH {
                index[i] += 4;
            }
            i += 1;
        }
        index
    };
}
