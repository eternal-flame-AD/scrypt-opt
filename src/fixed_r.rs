use core::num::NonZeroU8;

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{B0, NonZero, U1, U2, UInt, Unsigned},
};

#[allow(unused_imports)]
use crate::features::Feature as _;
#[cfg(feature = "alloc")]
use crate::memory;
use crate::{
    DefaultEngine1, DefaultEngine2, MAX_N, ScryptBlockMixInput, ScryptBlockMixOutput,
    memory::Align64,
    pbkdf2_1::Pbkdf2HmacSha256State,
    pipeline::PipelineContext,
    salsa20::{BlockType, Salsa20},
};

/// The type for one block for scrypt BlockMix operation (128 bytes/1R)
pub type Block<R> = GenericArray<u8, Mul128<R>>;

include!("block_mix.rs");

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
const MAX_R_FOR_FULL_INTERLEAVED_ZMM: usize = 6; // 6 * 2 * 2 = 24 registers
const MAX_R_FOR_UNROLLING: usize = 8;

pub(crate) type Mul2<U> = UInt<U, B0>;
pub(crate) type Mul4<U> = UInt<Mul2<U>, B0>;
pub(crate) type Mul8<U> = UInt<Mul4<U>, B0>;
pub(crate) type Mul16<U> = UInt<Mul8<U>, B0>;
pub(crate) type Mul32<U> = UInt<Mul16<U>, B0>;
pub(crate) type Mul64<U> = UInt<Mul32<U>, B0>;
pub(crate) type Mul128<U> = UInt<Mul64<U>, B0>;

macro_rules! integerify {
    (<$r:ty> $x:expr) => {{
        let input: &crate::fixed_r::Block<R> = $x;

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
        use crate::memory;

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
    pub(super) fn ro_mix_front_ex<S: Salsa20<Lanes = U1>>(&mut self) {
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
    pub(super) fn ro_mix_back_ex<S: Salsa20<Lanes = U1>>(&mut self) {
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
    pub(super) fn ro_mix_interleaved_ex<S: Salsa20<Lanes = U2>>(&mut self, other: &mut Self) {
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
            if crate::features::Avx2.check() {
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
            if crate::features::Avx2.check() {
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
            self.scrypt_ro_mix_ex_zmm::<crate::salsa20::x86_64::BlockAvx512F>();
            return;
        }

        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if crate::features::Avx2.check() {
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
            self.ro_mix_interleaved_ex_zmm::<crate::salsa20::x86_64::BlockAvx512FMb2>(other);
            return;
        }

        #[cfg(all(not(test), target_arch = "x86_64", not(target_feature = "avx2")))]
        {
            if crate::features::Avx2.check() {
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
            if crate::features::Avx2.check() {
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
    pub(super) fn scrypt_ro_mix_ex_zmm<
        S: Salsa20<Lanes = U1, Block = core::arch::x86_64::__m512i>,
    >(
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
    pub(super) fn ro_mix_interleaved_ex_zmm<
        S: Salsa20<Lanes = U2, Block = core::arch::x86_64::__m512i>,
    >(
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

impl<'a, R: ArrayLength, B: BlockType> ScryptBlockMixInput<'a, B> for &'a Align64<Block<R>> {
    #[inline(always)]
    unsafe fn load(&self, word_idx: usize) -> B {
        unsafe { B::read_from_ptr(self.as_ptr().add(word_idx * 64).cast()) }
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
    fn init_with_block(block: &Align64<crate::fixed_r::Block<R>>) -> Self {
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
    fn write_back(&mut self, output: &mut Align64<crate::fixed_r::Block<R>>) {
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
