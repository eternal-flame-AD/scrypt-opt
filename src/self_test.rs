use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use generic_array::typenum::{B1, IsGreaterOrEqual};
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{NonZero, PowerOfTwo, U1, U2, U4, U8, U10, U14, U16, U20, U64, Unsigned},
};

use crate::{
    Align64, Block, BufferSet, ValidCostFactor, pbkdf2_1::Pbkdf2HmacSha256State,
    pipeline::PipelineContext,
};

/// Test case for P = 1, N = 16, R = 1 in the scrypt specification
pub struct CastN16R1P1;

impl CaseP1 for CastN16R1P1 {
    type OutputLen = U64;
    type CF = U4;
    type R = U1;
    const PASSWORD: &'static [u8] = b"";
    const SALT: &'static [u8] = b"";
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen> = GenericArray::from_array([
        0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04,
        0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2,
        0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f,
        0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c,
        0x38, 0xd1, 0x89, 0x06,
    ]);
}

/// Test case for P = 1, N = 16384, R = 8 in the scrypt specification
pub struct CastN16384R8P1;

impl CaseP1 for CastN16384R8P1 {
    type OutputLen = U64;
    type CF = U14;
    type R = U8;
    const PASSWORD: &'static [u8] = b"pleaseletmein";
    const SALT: &'static [u8] = b"SodiumChloride";
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen> = GenericArray::from_array([
        0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38,
        0xeb, 0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d,
        0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24,
        0x2a, 0x9a, 0xf9, 0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b,
        0x45, 0x57, 0x58, 0x87,
    ]);
}

/// Test case for P = 1, N = 1048576, R = 8 in the scrypt specification
pub struct CastN1048576R8P1;

impl CaseP1 for CastN1048576R8P1 {
    type OutputLen = U64;
    type CF = U20;
    type R = U8;
    const PASSWORD: &'static [u8] = b"pleaseletmein";
    const SALT: &'static [u8] = b"SodiumChloride";
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen> = GenericArray::from_array([
        0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8,
        0x81, 0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d, 0xab, 0xe5, 0xee, 0x98, 0x20, 0xad,
        0xaa, 0x47, 0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f, 0xfa, 0x1c, 0x6d, 0x92, 0x7c,
        0x40, 0xf4, 0xc3, 0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb, 0xcb, 0xf4, 0x5c, 0x6f,
        0xa7, 0x7a, 0x41, 0xa4,
    ]);
}

/// Supplementary case for P = 2, N = 1024, R = 1
pub struct CastN1024R1P2;

impl Case for CastN1024R1P2 {
    type OutputLen = U64;
    type CF = U10;
    type R = U1;
    type P = U2;
    const PASSWORD: &'static [u8] = b"password";
    const SALT: &'static [u8] = b"NaCl";
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen> = GenericArray::from_array([
        0x09, 0xc4, 0x23, 0x86, 0xb2, 0x46, 0x97, 0x53, 0xeb, 0x76, 0x27, 0x75, 0x15, 0xbe, 0xff,
        0x09, 0x80, 0x9d, 0x18, 0xd9, 0x3f, 0xb4, 0xd3, 0x16, 0xea, 0xe1, 0xa8, 0x63, 0x43, 0x9a,
        0x48, 0x98, 0x17, 0xcf, 0x56, 0xa5, 0x87, 0x69, 0xcc, 0x13, 0xbd, 0xb3, 0x33, 0x14, 0x11,
        0xcc, 0xd7, 0xd5, 0x7f, 0x8e, 0x43, 0x9b, 0xa1, 0xa4, 0x84, 0x58, 0x0f, 0x41, 0x9f, 0x7c,
        0x8e, 0x34, 0x99, 0x41,
    ]);
}

#[cfg(feature = "alloc")]
/// Test case for P = 16, N = 1024, R = 8 in the scrypt specification
pub struct CastN1024R8P16;

#[cfg(feature = "alloc")]
impl Case for CastN1024R8P16 {
    type P = U16;
    type OutputLen = U64;
    type CF = U10;
    type R = U8;
    const PASSWORD: &'static [u8] = b"password";
    const SALT: &'static [u8] = b"NaCl";
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen> = GenericArray::from_array([
        0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9,
        0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37,
        0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1, 0x09, 0x27, 0x9d,
        0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d, 0x83, 0x60, 0xcb, 0xdf,
        0xa2, 0xcc, 0x06, 0x40,
    ]);
}

/// Test case for P = 1
pub trait CaseP1 {
    /// The length of the output
    type OutputLen: ArrayLength + NonZero;
    /// The cost factor
    type CF: ValidCostFactor;
    /// The number of rounds
    type R: ArrayLength + NonZero;
    /// The password
    const PASSWORD: &'static [u8];
    /// The salt
    const SALT: &'static [u8];
    /// The known answer
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen>;

    /// Test the algorithm implementation
    fn algorithm_self_test() {
        #[cfg(not(feature = "alloc"))]
        let mut buffer0: GenericArray<
            Align64<Block<Self::R>>,
            <Self::CF as ValidCostFactor>::MinimumBlocks,
        > = GenericArray::default();

        #[cfg(feature = "alloc")]
        let mut buffer0: alloc::boxed::Box<
            GenericArray<Align64<Block<Self::R>>, <Self::CF as ValidCostFactor>::MinimumBlocks>,
        > = unsafe { alloc::boxed::Box::new_uninit().assume_init() };

        #[cfg(not(feature = "alloc"))]
        let mut buffer1: GenericArray<
            Align64<Block<Self::R>>,
            <Self::CF as ValidCostFactor>::MinimumBlocks,
        > = GenericArray::default();

        #[cfg(feature = "alloc")]
        let mut buffer1: alloc::boxed::Box<
            GenericArray<Align64<Block<Self::R>>, <Self::CF as ValidCostFactor>::MinimumBlocks>,
        > = unsafe { alloc::boxed::Box::new_uninit().assume_init() };

        let mut buffer_set0 = BufferSet::<_, Self::R>::new(buffer0.as_mut_slice());
        let mut buffer_set1 = BufferSet::<_, Self::R>::new(buffer1.as_mut_slice());

        assert_eq!(buffer_set0.n(), 1 << Self::CF::U8);
        assert_eq!(buffer_set1.n(), 1 << Self::CF::U8);

        let mut output0 = GenericArray::default();
        let mut output1 = GenericArray::default();
        let mut output_dummy = GenericArray::default();

        // compat API test
        #[cfg(feature = "std")]
        {
            crate::compat::scrypt(
                Self::PASSWORD,
                Self::SALT,
                Self::CF::U8.try_into().unwrap(),
                Self::R::U32,
                1,
                output0.as_mut_slice(),
            );
            assert_eq!(output0, Self::KNOWN_ANSWER);
            output0.fill(0);
        }

        let hmac_state = Pbkdf2HmacSha256State::new(Self::PASSWORD);
        let hmac_state_dummy = Pbkdf2HmacSha256State::new(b"not a password");

        // exercise basic functionality
        buffer_set0.set_input(&hmac_state, Self::SALT);

        buffer_set0.scrypt_ro_mix();

        buffer_set0.extract_output(&hmac_state, &mut output0);

        assert_eq!(output0, Self::KNOWN_ANSWER);

        // check output is not stuck
        buffer_set0.set_input(&hmac_state_dummy, Self::SALT);
        buffer_set0.scrypt_ro_mix();
        buffer_set0.extract_output(&hmac_state_dummy, &mut output_dummy);
        assert_ne!(output_dummy, Self::KNOWN_ANSWER, "stuck output");

        // basic interleaved functionality
        buffer_set0.set_input(&hmac_state, Self::SALT);
        buffer_set1.set_input(&hmac_state_dummy, Self::SALT);

        buffer_set0.pipeline_start();
        buffer_set0.scrypt_ro_mix_interleaved(&mut buffer_set1);
        buffer_set1.pipeline_drain();

        buffer_set0.extract_output(&hmac_state, &mut output0);
        buffer_set1.extract_output(&hmac_state_dummy, &mut output1);

        assert_eq!(output0, Self::KNOWN_ANSWER);
        assert_eq!(output1, output_dummy);

        buffer_set0.as_mut().iter_mut().for_each(|b| {
            b.fill(0);
        });

        buffer_set1.as_mut().iter_mut().for_each(|b| {
            b.fill(0);
        });
    }

    /// Test the pipeline API
    fn pipeline_api_test() {
        #[cfg(not(feature = "alloc"))]
        let mut buffer0: GenericArray<
            Align64<Block<Self::R>>,
            <Self::CF as ValidCostFactor>::MinimumBlocks,
        > = GenericArray::default();

        #[cfg(feature = "alloc")]
        let mut buffer0: alloc::boxed::Box<
            GenericArray<Align64<Block<Self::R>>, <Self::CF as ValidCostFactor>::MinimumBlocks>,
        > = unsafe { alloc::boxed::Box::new_uninit().assume_init() };

        #[cfg(not(feature = "alloc"))]
        let mut buffer1: GenericArray<
            Align64<Block<Self::R>>,
            <Self::CF as ValidCostFactor>::MinimumBlocks,
        > = GenericArray::default();

        #[cfg(feature = "alloc")]
        let mut buffer1: alloc::boxed::Box<
            GenericArray<Align64<Block<Self::R>>, <Self::CF as ValidCostFactor>::MinimumBlocks>,
        > = unsafe { alloc::boxed::Box::new_uninit().assume_init() };

        let hmac_state = Pbkdf2HmacSha256State::new(Self::PASSWORD);
        let hmac_state_dummy = Pbkdf2HmacSha256State::new(b"not a password");

        let mut buffer_set0 = BufferSet::<_, Self::R>::new(buffer0.as_mut_slice());
        let mut buffer_set1 = BufferSet::<_, Self::R>::new(buffer1.as_mut_slice());

        // high level pipeline API
        struct Context<R: ArrayLength + NonZero, OutputLen: ArrayLength + NonZero> {
            i: usize,
            salt: &'static [u8],
            known_answer: GenericArray<u8, OutputLen>,

            hmac_state: Pbkdf2HmacSha256State,
            hmac_state_dummy: Pbkdf2HmacSha256State,
            _marker: PhantomData<R>,
        }

        impl<R: ArrayLength + NonZero, OutputLen: ArrayLength + NonZero>
            PipelineContext<usize, &mut [Align64<Block<R>>], R, ()> for Context<R, OutputLen>
        {
            fn begin(
                &mut self,
                _state: &mut usize,
                buffer_set: &mut BufferSet<&mut [Align64<Block<R>>], R>,
            ) -> Option<()> {
                match self.i % 3 {
                    0 | 1 => {
                        buffer_set.set_input(&self.hmac_state, self.salt);
                    }
                    2 => {
                        buffer_set.set_input(&self.hmac_state_dummy, self.salt);
                    }
                    _ => unreachable!(),
                }

                None
            }
            fn drain(
                self,
                state: &mut usize,
                buffer_set: &mut BufferSet<&mut [Align64<Block<R>>], R>,
            ) -> Option<()> {
                match self.i % 3 {
                    0 | 1 => {
                        let mut output = GenericArray::<_, OutputLen>::default();
                        buffer_set.extract_output(&self.hmac_state, &mut output);
                        assert_eq!(output, self.known_answer);
                    }
                    2 => {
                        let mut output_dummy = GenericArray::<_, OutputLen>::default();
                        buffer_set.extract_output(&self.hmac_state_dummy, &mut output_dummy);
                        assert_ne!(output_dummy, self.known_answer, "stuck output");
                    }
                    _ => unreachable!(),
                }
                *state += self.i;

                None
            }
        }

        for pipeline_length in 0..11 {
            let mut counter = 0;
            buffer_set0.pipeline(
                &mut buffer_set1,
                (0..pipeline_length).map(|i| Context {
                    i,
                    hmac_state,
                    hmac_state_dummy,
                    salt: Self::SALT,
                    known_answer: Self::KNOWN_ANSWER,
                    _marker: PhantomData,
                }),
                &mut counter,
            );

            let expected_sum = pipeline_length * (pipeline_length.saturating_sub(1)) / 2;
            assert_eq!(counter, expected_sum);
        }
    }
}

/// Test case for P > 1
#[cfg(feature = "alloc")]
pub trait Case {
    /// The parallel width
    type P: ArrayLength + PowerOfTwo + NonZero + IsGreaterOrEqual<U2, Output = B1>;
    /// The length of the output
    type OutputLen: ArrayLength + NonZero;
    /// The number of blocks
    type CF: ValidCostFactor;
    /// The number of rounds
    type R: ArrayLength + NonZero;
    /// The password
    const PASSWORD: &'static [u8];
    /// The salt
    const SALT: &'static [u8];
    /// The known answer
    const KNOWN_ANSWER: GenericArray<u8, Self::OutputLen>;

    /// Test the algorithm implementation
    fn algorithm_self_test() {
        let hmac_state = Pbkdf2HmacSha256State::new(Self::PASSWORD);
        let mut input_buffers: GenericArray<Align64<Block<Self::R>>, Self::P> =
            GenericArray::default();
        let mut output_buffers: GenericArray<Align64<Block<Self::R>>, Self::P> =
            GenericArray::default();

        let mut buffer0 = BufferSet::<_, Self::R>::new_boxed(Self::CF::U8.try_into().unwrap());
        let mut buffer1 = BufferSet::<_, Self::R>::new_boxed(Self::CF::U8.try_into().unwrap());

        hmac_state.emit_scatter(
            Self::SALT,
            input_buffers.iter_mut().map(|b| b.transmute_as_u8_mut()),
        );

        buffer0.pipeline(
            &mut buffer1,
            input_buffers.iter().zip(output_buffers.iter_mut()),
            &mut (),
        );

        let mut output = GenericArray::default();

        // compat API test
        #[cfg(feature = "std")]
        {
            crate::compat::scrypt(
                Self::PASSWORD,
                Self::SALT,
                Self::CF::U8.try_into().unwrap(),
                Self::R::U32,
                Self::P::U32,
                output.as_mut_slice(),
            );
            assert_eq!(output, Self::KNOWN_ANSWER);
            output.fill(0);
        }

        hmac_state.emit_gather(
            output_buffers.iter().map(|b| b.transmute_as_u8()),
            &mut output,
        );

        assert_eq!(output, Self::KNOWN_ANSWER);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cast_16_1_1_algorithm_self_test() {
        CastN16R1P1::algorithm_self_test();
    }

    #[test]
    fn test_cast_16_1_1_pipeline_api_test() {
        CastN16R1P1::pipeline_api_test();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_cast_16384_8_1_algorithm_self_test() {
        CastN16384R8P1::algorithm_self_test();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_cast_1024_8_16_algorithm_self_test() {
        CastN1024R8P16::algorithm_self_test();
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_cast_1024_1_2_algorithm_self_test() {
        CastN1024R1P2::algorithm_self_test();
    }
}
