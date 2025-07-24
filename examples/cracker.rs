//! Example of using the pipeline API to crack a password.
use core::marker::PhantomData;
use scrypt_opt::{
    Block, BufferSet,
    generic_array::ArrayLength,
    generic_array::GenericArray,
    generic_array::typenum::{NonZero, U8, U14, U64, Unsigned},
    memory::Align64,
    pbkdf2_1::Pbkdf2HmacSha256State,
    pipeline::PipelineContext,
};

type OutputLen = U64;
type CF = U14;
type R = U8;
const PASSWORD: &[u8] = b"pleaseletmein";
const DICTIONARY: &[&[u8]] = &[
    b"password",
    b"123456",
    PASSWORD,
    b"qwerty",
    b"admin",
    b"root",
    b"1234567890",
];
const SALT: &[u8] = b"SodiumChloride";
const KNOWN_ANSWER: GenericArray<u8, OutputLen> = GenericArray::from_array([
    0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
    0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
    0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
    0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87,
]);

struct CrackContext<'a, 's, R: ArrayLength + NonZero, OutputLen: ArrayLength + NonZero> {
    word: &'a [u8],
    salt: &'s [u8],
    known_answer: &'s GenericArray<u8, OutputLen>,
    hmac_state: Pbkdf2HmacSha256State,

    _marker: PhantomData<R>,
}

impl<
    'a,
    R: ArrayLength + NonZero,
    Q: AsRef<[Align64<Block<R>>]> + AsMut<[Align64<Block<R>>]>,
    OutputLen: ArrayLength + NonZero,
> PipelineContext<u64, Q, R, &'a [u8]> for CrackContext<'a, '_, R, OutputLen>
{
    fn begin(&mut self, _state: &mut u64, buffer_set: &mut BufferSet<Q, R>) -> Option<&'a [u8]> {
        buffer_set.set_input(&self.hmac_state, self.salt);
        None
    }

    fn drain(self, state: &mut u64, buffer_set: &mut BufferSet<Q, R>) -> Option<&'a [u8]> {
        let mut output = GenericArray::<_, OutputLen>::default();
        buffer_set.extract_output(&self.hmac_state, &mut output);
        *state += 1;

        if &output == self.known_answer {
            Some(self.word)
        } else {
            None
        }
    }
}

fn main() {
    let mut buffer_set0 = BufferSet::<_, R>::new_boxed(CF::U8.try_into().unwrap());
    let mut buffer_set1 = BufferSet::<_, R>::new_boxed(CF::U8.try_into().unwrap());

    let mut attempt_counter = 0;

    let answer = buffer_set0
        .pipeline(
            &mut buffer_set1,
            DICTIONARY.iter().map(|word| {
                let hmac_state = Pbkdf2HmacSha256State::new(word);
                CrackContext {
                    hmac_state,
                    word,
                    salt: SALT,
                    known_answer: &KNOWN_ANSWER,
                    _marker: PhantomData,
                }
            }),
            &mut attempt_counter,
        )
        .expect("no answer found");

    println!("answer: {:?}; attempt_counter: {}", answer, attempt_counter);
    assert_eq!(answer, PASSWORD);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cracker() {
        main();
    }
}
