//! Example for hashing where P is large.
use scrypt_opt::{
    Block, BufferSet,
    generic_array::GenericArray,
    generic_array::typenum::{U8, U10, U16, U64, Unsigned},
    memory::Align64,
    pbkdf2_1::Pbkdf2HmacSha256State,
};

type P = U16;
type OutputLen = U64;
type CF = U10;
type R = U8;
const PASSWORD: &'static [u8] = b"password";
const SALT: &'static [u8] = b"NaCl";
const KNOWN_ANSWER: GenericArray<u8, OutputLen> = GenericArray::from_array([
    0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
    0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
    0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
    0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d, 0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
]);

fn main() {
    let hmac_state = Pbkdf2HmacSha256State::new(PASSWORD);
    let mut input_buffers: GenericArray<Align64<Block<R>>, P> = GenericArray::default();
    let mut output_buffers: GenericArray<Align64<Block<R>>, P> = GenericArray::default();

    let mut buffer0 = BufferSet::<_, R>::new_boxed(CF::U8.try_into().unwrap());
    let mut buffer1 = BufferSet::<_, R>::new_boxed(CF::U8.try_into().unwrap());

    hmac_state.emit_scatter(
        SALT,
        input_buffers.iter_mut().map(|b| b.transmute_as_u8_mut()),
    );

    buffer0.pipeline(
        &mut buffer1,
        input_buffers.iter().zip(output_buffers.iter_mut()),
        &mut (),
    );

    let mut output = GenericArray::default();

    hmac_state.emit_gather(
        output_buffers.iter().map(|b| b.transmute_as_u8()),
        &mut output,
    );

    assert_eq!(output, KNOWN_ANSWER);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_large_p() {
        main();
    }
}
