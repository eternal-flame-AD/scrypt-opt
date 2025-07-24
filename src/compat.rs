use core::num::NonZeroU8;

use generic_array::{
    ArrayLength,
    typenum::{
        NonZero, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, U16, U32, U64,
    },
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{Align64, Block, BufferSet, pbkdf2_1::Pbkdf2HmacSha256State};

#[inline(never)]
fn scrypt_impl<R: ArrayLength + NonZero>(
    password: &[u8],
    salt: &[u8],
    log2_n: NonZeroU8,
    p: u32,
    output: &mut [u8],
) {
    if p == 0 {
        return;
    }

    let hmac_state = Pbkdf2HmacSha256State::new(password);
    let mut input_buffers: Vec<Align64<Block<R>>> = vec![Default::default(); p as usize];
    let mut output_buffers: Vec<Align64<Block<R>>> = vec![Default::default(); p as usize];

    let mut buffer0 = BufferSet::<_, R>::new_boxed(log2_n);

    if p == 1 {
        buffer0.set_input(&hmac_state, salt);
        buffer0.scrypt_ro_mix();
        buffer0.extract_output(&hmac_state, output);
        return;
    }

    let mut buffer1 = BufferSet::<_, R>::new_boxed(log2_n);

    hmac_state.emit_scatter(
        salt,
        input_buffers.iter_mut().map(|b| b.transmute_as_u8_mut()),
    );

    buffer0.pipeline(
        &mut buffer1,
        input_buffers.iter().zip(output_buffers.iter_mut()),
        &mut (),
    );

    hmac_state.emit_gather(output_buffers.iter().map(|b| b.transmute_as_u8()), output);
}

/// Run scrypt with the given parameters and store the result in the output buffer.
#[inline(always)]
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    log2_n: NonZeroU8,
    r: u32,
    p: u32,
    output: &mut [u8],
) -> bool {
    match r {
        0 => return false,
        1 => scrypt_impl::<U1>(password, salt, log2_n, p, output),
        2 => scrypt_impl::<U2>(password, salt, log2_n, p, output),
        3 => scrypt_impl::<U3>(password, salt, log2_n, p, output),
        4 => scrypt_impl::<U4>(password, salt, log2_n, p, output),
        5 => scrypt_impl::<U5>(password, salt, log2_n, p, output),
        6 => scrypt_impl::<U6>(password, salt, log2_n, p, output),
        7 => scrypt_impl::<U7>(password, salt, log2_n, p, output),
        8 => scrypt_impl::<U8>(password, salt, log2_n, p, output),
        9 => scrypt_impl::<U9>(password, salt, log2_n, p, output),
        10 => scrypt_impl::<U10>(password, salt, log2_n, p, output),
        11 => scrypt_impl::<U11>(password, salt, log2_n, p, output),
        12 => scrypt_impl::<U12>(password, salt, log2_n, p, output),
        13 => scrypt_impl::<U13>(password, salt, log2_n, p, output),
        14 => scrypt_impl::<U14>(password, salt, log2_n, p, output),
        15 => scrypt_impl::<U15>(password, salt, log2_n, p, output),
        16 => scrypt_impl::<U16>(password, salt, log2_n, p, output),
        32 => scrypt_impl::<U32>(password, salt, log2_n, p, output),
        64 => scrypt_impl::<U64>(password, salt, log2_n, p, output),
        _ => return false,
    }
    true
}

#[unsafe(export_name = "scrypt_kdf_cf")]
/// C export for scrypt_kdf using a libscrypt-kdf compatible API except input is taken as a cost factor.
pub unsafe extern "C" fn scrypt_c_cf(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    log2_n: u8,
    r: u32,
    p: u32,
    output: *mut u8,
    output_len: usize,
) -> core::ffi::c_int {
    let password = unsafe { core::slice::from_raw_parts(password, password_len) };
    let salt = unsafe { core::slice::from_raw_parts(salt, salt_len) };
    let output = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    if !scrypt(
        password,
        salt,
        NonZeroU8::new(log2_n).unwrap(),
        r,
        p,
        output,
    ) {
        return -1;
    }
    0
}

#[unsafe(export_name = "scrypt_kdf")]
/// C export for scrypt_kdf using a libscrypt-kdf compatible API.
pub unsafe extern "C" fn scrypt_c(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    n: u64,
    r: u32,
    p: u32,
    output: *mut u8,
    output_len: usize,
) -> core::ffi::c_int {
    let log2_n = n.trailing_zeros();
    if log2_n == 0 || 1 << log2_n != n {
        return -1;
    }
    let Some(log2_n) = NonZeroU8::new(log2_n as u8) else {
        return -1;
    };
    let password = unsafe { core::slice::from_raw_parts(password, password_len) };
    let salt = unsafe { core::slice::from_raw_parts(salt, salt_len) };
    let output = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    if !scrypt(password, salt, log2_n, r, p, output) {
        return -1;
    }
    0
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "scrypt")]
/// WASM bindings for scrypt, it's not really (much) faster on SIMD due to the complete lack of wide SIMD support, just a wrapper for API compatibility.
pub fn scrypt_wasm(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, dklen: usize) -> String {
    let log2_n = NonZeroU8::new(n.trailing_zeros() as u8).unwrap();
    if log2_n.get() as u32 >= r * 16 {
        return String::from("Invalid r");
    }
    if p as u64 > ((u32::max_value() as u64 - 1) * 32) / (128 * (r as u64)) {
        return String::from("Invalid p");
    }
    if dklen == 0 {
        return String::from("dklen must be non-zero");
    }

    let mut result: Vec<u8> = vec![0; dklen * 2];
    if !scrypt(password, salt, log2_n, r, p, &mut result[dklen..]) {
        return String::from("Unsupported r value");
    }
    for i in 0..dklen {
        let word = result[dklen + i];
        let high_nibble = (word >> 4) as u8;
        let low_nibble = word & 0b1111;
        result[i * 2] = if high_nibble < 10 {
            b'0' + high_nibble
        } else {
            b'a' + high_nibble - 10
        };
        result[i * 2 + 1] = if low_nibble < 10 {
            b'0' + low_nibble
        } else {
            b'a' + low_nibble - 10
        };
    }
    unsafe { String::from_utf8_unchecked(result) }
}
