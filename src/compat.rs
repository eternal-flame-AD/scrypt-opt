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

/// API constants for unsupported parameters.
pub const SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE: core::ffi::c_int = -1;

/// API constants for invalid buffer sizes.
pub const SCRYPT_OPT_INVALID_BUFFER_SIZE: core::ffi::c_int = -2;

/// API constants for invalid buffer alignments.
pub const SCRYPT_OPT_INVALID_BUFFER_ALIGNMENT: core::ffi::c_int = -3;

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
        return SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE;
    }
    let Some(log2_n) = NonZeroU8::new(log2_n as u8) else {
        return SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE;
    };
    let password = unsafe { core::slice::from_raw_parts(password, password_len) };
    let salt = unsafe { core::slice::from_raw_parts(salt, salt_len) };
    let output = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    if !scrypt(password, salt, log2_n, r, p, output) {
        return SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE;
    }
    0
}

/// Compute the minimum buffer length in bytes to allocate for [`scrypt_ro_mix`].
///
/// Returns 0 if the parameters are invalid or unsupported.
///
/// ```c
/// #include <stdlib.h>
///
/// extern size_t scrypt_ro_mix_minimum_buffer_len(unsigned int r, unsigned int cf);
///
/// int main() {
///     int minimum_buffer_len = scrypt_ro_mix_minimum_buffer_len(1, 1);
///     printf("Minimum buffer length: %d\n", minimum_buffer_len);
///     if (!minimum_buffer_len) {
///         return 1;
///     }
///     void* alloc = aligned_alloc(64, minimum_buffer_len);
///     if (alloc == NULL) {
///         return 2;
///     }
///     scrypt_ro_mix(alloc, alloc, r, cf, minimum_buffer_len);
///     return 0;
/// }
/// ```
#[unsafe(export_name = "scrypt_ro_mix_minimum_buffer_len")]
unsafe extern "C" fn scrypt_ro_mix_minimum_buffer_len(
    r: core::ffi::c_uint,
    cf: core::ffi::c_uint,
) -> usize {
    let Ok(cf) = cf.try_into() else {
        return 0;
    };
    let Some(cf) = NonZeroU8::new(cf) else {
        return 0;
    };

    match_r!(r, R, {
        let num_blocks = BufferSet::<&mut [Align64<Block<R>>], R>::minimum_blocks(cf);
        num_blocks * core::mem::size_of::<Align64<Block<R>>>() as usize
    })
    .unwrap_or(0)
}

/// C export for scrypt_ro_mix.
///
/// Parameters:
/// - `front_buffer`: In. Pointer to the buffer to perform the RoMix_front operation on. Can be null.
/// - `back_buffer`: In. Pointer to the buffer to perform the RoMix_back operation on. Can be null. Cannot be an alias of the front buffer.
/// - `salt_output`: Out. Pointer to receive a pointer to the raw salt that corresponds to the back buffer. Can be null.
/// - `r`: In. R value.
/// - `cf`: In. Cost factor.
/// - `minimum_buffer_size`: In. The smaller of the two buffer sizes.
///
/// Returns:
/// - 0 on success.
/// - `SCRYPT_OPT_INVALID_BUFFER_SIZE` if the parameters are invalid.
/// - `SCRYPT_OPT_INVALID_BUFFER_ALIGNMENT` if the buffers are not 64-byte aligned.
/// - `SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE` if the parameters are unsupported.
#[unsafe(export_name = "scrypt_ro_mix")]
unsafe extern "C" fn scrypt_ro_mix(
    front_buffer: *mut u8,
    back_buffer: *mut u8,
    salt_output: *mut *const u8,
    r: u32,
    cf: u8,
    minimum_buffer_size: usize,
) -> core::ffi::c_int {
    if r == 0 {
        return SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE;
    }

    let Some(cf) = NonZeroU8::new(cf) else {
        return SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE;
    };

    // if both buffers are null, we can't do anything
    if front_buffer.is_null() && back_buffer.is_null() {
        return SCRYPT_OPT_INVALID_BUFFER_SIZE;
    }

    // if the front buffer is not null, it must be 64-byte aligned
    if !front_buffer.is_null() && front_buffer.align_offset(64) != 0 {
        return SCRYPT_OPT_INVALID_BUFFER_ALIGNMENT;
    }
    // if the back buffer is not null, it must be 64-byte aligned
    if !back_buffer.is_null() && back_buffer.align_offset(64) != 0 {
        return SCRYPT_OPT_INVALID_BUFFER_ALIGNMENT;
    }

    // if the back buffer is null, the salt output must be null
    if back_buffer.is_null() && !salt_output.is_null() {
        return SCRYPT_OPT_INVALID_BUFFER_SIZE;
    }

    match_r!(r, R, {
        let available_blocks = minimum_buffer_size / core::mem::size_of::<Align64<Block<R>>>();

        let minimum_blocks = BufferSet::<&mut [Align64<Block<R>>], R>::minimum_blocks(cf);
        if available_blocks < minimum_blocks {
            return SCRYPT_OPT_INVALID_BUFFER_SIZE;
        }

        if front_buffer.is_null() {
            let buffer_back = unsafe {
                core::slice::from_raw_parts_mut(
                    back_buffer.cast::<Align64<Block<R>>>(),
                    minimum_blocks,
                )
            };
            let mut buffer1 = BufferSet::<_, R>::new(buffer_back);
            buffer1.pipeline_drain();
            if !salt_output.is_null() {
                unsafe {
                    *salt_output = buffer1.raw_salt_output().as_ptr().cast();
                }
            }
        } else if back_buffer.is_null() {
            let buffer_front = unsafe {
                core::slice::from_raw_parts_mut(
                    front_buffer.cast::<Align64<Block<R>>>(),
                    minimum_blocks,
                )
            };
            let mut buffer0 = BufferSet::<_, R>::new(buffer_front);
            buffer0.pipeline_start();
        } else {
            let buffer_back = unsafe {
                core::slice::from_raw_parts_mut(
                    back_buffer.cast::<Align64<Block<R>>>(),
                    minimum_blocks,
                )
            };

            let mut buffer_back = BufferSet::<_, R>::new(buffer_back);
            if back_buffer == front_buffer {
                buffer_back.scrypt_ro_mix();
            } else {
                let buffer_front = unsafe {
                    core::slice::from_raw_parts_mut(
                        front_buffer.cast::<Align64<Block<R>>>(),
                        minimum_blocks,
                    )
                };

                buffer_back.scrypt_ro_mix_interleaved(&mut BufferSet::<_, R>::new(buffer_front));
            }

            if !salt_output.is_null() {
                unsafe {
                    *salt_output = buffer_back.raw_salt_output().as_ptr().cast();
                }
            }
        }
    })
    .map(|_| 0)
    .unwrap_or(SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = "scrypt")]
#[cfg_attr(test, mutants::skip)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scrypt_ro_mix_api<R: ArrayLength + NonZero>() {
        const CF: u8 = 10;
        unsafe {
            let mut reference_buffer0 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
            let mut reference_buffer1 = BufferSet::<_, R>::new_boxed(CF.try_into().unwrap());
            reference_buffer0.set_input(&Pbkdf2HmacSha256State::new(b"password0"), b"salt");
            reference_buffer1.set_input(&Pbkdf2HmacSha256State::new(b"password1"), b"salt");

            let min_buffer_len = scrypt_ro_mix_minimum_buffer_len(R::U32, CF as u32);
            let layout = alloc::alloc::Layout::from_size_align(min_buffer_len, 64).unwrap();

            let alloc0 = alloc::alloc::alloc(layout);
            assert!(!alloc0.is_null());
            let alloc0 = core::slice::from_raw_parts_mut(alloc0, min_buffer_len);
            let alloc1 = alloc::alloc::alloc(layout);
            assert!(!alloc1.is_null());
            let alloc1 = core::slice::from_raw_parts_mut(alloc1, min_buffer_len);

            let input_slice = reference_buffer1.input_buffer().transmute_as_u8();
            alloc1[..input_slice.len()].copy_from_slice(input_slice);
            let input_slice = reference_buffer0.input_buffer().transmute_as_u8();
            alloc0[..input_slice.len()].copy_from_slice(input_slice);

            scrypt_ro_mix(
                alloc0.as_mut_ptr().cast(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                R::U32,
                CF,
                min_buffer_len,
            );

            let mut alloc0_salt_output = core::ptr::null();

            assert_eq!(
                scrypt_ro_mix(
                    alloc1.as_mut_ptr().cast(),
                    alloc0.as_mut_ptr().cast(),
                    &mut alloc0_salt_output,
                    R::U32,
                    CF,
                    min_buffer_len,
                ),
                0
            );

            let mut alloc1_salt_output = core::ptr::null();

            assert_eq!(
                scrypt_ro_mix(
                    core::ptr::null_mut(),
                    alloc1.as_mut_ptr().cast(),
                    &mut alloc1_salt_output,
                    R::U32,
                    CF,
                    min_buffer_len,
                ),
                0
            );

            reference_buffer0.scrypt_ro_mix();
            reference_buffer1.scrypt_ro_mix();
            assert_eq!(
                core::slice::from_raw_parts(
                    alloc0_salt_output,
                    reference_buffer0.raw_salt_output().transmute_as_u8().len()
                ),
                reference_buffer0
                    .raw_salt_output()
                    .transmute_as_u8()
                    .as_slice()
            );
            assert_eq!(
                core::slice::from_raw_parts(
                    alloc1_salt_output,
                    reference_buffer1.raw_salt_output().transmute_as_u8().len()
                ),
                reference_buffer1
                    .raw_salt_output()
                    .transmute_as_u8()
                    .as_slice()
            );

            alloc::alloc::dealloc(alloc0.as_mut_ptr().cast(), layout);
            alloc::alloc::dealloc(alloc1.as_mut_ptr().cast(), layout);
        }
    }

    #[test]
    fn test_scrypt_ro_mix_api_1() {
        test_scrypt_ro_mix_api::<U1>();
    }

    #[test]
    fn test_scrypt_ro_mix_api_2() {
        test_scrypt_ro_mix_api::<U2>();
    }

    #[test]
    fn test_scrypt_ro_mix_api_8() {
        test_scrypt_ro_mix_api::<U8>();
    }

    #[test]
    fn test_scrypt_ro_mix_api_16() {
        test_scrypt_ro_mix_api::<U16>();
    }
}
