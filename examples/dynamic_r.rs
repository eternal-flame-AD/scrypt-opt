use scrypt_opt::self_test::Case;

fn main() {
    let mut output = [0u8; 64];
    scrypt_opt::compat::scrypt(
        b"password",
        b"NaCl",
        10.try_into().unwrap(), // ln = 10 (1024)
        8.try_into().unwrap(),  // r = 8
        16.try_into().unwrap(), // p = 16
        &mut output,
    );
    assert_eq!(
        output,
        scrypt_opt::self_test::CaseN1024R8P16::KNOWN_ANSWER.as_slice(),
        "answer mismatch"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrypt() {
        main();
    }
}
