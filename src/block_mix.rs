macro_rules! block_mix {
    ($r:expr; [<$s:ty> $input:expr => $output:expr]) => {
        #[allow(unused_unsafe)]
        {
            use crate::{
                ScryptBlockMixInput, ScryptBlockMixOutput,
                salsa20::{BlockType, Salsa20},
            };

            let mut x: <$s as Salsa20>::Block = unsafe { $input.load($r * 2 - 1) };

            macro_rules! iteration {
                ($i:expr) => {{
                    x.xor_with(unsafe { $input.load(2 * $i) });

                    let mut b0 = <$s>::read(GenericArray::from_array([&x]));
                    b0.keystream::<4>();
                    b0.write(GenericArray::from_array([&mut x]));

                    $output.store_even($i, x);

                    x.xor_with(unsafe { $input.load(2 * $i + 1) });

                    let mut b1 = <$s>::read(GenericArray::from_array([&x]));
                    b1.keystream::<4>();
                    b1.write(GenericArray::from_array([&mut x]));

                    $output.store_odd($i, x);
                }};
            }

            if $r <= MAX_R_FOR_UNROLLING {
                repeat8!(i, {
                    if i < $r {
                        iteration!(i);
                    }
                });

                let _ = x;
            } else {
                for i in 0..$r {
                    iteration!(i);
                }
            }
        }
    };
    ($r:expr; [
        <$s0:ty> $input0:expr => $output0:expr,
        <$s1:ty> $input1:expr => $output1:expr$(,)?
    ]) => {
        #[allow(unused_unsafe)]
        {
            let mut x0: <$s0 as Salsa20>::Block = unsafe { $input0.load($r * 2 - 1) };
            let mut x1: <$s1 as Salsa20>::Block = unsafe { $input1.load($r * 2 - 1) };

            macro_rules! iteration {
                ($i:expr) => {{
                    x0.xor_with(unsafe { $input0.load(2 * $i) });
                    x1.xor_with(unsafe { $input1.load(2 * $i) });

                    let mut b0 = <$s0>::read(GenericArray::from_array([&x0, &x1]));
                    b0.keystream::<4>();
                    b0.write(GenericArray::from_array([&mut x0, &mut x1]));

                    $output0.store_even($i, x0);
                    $output1.store_even($i, x1);

                    x0.xor_with(unsafe { $input0.load(2 * $i + 1) });
                    x1.xor_with(unsafe { $input1.load(2 * $i + 1) });

                    let mut b0 = <$s0>::read(GenericArray::from_array([&x0, &x1]));
                    b0.keystream::<4>();
                    b0.write(GenericArray::from_array([&mut x0, &mut x1]));

                    $output0.store_odd($i, x0);
                    $output1.store_odd($i, x1);
                }};
            }

            if $r <= MAX_R_FOR_UNROLLING {
                repeat8!(i, {
                    if i < $r {
                        iteration!(i);
                    }
                });

                let _ = x0;
                let _ = x1;
            } else {
                for i in 0..$r {
                    iteration!(i);
                }
            }
        }
    };
}

macro_rules! block_mix_dyn {
    ($r:expr; [<$s:ty> $input:expr => $output:expr]) => {{
        let output: &mut [Align64<[u8; 64]>] = $output;
        let mut x: <$s as Salsa20>::Block = unsafe { $input.load($r * 2 - 1) };

        for i in 0..$r {
            x.xor_with(unsafe { $input.load(2 * i) });
            let mut b = <$s>::read(GenericArray::from_array([&x]));
            b.keystream::<4>();
            b.write(GenericArray::from_array([&mut x]));

            unsafe {
                x.write_to_ptr(output[i].as_mut_ptr().cast());
            }

            x.xor_with(unsafe { $input.load(2 * i + 1) });
            let mut b = S::read(GenericArray::from_array([&x]));
            b.keystream::<4>();
            b.write(GenericArray::from_array([&mut x]));

            unsafe {
                x.write_to_ptr(output[i + $r].as_mut_ptr().cast());
            }
        }
    }};
    ($r:expr; [
        <$s0:ty> $input0:expr => $output0:expr,
        <$s1:ty> $input1:expr => $output1:expr$(,)?
    ]) => {{
        let output0: &mut [Align64<[u8; 64]>] = $output0;
        let output1: &mut [Align64<[u8; 64]>] = $output1;
        debug_assert_eq!(output0.len(), output1.len());

        let mut x0: <$s0 as Salsa20>::Block = unsafe { $input0.load($r * 2 - 1) };
        let mut x1: <$s1 as Salsa20>::Block = unsafe { $input1.load($r * 2 - 1) };

        for i in 0..$r {
            x0.xor_with(unsafe { $input0.load(2 * i) });
            x1.xor_with(unsafe { $input1.load(2 * i) });
            let mut b0 = <$s0>::read(GenericArray::from_array([&x0, &x1]));
            b0.keystream::<4>();
            b0.write(GenericArray::from_array([&mut x0, &mut x1]));

            unsafe {
                x0.write_to_ptr(output0[i].as_mut_ptr().cast());
                x1.write_to_ptr(output1[i].as_mut_ptr().cast());
            }

            x0.xor_with(unsafe { $input0.load(2 * i + 1) });
            x1.xor_with(unsafe { $input1.load(2 * i + 1) });
            let mut b0 = <$s0>::read(GenericArray::from_array([&x0, &x1]));
            b0.keystream::<4>();
            b0.write(GenericArray::from_array([&mut x0, &mut x1]));

            unsafe {
                x0.write_to_ptr(output0[i + $r].as_mut_ptr().cast());
                x1.write_to_ptr(output1[i + $r].as_mut_ptr().cast());
            }
        }
    }};
}

#[inline(always)]
/// Perform the BlockMix operation on 2R 128-bit blocks
pub fn block_mix_dyn<
    'a,
    B: crate::BlockType,
    S: Salsa20<Lanes = U1, Block = B>,
    I: ScryptBlockMixInput<'a, B>,
>(
    input: &I,
    output: &mut [Align64<[u8; 64]>],
) {
    let r = output.len() / 2;

    let mut x: S::Block = unsafe { input.load(r * 2 - 1) };

    for i in 0..r {
        x.xor_with(unsafe { input.load(2 * i) });
        let mut b = S::read(GenericArray::from_array([&x]));
        b.keystream::<4>();
        b.write(GenericArray::from_array([&mut x]));

        unsafe {
            x.write_to_ptr(output[i].as_mut_ptr().cast());
        }

        x.xor_with(unsafe { input.load(2 * i + 1) });
        let mut b = S::read(GenericArray::from_array([&x]));
        b.keystream::<4>();
        b.write(GenericArray::from_array([&mut x]));

        unsafe {
            x.write_to_ptr(output[i + r].as_mut_ptr().cast());
        }
    }
}

#[inline(always)]
/// Perform the BlockMix operation on 2R 256-bit blocks
pub fn block_mix_dyn_mb2<
    'a,
    'b,
    B: crate::BlockType,
    S: Salsa20<Lanes = U2, Block = B>,
    I0: ScryptBlockMixInput<'a, B>,
    I1: ScryptBlockMixInput<'b, B>,
>(
    input0: &I0,
    output0: &mut [Align64<[u8; 64]>],
    input1: &I1,
    output1: &mut [Align64<[u8; 64]>],
) {
    debug_assert_eq!(output0.len(), output1.len());
    let r = output0.len().min(output1.len()) / 2;

    let mut x0: S::Block = unsafe { input0.load(r * 2 - 1) };
    let mut x1: S::Block = unsafe { input1.load(r * 2 - 1) };

    for i in 0..r {
        x0.xor_with(unsafe { input0.load(2 * i) });
        x1.xor_with(unsafe { input1.load(2 * i) });
        let mut b0 = S::read(GenericArray::from_array([&x0, &x1]));
        b0.keystream::<4>();
        b0.write(GenericArray::from_array([&mut x0, &mut x1]));

        unsafe {
            x0.write_to_ptr(output0[i].as_mut_ptr().cast());
            x1.write_to_ptr(output1[i].as_mut_ptr().cast());
        }

        x0.xor_with(unsafe { input0.load(2 * i + 1) });
        x1.xor_with(unsafe { input1.load(2 * i + 1) });
        let mut b0 = S::read(GenericArray::from_array([&x0, &x1]));
        b0.keystream::<4>();
        b0.write(GenericArray::from_array([&mut x0, &mut x1]));

        unsafe {
            x0.write_to_ptr(output0[i + r].as_mut_ptr().cast());
            x1.write_to_ptr(output1[i + r].as_mut_ptr().cast());
        }
    }
}
