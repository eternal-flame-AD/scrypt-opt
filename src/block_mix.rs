#[allow(unused_macros, reason = "false alarm")]
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

            if $r <= crate::fixed_r::MAX_R_FOR_UNROLLING {
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

            if $r <= crate::fixed_r::MAX_R_FOR_UNROLLING {
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
#[allow(unused_macros, reason = "false alarm")]
macro_rules! block_mix_dyn {
    ($r:expr; [<$s:ty> $input:expr => $output:expr]) => {{
        let output: &mut [Align64<crate::fixed_r::Block<U1>>] = $output;
        let mut x: <$s as Salsa20>::Block = unsafe { $input.load($r * 2 - 1) };

        for i in 0..$r {
            x.xor_with(unsafe { $input.load(2 * i) });
            let mut b = <$s>::read(GenericArray::from_array([&x]));
            b.keystream::<4>();
            b.write(GenericArray::from_array([&mut x]));

            unsafe {
                x.write_to_ptr(output.as_mut_ptr().cast::<[u8; 64]>().add(i).cast());
            }

            x.xor_with(unsafe { $input.load(2 * i + 1) });
            let mut b = S::read(GenericArray::from_array([&x]));
            b.keystream::<4>();
            b.write(GenericArray::from_array([&mut x]));

            unsafe {
                x.write_to_ptr(output.as_mut_ptr().cast::<[u8; 64]>().add(i + $r).cast());
            }
        }
    }};
    ($r:expr; [
        <$s0:ty> $input0:expr => $output0:expr,
        <$s1:ty> $input1:expr => $output1:expr$(,)?
    ]) => {{
        let output0: &mut [Align64<crate::fixed_r::Block<U1>>] = $output0;
        let output1: &mut [Align64<crate::fixed_r::Block<U1>>] = $output1;
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
                x0.write_to_ptr(output0.as_mut_ptr().cast::<[u8; 64]>().add(i).cast());
                x1.write_to_ptr(output1.as_mut_ptr().cast::<[u8; 64]>().add(i).cast());
            }

            x0.xor_with(unsafe { $input0.load(2 * i + 1) });
            x1.xor_with(unsafe { $input1.load(2 * i + 1) });
            let mut b0 = <$s0>::read(GenericArray::from_array([&x0, &x1]));
            b0.keystream::<4>();
            b0.write(GenericArray::from_array([&mut x0, &mut x1]));

            unsafe {
                x0.write_to_ptr(output0.as_mut_ptr().cast::<[u8; 64]>().add(i + $r).cast());
                x1.write_to_ptr(output1.as_mut_ptr().cast::<[u8; 64]>().add(i + $r).cast());
            }
        }
    }};
}
