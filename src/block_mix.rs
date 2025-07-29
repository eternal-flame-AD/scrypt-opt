macro_rules! block_mix {
    ($r:expr; [<$s:ty> $input:expr => $output:expr]) => {{
        use crate::{
            ScryptBlockMixInput, ScryptBlockMixOutput,
            salsa20::{BlockType, Salsa20},
        };

        let mut x: <$s as Salsa20>::Block = $input.load($r * 2 - 1);

        macro_rules! iteration {
            ($i:expr) => {{
                x.xor_with($input.load(2 * $i));

                let mut b0 = <$s>::read(GenericArray::from_array([&x]));
                b0.keystream::<4>();
                b0.write(GenericArray::from_array([&mut x]));

                $output.store_even($i, x);

                x.xor_with($input.load(2 * $i + 1));

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
    }};
    ($r:expr; [
        <$s0:ty> $input0:expr => $output0:expr,
        <$s1:ty> $input1:expr => $output1:expr$(,)?
    ]) => {{
        let mut x0: <$s0 as Salsa20>::Block = $input0.load($r * 2 - 1);
        let mut x1: <$s1 as Salsa20>::Block = $input1.load($r * 2 - 1);

        macro_rules! iteration {
            ($i:expr) => {{
                x0.xor_with($input0.load(2 * $i));
                x1.xor_with($input1.load(2 * $i));

                let mut b0 = <$s0>::read(GenericArray::from_array([&x0, &x1]));
                b0.keystream::<4>();
                b0.write(GenericArray::from_array([&mut x0, &mut x1]));

                $output0.store_even($i, x0);
                $output1.store_even($i, x1);

                x0.xor_with($input0.load(2 * $i + 1));
                x1.xor_with($input1.load(2 * $i + 1));

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
    }};
}
