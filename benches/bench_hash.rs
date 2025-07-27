use std::{num::NonZeroU8, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use generic_array::typenum::{U8, Unsigned};
use scrypt_opt::{memory::Align64, pbkdf2_1::Pbkdf2HmacSha256State, pipeline::PipelineContext};

fn bench_scrypt(c: &mut Criterion) {
    type R = U8;

    let mut group = c.benchmark_group("scrypt");
    group.throughput(criterion::Throughput::Elements(32));
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(10));
    group.measurement_time(Duration::from_secs(20));

    let mut counter = 0u64;

    const CFS: [NonZeroU8; 2] = [NonZeroU8::new(14).unwrap(), NonZeroU8::new(16).unwrap()];

    let max_minimum_blocks =
        scrypt_opt::BufferSet::<&mut [Align64<scrypt_opt::Block<R>>], R>::minimum_blocks(
            *CFS.iter().max().unwrap(),
        );
    let mut alloc = scrypt_opt::memory::MaybeHugeSlice::<Align64<scrypt_opt::Block<R>>>::new(
        max_minimum_blocks * 2,
    )
    .0;

    for cf in CFS {
        let minimum_blocks =
            scrypt_opt::BufferSet::<&mut [Align64<scrypt_opt::Block<R>>], R>::minimum_blocks(cf);

        group.bench_function(format!("{}/8/1", 1u32 << cf.get()), |b| {
            let mut buffers0 = scrypt_opt::BufferSet::<_, R>::new(unsafe {
                core::slice::from_raw_parts_mut(
                    alloc.as_mut().as_mut_ptr().add(minimum_blocks),
                    minimum_blocks,
                )
            });
            b.iter(|| {
                let mut output = [0u8; 12];
                for di in 0..32u32 {
                    let hmac = Pbkdf2HmacSha256State::new(&di.to_ne_bytes());
                    buffers0.set_input(&hmac, b"salt");
                    buffers0.scrypt_ro_mix();
                    buffers0.extract_output(&hmac, &mut output);
                    core::hint::black_box(output);
                }
            });
        });

        group.bench_function(format!("{}/8/1_interleaved", 1u32 << cf.get()), |b| {
            let mut buffers0 = scrypt_opt::BufferSet::<_, R>::new(unsafe {
                core::slice::from_raw_parts_mut(alloc.as_mut().as_mut_ptr(), minimum_blocks)
            });
            let mut buffers1 = scrypt_opt::BufferSet::<_, R>::new(unsafe {
                core::slice::from_raw_parts_mut(
                    alloc.as_mut().as_mut_ptr().add(minimum_blocks),
                    minimum_blocks,
                )
            });

            struct Context {
                hmac_state: Pbkdf2HmacSha256State,
            }

            impl PipelineContext<(), &mut [Align64<scrypt_opt::Block<R>>], R, ()> for Context {
                #[inline(always)]
                fn begin(
                    &mut self,
                    _state: &mut (),
                    buffer_set: &mut scrypt_opt::BufferSet<&mut [Align64<scrypt_opt::Block<R>>], R>,
                ) {
                    buffer_set.set_input(&self.hmac_state, b"salt");
                }

                #[inline(always)]
                fn drain(
                    self,
                    _state: &mut (),
                    buffer_set: &mut scrypt_opt::BufferSet<&mut [Align64<scrypt_opt::Block<R>>], R>,
                ) -> Option<()> {
                    let mut output = [0u8; 32];
                    buffer_set.extract_output(&self.hmac_state, &mut output);
                    core::hint::black_box(output);
                    None
                }
            }

            b.iter(|| {
                buffers0.pipeline(
                    &mut buffers1,
                    (0..32u32).map(|i| Context {
                        hmac_state: Pbkdf2HmacSha256State::new(&i.to_ne_bytes()),
                    }),
                    &mut (),
                );
            });
        });

        group.bench_function(format!("{}/8/1_rustcrypto", 1u32 << cf.get()), |b| {
            let params = scrypt::Params::new(cf.try_into().unwrap(), R::U32, 1, 64).unwrap();
            b.iter_batched(
                || {
                    let mut input = [0u8; 12];
                    input[..8].copy_from_slice(counter.to_le_bytes().as_slice());
                    counter += 1;
                    input
                },
                |mut input| {
                    let mut output = [0u8; 12];
                    for di in 0..32u32 {
                        input[8..].copy_from_slice(&di.to_le_bytes());
                        scrypt::scrypt(&input, b"salt", &params, &mut output).unwrap();
                        core::hint::black_box(output);
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, bench_scrypt);
criterion_main!(benches);
