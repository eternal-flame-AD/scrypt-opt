use std::{
    num::{NonZeroU8, NonZeroU32},
    time::Duration,
};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use generic_array::typenum::{U1, U8, Unsigned};
use scrypt_opt::{
    RoMix, fixed_r::BufferSet, memory::Align64, pbkdf2_1::Pbkdf2HmacSha256State,
    pipeline::PipelineContext,
};

fn bench_static_vs_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("static_vs_dynamic");
    let mut counter = 0u64;

    macro_rules! write_bench {
        ($cf:literal, $r: ty) => {{
            group.throughput(criterion::Throughput::Bytes(
                128 * 2 * <$r>::U64 * (1 << $cf),
            ));
            group.sample_size(20);
            group.warm_up_time(Duration::from_secs(5));
            group.measurement_time(Duration::from_secs(10));

            let mut buf_static0 = BufferSet::<_, $r>::new_boxed($cf.try_into().unwrap());
            let mut buf_static1 = BufferSet::<_, $r>::new_boxed($cf.try_into().unwrap());
            let mut buf_dynamic0 = vec![Align64([0u8; 64]); 2 * 8 * ((1 << $cf) + 2)];
            let mut buf_dynamic1 = vec![Align64([0u8; 64]); 2 * 8 * ((1 << $cf) + 2)];

            group.bench_with_input(
                format!("static/{}/r={}", $cf, <$r>::U32),
                &($cf, <$r>::U32),
                |b, &(_cf, _r)| {
                    b.iter(|| {
                        buf_static0.input_buffer_mut()[..8].copy_from_slice(&counter.to_le_bytes());
                        counter += 1;
                        buf_static0.scrypt_ro_mix();
                        core::hint::black_box(buf_static0.raw_salt_output());
                    });
                },
            );

            group.bench_with_input(
                format!("dynamic/{}/r={}", $cf, <$r>::U32),
                &($cf, <$r>::U32),
                |b, &(cf, r)| {
                    b.iter(|| {
                        buf_dynamic0[0][..8].copy_from_slice(&counter.to_le_bytes());
                        counter += 1;
                        buf_dynamic0.ro_mix_front(r.try_into().unwrap(), cf.try_into().unwrap());
                        buf_dynamic0.ro_mix_back(r.try_into().unwrap(), cf.try_into().unwrap());
                        core::hint::black_box(buf_dynamic0[0].as_slice());
                    });
                },
            );

            group.bench_with_input(
                format!("static_interleaved/{}/r={}", $cf, <$r>::U32),
                &($cf, <$r>::U32),
                |b, &(_cf, _r)| {
                    b.iter(|| {
                        buf_static1.input_buffer_mut()[..8].copy_from_slice(&counter.to_le_bytes());
                        counter += 1;
                        buf_static0.ro_mix_interleaved(&mut buf_static1);
                        core::hint::black_box(buf_static1.raw_salt_output());
                    });
                },
            );

            group.bench_with_input(
                format!("dynamic_interleaved/{}/r={}", $cf, <$r>::U32),
                &($cf, <$r>::U32),
                |b, &(cf, r)| {
                    b.iter(|| {
                        buf_dynamic1[0][..8].copy_from_slice(&counter.to_le_bytes());
                        counter += 1;
                        buf_dynamic0.as_mut_slice().ro_mix_interleaved(
                            &mut buf_dynamic1.as_mut_slice(),
                            r.try_into().unwrap(),
                            cf.try_into().unwrap(),
                        );
                        core::hint::black_box(buf_dynamic0[0].as_slice());
                    });
                },
            );
        }};
    }
    write_bench!(10, U1);
    write_bench!(14, U8);
}

fn bench_api(c: &mut Criterion) {
    let cf = 14;
    let nprocs = num_cpus::get();
    let num_thread_values = [1, nprocs / 2, nprocs];

    let cap_num_threads = std::env::var("CAP_NUM_THREADS")
        .map(|v| {
            v.parse::<usize>()
                .expect("CAP_NUM_THREADS must be a number")
        })
        .ok();

    for num_threads in num_thread_values[..if nprocs > 2 {
        3
    } else if nprocs > 1 {
        2
    } else {
        1
    }]
        .iter()
        .filter(|&&num_threads| {
            cap_num_threads
                .map(|cap_num_threads| num_threads <= cap_num_threads)
                .unwrap_or(true)
        })
    {
        let mut group = c.benchmark_group(format!("api/{num_threads}T"));

        let num_threads = *num_threads;
        for r in [1, 8, 32] {
            for p in [1, 2, 4, 32] {
                group.throughput(criterion::Throughput::Bytes(
                    p * r * num_threads as u64 * (1 << cf) * 128 * 2,
                ));
                group.sample_size(20);
                group.warm_up_time(Duration::from_secs(5));
                group.measurement_time(Duration::from_secs(10));

                group.bench_with_input(
                    BenchmarkId::new("scrypt_kdf/scrypt-opt", format!("ln={cf}/r={r}/p={p}")),
                    &(r, p),
                    |b, &(r, p)| {
                        b.iter_custom(|iters| {
                            let start_barrier = std::sync::Barrier::new(num_threads);
                            let remaining = std::sync::atomic::AtomicI64::new(
                                (iters * num_threads as u64) as i64,
                            );
                            let total_duration = std::sync::atomic::AtomicU64::new(0);
                            std::thread::scope(|s| {
                                for _ in 0..num_threads {
                                    s.spawn(|| {
                                        start_barrier.wait();

                                        let start = std::time::Instant::now();

                                        loop {
                                            let work_id = remaining
                                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                            if work_id <= 0 {
                                                break;
                                            }
                                            let mut output = [0u8; 64];
                                            scrypt_opt::compat::scrypt(
                                                &work_id.to_be_bytes(),
                                                &(r + p).to_be_bytes(),
                                                cf.try_into().unwrap(),
                                                NonZeroU32::new(r as u32).unwrap(),
                                                p.try_into().unwrap(),
                                                &mut output,
                                            );
                                            core::hint::black_box(output);
                                        }
                                        total_duration.fetch_add(
                                            start.elapsed().as_nanos() as u64,
                                            std::sync::atomic::Ordering::Relaxed, // thread::scope already has a AcqRel barrier
                                        );
                                    });
                                }
                            });
                            std::time::Duration::from_nanos(
                                total_duration.load(std::sync::atomic::Ordering::Relaxed)
                                    / num_threads as u64,
                            )
                        });
                    },
                );
                group.bench_with_input(
                    BenchmarkId::new("scrypt_kdf/RustCrypto", format!("ln={cf}/r={r}/p={p}")),
                    &(r, p),
                    |b, &(r, p)| {
                        b.iter_custom(|iters| {
                            let start_barrier = std::sync::Barrier::new(num_threads);
                            let total_duration = std::sync::atomic::AtomicU64::new(0);
                            let remaining = std::sync::atomic::AtomicI64::new(
                                (iters * num_threads as u64) as i64,
                            );
                            std::thread::scope(|s| {
                                for _ in 0..num_threads {
                                    s.spawn(|| {
                                        start_barrier.wait();

                                        let start = std::time::Instant::now();

                                        let params =
                                            scrypt::Params::new(cf, r as u32, p as u32, 64)
                                                .unwrap();

                                        loop {
                                            let work_id = remaining
                                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                            if work_id <= 0 {
                                                break;
                                            }
                                            let mut output = [0u8; 64];

                                            scrypt::scrypt(
                                                &work_id.to_be_bytes(),
                                                &(r + p).to_be_bytes(),
                                                &params,
                                                &mut output,
                                            )
                                            .unwrap();
                                            core::hint::black_box(output);
                                        }
                                        total_duration.fetch_add(
                                            start.elapsed().as_nanos() as u64,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                    });
                                }
                            });
                            std::time::Duration::from_nanos(
                                total_duration.load(std::sync::atomic::Ordering::Relaxed)
                                    / num_threads as u64,
                            )
                        });
                    },
                );
            }
        }
    }
}

fn bench_scrypt(c: &mut Criterion) {
    type R = U8;

    let mut group = c.benchmark_group("scrypt");
    group.throughput(criterion::Throughput::Elements(32));
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(10));
    group.measurement_time(Duration::from_secs(20));

    let mut counter = 0u64;

    const CFS: [NonZeroU8; 2] = [NonZeroU8::new(14).unwrap(), NonZeroU8::new(16).unwrap()];

    let max_minimum_blocks = scrypt_opt::fixed_r::minimum_blocks(*CFS.iter().max().unwrap());
    let mut alloc =
        scrypt_opt::memory::MaybeHugeSlice::<Align64<scrypt_opt::fixed_r::Block<R>>>::new(
            max_minimum_blocks * 2,
        )
        .0;

    for cf in CFS {
        let minimum_blocks = scrypt_opt::fixed_r::minimum_blocks(cf);

        group.bench_function(format!("{}/8/1", 1u32 << cf.get()), |b| {
            let mut buffers0 = scrypt_opt::fixed_r::BufferSet::<_, R>::new(unsafe {
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
            let mut buffers0 = scrypt_opt::fixed_r::BufferSet::<_, R>::new(unsafe {
                core::slice::from_raw_parts_mut(alloc.as_mut().as_mut_ptr(), minimum_blocks)
            });
            let mut buffers1 = scrypt_opt::fixed_r::BufferSet::<_, R>::new(unsafe {
                core::slice::from_raw_parts_mut(
                    alloc.as_mut().as_mut_ptr().add(minimum_blocks),
                    minimum_blocks,
                )
            });

            struct Context {
                hmac_state: Pbkdf2HmacSha256State,
            }

            impl PipelineContext<(), &mut [Align64<scrypt_opt::fixed_r::Block<R>>], R, ()> for Context {
                #[inline(always)]
                fn begin(
                    &mut self,
                    _state: &mut (),
                        buffer_set: &mut scrypt_opt::fixed_r::BufferSet<
                        &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                        R,
                    >,
                ) {
                    buffer_set.set_input(&self.hmac_state, b"salt");
                }

                #[inline(always)]
                fn drain(
                    self,
                    _state: &mut (),
                    buffer_set: &mut scrypt_opt::fixed_r::BufferSet<
                        &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                        R,
                    >,
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

criterion_group!(benches, bench_scrypt, bench_api, bench_static_vs_dynamic);
criterion_main!(benches);
