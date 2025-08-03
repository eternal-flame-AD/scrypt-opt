use base64::{
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    prelude::*,
    write::EncoderWriter,
};
use clap::Parser;
use crossbeam_utils::CachePadded;
use generic_array::{
    ArrayLength,
    typenum::{
        B0, B1, Bit, NonZero, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, U16,
    },
};
use password_hash::Ident;
use scrypt_opt::{
    RoMix,
    memory::Align64,
    pbkdf2_1::{CreatePbkdf2HmacSha256State, Pbkdf2HmacSha256State},
    pipeline::PipelineContext,
    self_test::{
        Case, CaseN16R1P1, CaseN1024R1P2, CaseN1024R8P16, CaseN1024R53P1, CaseN1024R53P3,
        CaseN16384R8P1, CaseN1048576R8P1, CaseP1,
    },
};

#[cfg(feature = "core_affinity")]
use std::num::NonZeroUsize;

use std::{
    io::{BufRead, BufReader, Read, Write},
    marker::PhantomData,
    num::{NonZeroU8, NonZeroU32, NonZeroU64},
    ops::DerefMut,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64},
    },
};

#[rustfmt::skip]
macro_rules! match_r {
    ($r:expr, $b:ident, $c:block) => {
        match $r {
            1 => { type $b = U1; Some($c) },    
            2 => { type $b = U2; Some($c) },
            3 => { type $b = U3; Some($c) },
            4 => { type $b = U4; Some($c) },
            5 => { type $b = U5; Some($c) },
            6 => { type $b = U6; Some($c) },
            7 => { type $b = U7; Some($c) },
            8 => { type $b = U8; Some($c) },
            9 => { type $b = U9; Some($c) },
            10 => { type $b = U10; Some($c) },
            11 => { type $b = U11; Some($c) },
            12 => { type $b = U12; Some($c) },
            13 => { type $b = U13; Some($c) },
            14 => { type $b = U14; Some($c) },
            15 => { type $b = U15; Some($c) },
            16 => { type $b = U16; Some($c) },
            _ => None,
        }
    };
}

#[rustfmt::skip]
macro_rules! match_op {
    ($op:expr, $b:ident, $c:block) => {
        match $op {
            "LT" | "lt" => { const $b: u32 = scrypt_opt::pipeline::CMP_LT; $c },
            "GT" | "gt" => { const $b: u32 = scrypt_opt::pipeline::CMP_GT; $c },
            "LE" | "le" => { const $b: u32 = scrypt_opt::pipeline::CMP_LE; $c },
            "GE" | "ge" => { const $b: u32 = scrypt_opt::pipeline::CMP_GE; $c },
            "EQ" | "eq" => { const $b: u32 = scrypt_opt::pipeline::CMP_EQ; $c },
            _ => panic!("invalid op: {}", $op),
        }
    };
}

#[derive(clap::Subcommand)]
enum Command {
    Info,
    Cast {
        #[arg(short, long)]
        fast: bool,
    },
    Compute {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        salt: Option<String>,
        #[arg(short, long, default_value = "14")]
        cf: NonZeroU8,
        #[arg(short, long, default_value = "8")]
        r: u32,
        #[arg(short, long, default_value = "1")]
        p: u32,
        #[arg(short, long, default_value = "64")]
        output_len: usize,
        #[arg(long)]
        output_raw: bool,
    },
    Throughput {
        #[arg(short, long, default_value = "14")]
        cf: NonZeroU8,
        #[arg(short, long, default_value = "8")]
        r: NonZeroU32,
        #[arg(short, long)]
        no_pipeline: bool,
    },
    Search {
        #[arg(long, help = "target hash in PHC format")]
        target: String,

        #[arg(long)]
        progress: bool,

        #[arg(default_value = "-")]
        file: String,
    },
    Pow {
        #[arg(
            long,
            default_value = "LE",
            help = "Comparison operator (LE/GE/EQ/LT/GT)"
        )]
        op: String,
        #[arg(short, long, default_value = "14", help = "N value (log2)")]
        cf: NonZeroU8,
        #[arg(short, long, default_value = "8", help = "R value")]
        r: NonZeroU32,
        #[arg(short, long, default_value = "1", help = "P value")]
        p: NonZeroU32,
        #[arg(long, default_value = "8", help = "length of nonce in bytes")]
        nonce_len: usize,
        #[arg(
            long,
            help = "length of output in bytes (default: offset rounded up to 8 bytes)"
        )]
        output_len: Option<usize>,
        #[arg(long, default_value = "U29kaXVtQ2xvcmlkZQ==")] // "SodiumChloride"
        salt: String,
        #[arg(
            long,
            default_value = "0",
            help = "offset in nibbles for the target hash"
        )]
        offset: usize,
        #[arg(long, help = "target hash in hex")]
        target: String,
        #[arg(
            long,
            help = "target mask in hex (Implicitly (1 << target_signif_bits) - 1)"
        )]
        mask: Option<String>,
        #[arg(long)]
        quiet: bool,
    },
}

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "1")]
    num_threads: NonZeroU32,
    #[cfg(feature = "core_affinity")]
    #[arg(short, long, default_value = "1")]
    core_stride: NonZeroUsize,
    #[command(subcommand)]
    command: Command,
}

#[cold]
fn unlikely() {}

#[derive(Clone, Copy, Debug)]
struct Key(CachePadded<[u8; 256]>);

impl Key {
    fn key_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.0.as_ptr().add(1), self.0[0] as usize) }
    }
}

impl CreatePbkdf2HmacSha256State for Key {
    fn create_pbkdf2_hmac_sha256_state(&self) -> Pbkdf2HmacSha256State {
        Pbkdf2HmacSha256State::new(self.key_bytes())
    }
}

const KAT_PASSWORD: [u8; 13] = *b"pleaseletmein";
const KAT_SALT: &[u8] = b"SodiumChloride";
const KAT_EXPECTED: [u8; 64] = [
    0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
    0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
    0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
    0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87,
];

fn slurp_stdin() -> Box<[u8]> {
    let mut stdin = std::io::stdin().lock();
    let mut buffer = Vec::new();
    stdin.read_to_end(&mut buffer).unwrap();
    buffer.into_boxed_slice()
}

struct MultiThreadedHugeSlice<T> {
    len_per_thread: usize,
    num_threads: NonZeroU32,
    inner: scrypt_opt::memory::MaybeHugeSlice<T>,
    _marker: PhantomData<T>,
}

impl<T> MultiThreadedHugeSlice<T> {
    fn new(len_per_thread: usize, num_threads: NonZeroU32) -> Self {
        if len_per_thread == 0 {
            return Self {
                len_per_thread,
                num_threads,
                inner: scrypt_opt::memory::MaybeHugeSlice::new_slice_zeroed(0),
                _marker: PhantomData,
            };
        }

        let (inner, error) = scrypt_opt::memory::MaybeHugeSlice::new(
            len_per_thread
                .checked_mul(num_threads.get() as usize)
                .expect("size overflow"),
        );

        if let Some(error) = error {
            eprintln!("Failed to allocate huge page: {}", error);
        } else {
            eprintln!("Huge Page allocation successful");
        }

        Self {
            len_per_thread,
            num_threads,
            inner,
            _marker: PhantomData,
        }
    }

    fn get(
        &mut self,
    ) -> impl IntoIterator<Item = impl DerefMut<Target = impl AsMut<[T]> + ?Sized>> {
        let mut inner = self.inner.as_mut();
        let num_threads = self.num_threads.get();
        let mut ret = Vec::with_capacity(num_threads as usize);
        for _ in 0..num_threads as usize {
            let (this, rest) = inner.split_at_mut(self.len_per_thread);
            ret.push(this);
            inner = rest;
        }
        ret.into_boxed_slice()
    }
}

#[cfg(feature = "core_affinity")]
struct CoreAffinityAssigner {
    core_ids: Option<Vec<core_affinity::CoreId>>,
    stride: NonZeroUsize,
    ptr: usize,
}

#[cfg(feature = "core_affinity")]
impl CoreAffinityAssigner {
    fn new(mut stride: NonZeroUsize) -> Self {
        let core_ids = core_affinity::get_core_ids();

        if let Some(core_ids) = &core_ids {
            let modulo = stride.get() % core_ids.len();
            stride = NonZeroUsize::new(modulo).unwrap_or(NonZeroUsize::new(1).unwrap());
        }

        Self {
            core_ids,
            stride,
            ptr: 0,
        }
    }

    fn next(&mut self) -> Option<core_affinity::CoreId> {
        let Some(core_ids) = &self.core_ids else {
            return None;
        };

        let ret = core_ids[self.ptr];

        self.ptr += self.stride.get();
        if self.ptr >= core_ids.len() {
            self.ptr -= core_ids.len();
            if core_ids.len() > 1 {
                self.ptr += 1;
            }
        }

        Some(ret)
    }
}

fn pgeom_inv(q: u64, prob: f64) -> f64 {
    (1.0 - prob).powf(q as f64)
}

struct PowResult {
    nonce: u64,
    output: Box<[u8]>,
    actual_iterations: u64,
    elapsed: std::time::Duration,
}

fn pow<const OP: u32>(
    salt: &[u8],
    cf: NonZeroU8,
    r: NonZeroU32,
    p: NonZeroU32,
    mask: NonZeroU64,
    target: u64,
    num_threads: NonZeroU32,
    offset: usize,
    output_len: usize,
    nonce_len: usize,
    #[cfg(feature = "core_affinity")] core_stride: NonZeroUsize,
) -> Option<PowResult> {
    assert!(
        nonce_len <= Pbkdf2HmacSha256State::MAX_SHORT_PASSWORD_LEN,
        "nonce length must be less than or equal to {} for now",
        Pbkdf2HmacSha256State::MAX_SHORT_PASSWORD_LEN
    );

    let required_blocks = scrypt_opt::fixed_r::minimum_blocks(cf);

    let search_max = if nonce_len == 8 {
        u64::MAX - 1
    } else {
        (1 << (nonce_len * 8)) - 1
    };

    let mut full_slice = MultiThreadedHugeSlice::<Align64<scrypt_opt::fixed_r::Block<U1>>>::new(
        required_blocks * 2 * r.get() as usize,
        num_threads,
    );

    let stop_signal = AtomicBool::new(false);
    let found_nonce = AtomicU64::new(0);
    let retired_count = AtomicU64::new(0);
    let output = Mutex::new(vec![0u8; output_len].into_boxed_slice());

    let start_time = std::time::Instant::now();
    std::thread::scope(|s| {
        #[cfg(feature = "core_affinity")]
        let mut core_assigner = CoreAffinityAssigner::new(core_stride);

        for (thread_idx, mut local_buffer) in full_slice.get().into_iter().enumerate() {
            #[cfg(feature = "core_affinity")]
            let core = core_assigner.next();
            let output = &output;
            let retired_count = &retired_count;
            let stop_signal = &stop_signal;
            let found_nonce = &found_nonce;

            std::thread::Builder::new()
                .name(format!("pow-worker-{}", thread_idx))
                .spawn_scoped(s, move || {
                    #[cfg(feature = "core_affinity")]
                    if let Some(core) = core {
                        if !core_affinity::set_for_current(core) {
                            eprintln!("Failed to set core affinity for thread {}", thread_idx);
                        }
                    } else {
                        eprintln!("No core affinity available for thread {}", thread_idx);
                    }

                    let mut nonce_generator = ((thread_idx as u64)..=search_max)
                        .step_by(num_threads.get() as usize)
                        .take_while(|_| {
                            if stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                                return false;
                            }
                            retired_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            true
                        });

                    let result = match_r!(r.get(), R, {
                        // if P=1 and R is small, try a static pipeline
                        let (buffer0_inner, buffer1_inner) = local_buffer.as_mut()
                            [..required_blocks * r.get() as usize * 2]
                            .split_at_mut(required_blocks * r.get() as usize);

                        let mut buffer0 = scrypt_opt::fixed_r::BufferSet::<
                            &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                            R,
                        >::new(unsafe {
                            core::slice::from_raw_parts_mut(
                                buffer0_inner.as_mut_ptr().cast(),
                                buffer1_inner.len() / r.get() as usize,
                            )
                        });

                        let mut buffer1 = scrypt_opt::fixed_r::BufferSet::<
                            &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                            R,
                        >::new(unsafe {
                            core::slice::from_raw_parts_mut(
                                buffer1_inner.as_mut_ptr().cast(),
                                buffer1_inner.len() / r.get() as usize,
                            )
                        });

                        scrypt_opt::pipeline::test_static::<OP, _, R, _>(
                            [&mut buffer0, &mut buffer1],
                            p,
                            salt,
                            mask,
                            target,
                            offset,
                            &mut nonce_generator,
                        )
                    })
                    .unwrap_or_else(|| {
                        // otherwise, use the dynamic pipeline
                        scrypt_opt::pipeline::test::<OP, _>(
                            local_buffer.as_mut(),
                            cf,
                            r,
                            p,
                            salt,
                            mask,
                            target,
                            offset,
                            &mut nonce_generator,
                        )
                    });

                    if let Some((nonce, hmac_state)) = result {
                        stop_signal.store(true, std::sync::atomic::Ordering::Relaxed);
                        let mut output = output.lock().unwrap();
                        hmac_state.emit(&mut output);
                        found_nonce.store(nonce, std::sync::atomic::Ordering::Relaxed);
                    }
                })
                .expect("failed to spawn thread");
        }
    });

    if !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }

    let output = Mutex::into_inner(output).unwrap();

    Some(PowResult {
        nonce: found_nonce.load(std::sync::atomic::Ordering::Relaxed),
        output,
        actual_iterations: retired_count.load(std::sync::atomic::Ordering::Relaxed) - 1,
        elapsed: start_time.elapsed(),
    })
}

struct SearchResult {
    key: Box<[u8]>,
    elapsed: std::time::Duration,
}

fn search(
    iterations: &AtomicU64,
    rx: &crossbeam_channel::Receiver<Key>,
    needle: &[u8],
    salt: &[u8],
    cf: NonZeroU8,
    r: NonZeroU32,
    p: NonZeroU32,
    num_threads: NonZeroU32,
    #[cfg(feature = "core_affinity")] core_stride: NonZeroUsize,
) -> Option<SearchResult> {
    let required_blocks = scrypt_opt::fixed_r::minimum_blocks(cf);

    let mut full_slice = MultiThreadedHugeSlice::<Align64<scrypt_opt::fixed_r::Block<U1>>>::new(
        required_blocks * 2 * r.get() as usize,
        num_threads,
    );

    let stop_signal = AtomicBool::new(false);

    let target = u64::from_be_bytes(needle[..8].try_into().unwrap()); // PHC requires at least 10 bytes of output

    let output = Mutex::new(Key(CachePadded::new([0u8; 256])));

    let start_time = std::time::Instant::now();
    std::thread::scope(|s| {
        #[cfg(feature = "core_affinity")]
        let mut core_assigner = CoreAffinityAssigner::new(core_stride);

        for (thread_idx, mut local_buffer) in full_slice.get().into_iter().enumerate() {
            #[cfg(feature = "core_affinity")]
            let core = core_assigner.next();
            let output = &output;
            let iterations = &iterations;
            let stop_signal = &stop_signal;

            std::thread::Builder::new()
                .name(format!("search-worker-{}", thread_idx))
                .spawn_scoped(s, move || {
                    #[cfg(feature = "core_affinity")]
                    if let Some(core) = core {
                        if !core_affinity::set_for_current(core) {
                            eprintln!("Failed to set core affinity for thread {}", thread_idx);
                        }
                    } else {
                        eprintln!("No core affinity available for thread {}", thread_idx);
                    }

                    loop {
                        let mut pending_key = None;
                        let mut key_generator = core::iter::from_fn(|| {
                            if stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                                return None;
                            }

                            iterations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let key = rx.recv().ok();
                            pending_key = key.clone();

                            key
                        });

                        let result = match_r!(r.get(), R, {
                            // if P=1 and R is small, try a static pipeline
                            let (buffer0_inner, buffer1_inner) = local_buffer.as_mut()
                                [..required_blocks * r.get() as usize * 2]
                                .split_at_mut(required_blocks * r.get() as usize);

                            let mut buffer0 = scrypt_opt::fixed_r::BufferSet::<
                                &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                                R,
                            >::new(unsafe {
                                core::slice::from_raw_parts_mut(
                                    buffer0_inner.as_mut_ptr().cast(),
                                    buffer1_inner.len() / r.get() as usize,
                                )
                            });

                            let mut buffer1 = scrypt_opt::fixed_r::BufferSet::<
                                &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                                R,
                            >::new(unsafe {
                                core::slice::from_raw_parts_mut(
                                    buffer1_inner.as_mut_ptr().cast(),
                                    buffer1_inner.len() / r.get() as usize,
                                )
                            });

                            scrypt_opt::pipeline::test_static::<
                                { scrypt_opt::pipeline::CMP_EQ },
                                _,
                                R,
                                _,
                            >(
                                [&mut buffer0, &mut buffer1],
                                p,
                                salt,
                                u64::MAX.try_into().unwrap(),
                                target,
                                0,
                                &mut key_generator,
                            )
                        })
                        .unwrap_or_else(|| {
                            // otherwise, use the dynamic pipeline
                            scrypt_opt::pipeline::test::<{ scrypt_opt::pipeline::CMP_EQ }, _>(
                                local_buffer.as_mut(),
                                cf,
                                r,
                                p,
                                salt,
                                u64::MAX.try_into().unwrap(),
                                target,
                                0,
                                &mut key_generator,
                            )
                        });

                        if let Some((mut found_key, hmac_state)) = result {
                            // double check the full output
                            let mut full_output = vec![0u8; needle.len()].into_boxed_slice();
                            hmac_state.emit(&mut full_output);

                            // the first 64-bit matched but the rest does not
                            if &*full_output != needle {
                                unlikely();

                                // this is astronomically unlikely happen so let's just fix it up with the slow but compact version
                                if let Some(pending_key) = pending_key {
                                    scrypt_opt::compat::scrypt(
                                        &pending_key.key_bytes(),
                                        salt,
                                        cf,
                                        r,
                                        p,
                                        &mut full_output,
                                    );

                                    if &*full_output != needle {
                                        // none of the keys in the pipeline matched, loop back and restart the pipeline
                                        continue;
                                    }

                                    // two jackpots in a row, the last one matched 64-bit and the next matched exactly
                                    unlikely();

                                    found_key = pending_key;
                                }
                            }

                            let is_leader =
                                !stop_signal.fetch_or(true, std::sync::atomic::Ordering::Relaxed);

                            if is_leader {
                                *output.lock().unwrap() = found_key;
                            }
                        }

                        return;
                    }
                })
                .expect("failed to spawn thread");
        }
    });

    if !stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }

    let key_len = output.lock().unwrap().0[0];
    let key = output.lock().unwrap().0[1..][..key_len as usize].to_vec();

    Some(SearchResult {
        key: key.into_boxed_slice(),
        elapsed: start_time.elapsed(),
    })
}

fn cast(fast: bool) {
    macro_rules! case {
        ($name:literal, $c:block) => {{
            let mut stdout = std::io::stdout().lock();
            write!(stdout, "Testing: {} ... ", $name).unwrap();
            stdout.flush().unwrap();
            let start = std::time::Instant::now();
            $c
            let elapsed = start.elapsed();
            writeln!(stdout, "PASS ({} ms)", elapsed.as_millis()).unwrap();
        }};
    }

    case!("16/1/1", { CaseN16R1P1::algorithm_self_test() });
    case!("16/1/1 (pipeline)", { CaseN16R1P1::pipeline_api_test() });
    case!("1024/1/2", { CaseN1024R1P2::algorithm_self_test() });
    case!("1024/8/16", { CaseN1024R8P16::algorithm_self_test() });
    case!("1024/53/1", { CaseN1024R53P1::algorithm_self_test() });
    case!("1024/53/1 (pipeline)", {
        CaseN1024R53P1::pipeline_api_test()
    });
    case!("1024/53/3", { CaseN1024R53P3::algorithm_self_test() });

    if !fast {
        case!("16384/8/1", { CaseN16384R8P1::algorithm_self_test() });
        case!("16384/8/1 (pipeline)", {
            CaseN16384R8P1::pipeline_api_test()
        });
        case!("1048576/8/1", { CaseN1048576R8P1::algorithm_self_test() });
    }

    println!("------ PASSED ALL TESTS ------");
}

fn throughput<Pipeline: Bit, R: ArrayLength + NonZero>(
    num_threads: NonZeroU32,
    cf: NonZeroU8,
    #[cfg(feature = "core_affinity")] core_stride: NonZeroUsize,
) {
    let counter = AtomicU64::new(0);

    let required_blocks = scrypt_opt::fixed_r::minimum_blocks(cf);

    let mut full_slice = MultiThreadedHugeSlice::<Align64<scrypt_opt::fixed_r::Block<R>>>::new(
        if Pipeline::BOOL {
            required_blocks * 2
        } else {
            required_blocks
        },
        num_threads,
    );

    #[cfg(feature = "core_affinity")]
    let mut core_assigner = CoreAffinityAssigner::new(core_stride);

    std::thread::scope(|s| {
        for (thread_idx, mut local_buffer) in full_slice.get().into_iter().enumerate() {
            #[cfg(feature = "core_affinity")]
            let core = core_assigner.next();

            let mut counter = &counter;

            std::thread::Builder::new()
                .name(format!("throughput-worker-{}", thread_idx))
                .spawn_scoped(s, move || {
                    #[cfg(feature = "core_affinity")]
                    if let Some(core) = core {
                        if !core_affinity::set_for_current(core) {
                            eprintln!("Failed to set core affinity for thread {}", thread_idx);
                        }
                    }

                    let (buffer0_inner, buffer1_inner) =
                        local_buffer.as_mut().split_at_mut(required_blocks);

                    let mut buffers0 = scrypt_opt::fixed_r::BufferSet::<
                        &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                        R,
                    >::new(buffer0_inner);

                    if !Pipeline::BOOL {
                        let mut password = KAT_PASSWORD;
                        let hmac_state = Pbkdf2HmacSha256State::new(&password);
                        let mut output = [0u8; KAT_EXPECTED.len()];
                        for i in 0u64.. {
                            password[..8].copy_from_slice(&i.to_le_bytes());
                            buffers0.set_input(&hmac_state, KAT_SALT);
                            buffers0.scrypt_ro_mix();
                            buffers0.extract_output(&hmac_state, &mut output);
                            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }

                        return;
                    }

                    let mut buffers1 = scrypt_opt::fixed_r::BufferSet::<
                        &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                        R,
                    >::new(buffer1_inner);

                    struct Context {
                        hmac_state: Pbkdf2HmacSha256State,
                    }

                    impl Context {
                        #[inline(always)]
                        fn new(i: u64) -> Self {
                            let mut password = KAT_PASSWORD;
                            if i >= 3 {
                                password[..8].copy_from_slice(&i.to_le_bytes());
                                password[8] = 0;
                            }
                            Self {
                                hmac_state: Pbkdf2HmacSha256State::new(&password),
                            }
                        }
                    }

                    impl<R: ArrayLength + NonZero>
                        PipelineContext<
                            &AtomicU64,
                            &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                            R,
                            (),
                        > for Context
                    {
                        #[inline(always)]
                        fn begin(
                            &mut self,
                            _state: &mut &AtomicU64,
                            buffer_set: &mut scrypt_opt::fixed_r::BufferSet<
                                &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                                R,
                            >,
                        ) {
                            buffer_set.set_input(&self.hmac_state, KAT_SALT);
                        }

                        #[inline(always)]
                        fn drain(
                            self,
                            counter: &mut &AtomicU64,
                            buffer_set: &mut scrypt_opt::fixed_r::BufferSet<
                                &mut [Align64<scrypt_opt::fixed_r::Block<R>>],
                                R,
                            >,
                        ) -> Option<()> {
                            let mut output = [0u8; KAT_EXPECTED.len()];
                            buffer_set.extract_output(&self.hmac_state, &mut output);
                            core::hint::black_box(output);

                            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            None
                        }
                    }

                    buffers0.pipeline(&mut buffers1, (0..).map(|i| Context::new(i)), &mut counter);
                })
                .expect("failed to spawn thread");
        }

        println!(
            "Started {} threads (N={}, R={}, P=1)",
            num_threads,
            1u64 << cf.get(),
            R::USIZE
        );

        let mut prev = counter.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            let cur = counter.load(std::sync::atomic::Ordering::Relaxed);
            println!("Thrpt: {} c/s (total: {})", cur - prev, cur);
            prev = cur;
        }
    });
}

fn throughput_dyn<Pipeline: Bit>(
    num_threads: NonZeroU32,
    cf: NonZeroU8,
    r: NonZeroU32,
    #[cfg(feature = "core_affinity")] core_stride: NonZeroUsize,
) {
    let counter = AtomicU64::new(0);

    let required_blocks = scrypt_opt::fixed_r::minimum_blocks(cf);

    let mut full_slice = MultiThreadedHugeSlice::<Align64<scrypt_opt::fixed_r::Block<U1>>>::new(
        required_blocks * r.get() as usize * (if Pipeline::BOOL { 2 } else { 1 }),
        num_threads,
    );

    #[cfg(feature = "core_affinity")]
    let mut core_assigner = CoreAffinityAssigner::new(core_stride);

    std::thread::scope(|s| {
        for (thread_idx, mut local_buffer) in full_slice.get().into_iter().enumerate() {
            #[cfg(feature = "core_affinity")]
            let core = core_assigner.next();

            let counter = &counter;

            std::thread::Builder::new()
                .name(format!("throughput-worker-{}", thread_idx))
                .spawn_scoped(s, move || {
                    #[cfg(feature = "core_affinity")]
                    if let Some(core) = core {
                        if !core_affinity::set_for_current(core) {
                            eprintln!("Failed to set core affinity for thread {}", thread_idx);
                        }
                    }

                    let (mut buffer0, mut buffer1) = local_buffer
                        .as_mut()
                        .split_at_mut(required_blocks * r.get() as usize);

                    for _ in 0.. {
                        let hmac_state = Pbkdf2HmacSha256State::new(&0u64.to_le_bytes());
                        let mut output_hmac_state = hmac_state.clone();
                        hmac_state.emit_scatter(
                            KAT_SALT,
                            buffer0
                                .ro_mix_input_buffer(r)
                                .chunks_exact_mut(core::mem::size_of::<
                                    Align64<scrypt_opt::fixed_r::Block<U1>>,
                                >())
                                .map(|chunk| unsafe {
                                    chunk
                                        .as_mut_ptr()
                                        .cast::<Align64<scrypt_opt::fixed_r::Block<U1>>>()
                                        .as_mut()
                                        .unwrap()
                                }),
                        );

                        let salt = if Pipeline::BOOL {
                            buffer0.ro_mix_interleaved(&mut buffer1, r, cf)
                        } else {
                            buffer0.ro_mix_front(r, cf);
                            buffer0.ro_mix_back(r, cf)
                        };

                        output_hmac_state.ingest_salt(unsafe {
                            core::slice::from_raw_parts(
                                salt.as_ptr()
                                    .cast::<Align64<scrypt_opt::fixed_r::Block<U1>>>(),
                                salt.len()
                                    / core::mem::size_of::<Align64<scrypt_opt::fixed_r::Block<U1>>>(
                                    ),
                            )
                        });

                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        core::hint::black_box(output_hmac_state);

                        if Pipeline::BOOL {
                            (buffer0, buffer1) = (buffer1, buffer0);
                        }
                    }
                })
                .expect("failed to spawn thread");
        }

        println!(
            "Started {} threads (N={}, R={}, P=1)",
            num_threads,
            1u64 << cf.get(),
            r,
        );

        let mut prev = counter.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            let cur = counter.load(std::sync::atomic::Ordering::Relaxed);
            println!("Thrpt: {} c/s (total: {})", cur - prev, cur);
            prev = cur;
        }
    });
}

fn main() {
    let args = Args::parse();

    let num_threads = args.num_threads;
    #[cfg(feature = "core_affinity")]
    let core_stride = args.core_stride;
    match args.command {
        Command::Info => {
            println!("Target: {}", std::env::consts::ARCH);
            println!("Features:");
            scrypt_opt::features::iterate(|f| {
                println!(
                    "{}: compile-time: {}, runtime: {}",
                    f.name(),
                    f.required(),
                    f.check()
                );
            });
        }
        Command::Search {
            target,
            file,
            progress,
        } => {
            let hash =
                password_hash::PasswordHashString::parse(&target, password_hash::Encoding::B64)
                    .expect("invalid hash");

            const ALGORITHM: Ident<'static> = Ident::new_unwrap("scrypt");

            assert_eq!(hash.algorithm(), ALGORITHM, "algorithm must be scrypt");
            let params = hash.params();

            let ln = params.get("ln").expect("ln param must be present");
            let r = params.get("r").expect("r param must be present");
            let p = params.get("p").expect("p param must be present");

            let ln = ln
                .decimal()
                .expect("ln must be a number")
                .try_into()
                .expect("ln must be within u8 range");
            let r = r.decimal().expect("r must be a number");
            let p = p.decimal().expect("p must be a number");

            let cf = NonZeroU8::new(ln).expect("ln must be positive");
            let r = NonZeroU32::new(r).expect("r must be positive");
            let p = NonZeroU32::new(p).expect("p must be positive");

            let needle = hash.hash().expect("hash output must be present");

            let salt = hash.salt().expect("salt must be present");

            let mut salt_bytes = vec![0; salt.len()];
            let salt_bytes = salt
                .decode_b64(&mut salt_bytes)
                .expect("failed to decode salt - must be valid b64");

            let mut key_bytes = vec![0; 256];
            key_bytes[..salt_bytes.len()].copy_from_slice(&salt_bytes);

            let (tx, rx) = crossbeam_channel::bounded(num_threads.get() as usize * 4);

            std::thread::spawn(move || {
                fn fill_worker<R: Read>(
                    reader: &mut BufReader<R>,
                    tx: &crossbeam_channel::Sender<Key>,
                ) {
                    let mut buf = String::with_capacity(256);
                    loop {
                        buf.clear();
                        let mut key = Key(CachePadded::new([0; 256]));

                        let read_len = reader.read_line(&mut buf).unwrap();

                        if read_len == 0 {
                            return;
                        }
                        let key_bytes = buf.trim();
                        if key_bytes.is_empty() {
                            continue;
                        }

                        let Ok(buf_len_byte) = key_bytes.len().try_into() else {
                            eprintln!("invalid key: {}", key_bytes);
                            continue;
                        };

                        key.0[0] = buf_len_byte;
                        key.0[1..][..key_bytes.len()].copy_from_slice(key_bytes.as_bytes());
                        tx.send(key).unwrap();
                    }
                }

                match file.as_str() {
                    "-" => fill_worker(&mut BufReader::new(std::io::stdin().lock()), &tx),
                    file => {
                        fill_worker(&mut BufReader::new(std::fs::File::open(file).unwrap()), &tx)
                    }
                }
            });

            let iterations = Arc::new(AtomicU64::new(0));

            if progress {
                let iterations_clone = iterations.clone();
                std::thread::spawn(move || {
                    let mut prev = iterations_clone.load(std::sync::atomic::Ordering::Relaxed);
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        let cur = iterations_clone.load(std::sync::atomic::Ordering::Relaxed);
                        println!("{} c/s (total: {})", cur - prev, cur);
                        prev = cur;
                    }
                });
            }

            let result = search(
                &iterations,
                &rx,
                &needle.as_bytes(),
                &salt_bytes,
                cf,
                r,
                p,
                num_threads,
                #[cfg(feature = "core_affinity")]
                core_stride,
            );

            if let Some(result) = result {
                println!(
                    "{}:{} ({} cands, {:.2} c/s)",
                    target,
                    String::from_utf8_lossy(&result.key),
                    iterations.load(std::sync::atomic::Ordering::Relaxed) - 1,
                    (iterations.load(std::sync::atomic::Ordering::Relaxed) - 1) as f64
                        / result.elapsed.as_secs_f64()
                );
            } else {
                println!("No key found");
                std::process::exit(1);
            }
        }
        Command::Cast { fast } => cast(fast),
        Command::Compute {
            key,
            salt,
            cf,
            r,
            p,
            output_len,
            output_raw,
        } => {
            assert!(
                key.is_some() || salt.is_some(),
                "at least one of key or salt is required"
            );

            let mut key = key.map(|s| s.into_bytes().into_boxed_slice());
            let mut salt = salt.map(|s| s.into_bytes().into_boxed_slice());

            let mut stdout = std::io::stdout();

            if key.is_none() || salt.is_none() {
                let data = slurp_stdin();

                if key.is_some() {
                    salt = Some(data);
                } else {
                    key = Some(data);
                }
            }

            let (key, salt) = (key.unwrap(), salt.unwrap());

            let mut output = vec![0; output_len].into_boxed_slice();
            scrypt_opt::compat::scrypt(
                &key,
                &salt,
                cf,
                r.try_into().expect("invalid r value"),
                p.try_into().expect("invalid p value"),
                &mut output,
            );

            if output_raw {
                stdout.write_all(&output).unwrap();
            } else {
                let encoder = base64::engine::general_purpose::STANDARD_NO_PAD;
                write!(stdout, "$scrypt$ln={cf},r={r},p={p}$").unwrap();

                {
                    let mut write = EncoderWriter::new(&mut stdout, &encoder);
                    write.write_all(&salt).unwrap();
                }
                stdout.write_all(b"$").unwrap();
                let mut write = EncoderWriter::new(&mut stdout, &encoder);
                write.write_all(&output).unwrap();
                write.finish().unwrap().write_all(b"\n").unwrap();
            }
            stdout.flush().unwrap();
        }
        Command::Throughput { cf, r, no_pipeline } => match_r!(r.get(), R, {
            if no_pipeline {
                throughput::<B0, R>(
                    num_threads,
                    cf,
                    #[cfg(feature = "core_affinity")]
                    core_stride,
                )
            } else {
                throughput::<B1, R>(
                    num_threads,
                    cf,
                    #[cfg(feature = "core_affinity")]
                    core_stride,
                )
            }
        })
        .unwrap_or_else(|| {
            if no_pipeline {
                throughput_dyn::<B0>(
                    num_threads,
                    cf,
                    r,
                    #[cfg(feature = "core_affinity")]
                    core_stride,
                )
            } else {
                throughput_dyn::<B1>(
                    num_threads,
                    cf,
                    r,
                    #[cfg(feature = "core_affinity")]
                    core_stride,
                )
            }
        }),
        Command::Pow {
            op,
            cf,
            r,
            p,
            nonce_len,
            output_len,
            salt,
            offset,
            target,
            mask,
            quiet,
        } => {
            assert!(target.len() <= 16, "target must be less than 8 bytes");

            let mut target_u64 = 0u64;
            let mut target_mask = 0u64;

            for nibble in target.as_bytes().iter() {
                let addend = match nibble {
                    b'0'..=b'9' => nibble - b'0',
                    b'A'..=b'F' => nibble - b'A' + 10,
                    b'a'..=b'f' => nibble - b'a' + 10,
                    _ => panic!("invalid nibble: {}", nibble),
                } as u64;

                target_u64 <<= 4;
                target_u64 |= addend;
                target_mask <<= 4;
                target_mask |= 15;
            }
            if let Some(mask) = mask {
                target_mask = 0;
                for nibble in mask.as_bytes().iter() {
                    let addend = match nibble {
                        b'0'..=b'9' => nibble - b'0',
                        b'A'..=b'F' => nibble - b'A' + 10,
                        b'a'..=b'f' => nibble - b'a' + 10,
                        _ => panic!("invalid nibble: {}", nibble),
                    } as u64;
                    target_mask <<= 4;
                    target_mask |= addend;
                }
            }

            let estimated_cs = match op.as_str() {
                "EQ" | "eq" => 2u64.pow(target_mask.count_ones()),
                "GT" | "gt" => {
                    assert_ne!(
                        target_u64, 0,
                        "target must be non-zero for strict greater than"
                    );
                    target_mask.div_ceil(target_mask - target_u64)
                }
                "LT" | "lt" => {
                    assert_ne!(
                        target_u64, 0,
                        "target must be non-zero for strict less than"
                    );
                    target_mask.div_ceil(target_u64)
                }
                "LE" | "le" => target_mask.div_ceil(target_u64 + 1),
                "GE" | "ge" => target_mask.div_ceil((target_mask - target_u64) + 1),
                _ => panic!("invalid op: {}, expected one of: EQ/GT/LT/LE/GE", op),
            };

            target_u64 <<= (16 - target.len()) * 4;
            target_mask <<= (16 - target.len()) * 4;

            let byte_offset = offset / 2;

            let output_len = output_len
                .unwrap_or_else(|| byte_offset.checked_next_multiple_of(8).unwrap_or(8).max(8));

            assert_eq!(
                target_u64 & target_mask,
                target_u64,
                "target must be a subset of the mask (target: {:x}, mask: {:x}, diff: {:x})",
                target_u64,
                target_mask,
                target_u64 & (!target_mask)
            );

            let target_mask = NonZeroU64::new(target_mask).expect("target mask must be non-zero");

            let config = GeneralPurposeConfig::new()
                .with_decode_padding_mode(DecodePaddingMode::Indifferent);
            let salt_decoded = GeneralPurpose::new(&base64::alphabet::URL_SAFE, config)
                .decode(&salt)
                .or_else(|_| GeneralPurpose::new(&base64::alphabet::STANDARD, config).decode(salt))
                .expect("invalid salt, should be base64 encoded");

            if !quiet {
                eprintln!(
                    "spawning {} threads for an estimated iteration count of {}",
                    num_threads, estimated_cs
                );
            }
            eprintln!("Nonce\tResult\tN\tR\tEstimatedCands\tRealCands\tLuck%\tCPS");
            let output = match_op!(op.as_str(), OP, {
                pow::<OP>(
                    &salt_decoded,
                    cf,
                    r,
                    p,
                    target_mask,
                    target_u64,
                    num_threads,
                    byte_offset,
                    output_len,
                    nonce_len,
                    #[cfg(feature = "core_affinity")]
                    core_stride,
                )
            })
            .expect("no solution found");

            let mut stdout = std::io::stdout();
            let mut output_nonce = [0u8; Pbkdf2HmacSha256State::MAX_SHORT_PASSWORD_LEN];
            output_nonce[..8].copy_from_slice(&output.nonce.to_le_bytes());
            if quiet {
                for i in 0..nonce_len {
                    write!(stdout, "{:02x}", output_nonce[i]).unwrap();
                }
                write!(stdout, "\t").unwrap();
                for word in output.output {
                    write!(stdout, "{:02x}", word).unwrap();
                }
                write!(stdout, "\n").unwrap();
                stdout.flush().unwrap();
            } else {
                for i in 0..nonce_len {
                    write!(stdout, "{:02x}", output_nonce[i]).unwrap();
                }
                write!(stdout, "\t").unwrap();
                for word in output.output {
                    write!(stdout, "{:02x}", word).unwrap();
                }
                let real_cps = output.actual_iterations as f64 / output.elapsed.as_secs_f64();
                writeln!(
                    stdout,
                    "\t{}\t{}\t{}\t{}\t{:.2}\t{:.1}",
                    1u32 << cf.get(),
                    r,
                    estimated_cs,
                    output.actual_iterations,
                    pgeom_inv(output.actual_iterations, (estimated_cs as f64).recip()) * 100.0,
                    real_cps,
                )
                .unwrap();
                stdout.flush().unwrap();
            }
        }
    }
}
