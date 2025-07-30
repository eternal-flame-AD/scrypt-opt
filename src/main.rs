use base64::{
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    prelude::*,
    write::EncoderWriter,
};
use clap::Parser;
use generic_array::{
    ArrayLength,
    typenum::{
        B0, B1, Bit, NonZero, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15,
        U16, U17, U18, U19, U20, U21, U22, U23, U24, U25, U26, U27, U28, U29, U30, U31, U32,
    },
};
use scrypt_opt::{
    BufferSet,
    memory::Align64,
    pbkdf2_1::Pbkdf2HmacSha256State,
    pipeline::PipelineContext,
    self_test::{
        Case, CaseP1, CastN16R1P1, CastN1024R1P2, CastN1024R8P16, CastN16384R8P1, CastN1048576R8P1,
    },
};

#[cfg(feature = "core_affinity")]
use std::num::NonZeroUsize;

use std::ops::DerefMut;
use std::{
    io::{Read, Write},
    marker::PhantomData,
    num::{NonZeroU8, NonZeroU32, NonZeroU64},
    sync::{
        Mutex,
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
            17 => { type $b = U17; Some($c) },
            18 => { type $b = U18; Some($c) },
            19 => { type $b = U19; Some($c) },
            20 => { type $b = U20; Some($c) },
            21 => { type $b = U21; Some($c) },
            22 => { type $b = U22; Some($c) },
            23 => { type $b = U23; Some($c) },
            24 => { type $b = U24; Some($c) },
            25 => { type $b = U25; Some($c) },
            26 => { type $b = U26; Some($c) },
            27 => { type $b = U27; Some($c) },
            28 => { type $b = U28; Some($c) },
            29 => { type $b = U29; Some($c) },
            30 => { type $b = U30; Some($c) },
            31 => { type $b = U31; Some($c) },
            32 => { type $b = U32; Some($c) },
            _ => None,
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
        r: usize,
        #[arg(short, long)]
        no_pipeline: bool,
    },
    Pow {
        #[arg(short, long, default_value = "14", help = "N value (log2)")]
        cf: NonZeroU8,
        #[arg(short, long, default_value = "8", help = "R value")]
        r: usize,
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

fn pow<R: ArrayLength + NonZero + Send + Sync>(
    salt: Box<[u8]>,
    cf: NonZeroU8,
    mask: NonZeroU64,
    target: u64,
    num_threads: NonZeroU32,
    offset: usize,
    output: Box<[u8]>,
    nonce_len: usize,
    #[cfg(feature = "core_affinity")] core_stride: NonZeroUsize,
) -> Option<PowResult> {
    assert!(
        nonce_len <= Pbkdf2HmacSha256State::MAX_SHORT_PASSWORD_LEN,
        "nonce length must be less than or equal to {} for now",
        Pbkdf2HmacSha256State::MAX_SHORT_PASSWORD_LEN
    );

    const NOT_A_SOLUTION: u64 = u64::MAX;

    let required_blocks = scrypt_opt::minimum_blocks(cf);

    let search_max = if nonce_len == 8 {
        u64::MAX - 1
    } else {
        (1 << (nonce_len * 8)) - 1
    };
    let output_len = output.len();

    struct State<R: ArrayLength + NonZero + Send + Sync> {
        salt: Box<[u8]>,
        mask: NonZeroU64,
        target: u64,
        offset: usize,
        stop_signal: AtomicBool,
        retired_count: AtomicU64,
        solved_mutex: Mutex<(Box<[u8]>, u64)>,
        _marker: PhantomData<R>,
    }
    let mut full_slice = MultiThreadedHugeSlice::<Align64<scrypt_opt::Block<R>>>::new(
        required_blocks * 2,
        num_threads,
    );
    let state = State::<R> {
        salt,
        mask,
        target,
        offset,
        stop_signal: AtomicBool::new(false),
        retired_count: AtomicU64::new(0),
        solved_mutex: Mutex::new((output, NOT_A_SOLUTION)),
        _marker: PhantomData,
    };

    let start_time = std::time::Instant::now();
    std::thread::scope(|s| {
        #[cfg(feature = "core_affinity")]
        let mut core_assigner = CoreAffinityAssigner::new(core_stride);

        for (thread_idx, mut local_buffer) in full_slice.get().into_iter().enumerate() {
            #[cfg(feature = "core_affinity")]
            let core = core_assigner.next();

            let state = &state;

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

                    // pad front and back 8 bytes to ensure all possible reads are aligned
                    // the lowest possible output length is 0, which gives an offset of -8, which needs to be in bounds
                    let mut local_output = vec![0u8; output_len].into_boxed_slice();

                    let (buffer0_inner, buffer1_inner) =
                        local_buffer.as_mut().split_at_mut(required_blocks);

                    let mut buffers0 = scrypt_opt::BufferSet::<
                        &mut [Align64<scrypt_opt::Block<R>>],
                        R,
                    >::new(buffer0_inner);

                    let mut buffers1 = scrypt_opt::BufferSet::<
                        &mut [Align64<scrypt_opt::Block<R>>],
                        R,
                    >::new(buffer1_inner);

                    struct NonceState<R: ArrayLength + NonZero + Send + Sync> {
                        nonce: u64,
                        hmac_state: Pbkdf2HmacSha256State,
                        _marker: PhantomData<R>,
                    }

                    impl<'a, 'b, R: ArrayLength + NonZero + Send + Sync>
                        PipelineContext<
                            (&'a State<R>, &'b mut [u8]),
                            &mut [Align64<scrypt_opt::Block<R>>],
                            R,
                            u64,
                        > for NonceState<R>
                    {
                        #[inline(always)]
                        fn begin(
                            &mut self,
                            (pipeline_state, _): &mut (&'a State<R>, &'b mut [u8]),
                            buffer_set: &mut BufferSet<&mut [Align64<scrypt_opt::Block<R>>], R>,
                        ) {
                            buffer_set.set_input(&self.hmac_state, &pipeline_state.salt);
                        }

                        #[inline(always)]
                        fn drain(
                            self,
                            (pipeline_state, local_output): &mut (&'a State<R>, &'b mut [u8]),
                            buffer_set: &mut scrypt_opt::BufferSet<
                                &mut [Align64<scrypt_opt::Block<R>>],
                                R,
                            >,
                        ) -> Option<u64> {
                            let mut output = [0u8; 8];
                            self.hmac_state.partial_gather(
                                [buffer_set.raw_salt_output()],
                                pipeline_state.offset,
                                &mut output,
                            );

                            let t = u64::from_be_bytes(output) & pipeline_state.mask.get();

                            pipeline_state
                                .retired_count
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let succeeded = t <= pipeline_state.target;
                            if succeeded {
                                buffer_set.extract_output(&self.hmac_state, local_output);
                                return Some(self.nonce);
                            }

                            None
                        }
                    }

                    let result = buffers0.pipeline(
                        &mut buffers1,
                        ((thread_idx as u64)..=search_max)
                            .step_by(num_threads.get() as usize)
                            .map_while(|i| {
                                if state.stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                                    return None;
                                }

                                Some(NonceState::<R> {
                                    nonce: i,
                                    // SAFETY: i.to_le_bytes() is way less than 1 SHA-256 block, so we can safely unwrap without checking
                                    hmac_state: unsafe {
                                        // we do not need to [..nonce_len] because HMAC(short_key) = HMAC(short_key || 0)
                                        Pbkdf2HmacSha256State::new_short(&i.to_le_bytes())
                                            .unwrap_unchecked()
                                    },
                                    _marker: PhantomData,
                                })
                            }),
                        &mut (&state, &mut local_output),
                    );

                    if let Some(nonce) = result {
                        // if the solution is real we definitely can stop the search
                        // so signal ASAP
                        state
                            .stop_signal
                            .store(true, std::sync::atomic::Ordering::Release);

                        // synchronize and pick our answer if no one else has gotten to this point yet
                        let mut solution = state.solved_mutex.lock().unwrap();
                        if solution.1 == NOT_A_SOLUTION {
                            solution.0.copy_from_slice(&local_output);
                            solution.1 = nonce;
                        }
                    }
                })
                .expect("failed to spawn thread");
        }
    });

    let lock = Mutex::into_inner(state.solved_mutex).expect("some solver panicked");
    let retired_count = state
        .retired_count
        .load(std::sync::atomic::Ordering::Relaxed);

    Some(PowResult {
        nonce: lock.1,
        output: lock.0,
        actual_iterations: retired_count,
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

    case!("16/1/1", { CastN16R1P1::algorithm_self_test() });
    case!("16/1/1 (pipeline)", { CastN16R1P1::pipeline_api_test() });
    case!("1024/1/2", { CastN1024R1P2::algorithm_self_test() });
    case!("1024/8/16", { CastN1024R8P16::algorithm_self_test() });

    if !fast {
        case!("16384/8/1", { CastN16384R8P1::algorithm_self_test() });
        case!("16384/8/1 (pipeline)", {
            CastN16384R8P1::pipeline_api_test()
        });
        case!("1048576/8/1", { CastN1048576R8P1::algorithm_self_test() });
    }

    println!("------ PASSED ALL TESTS ------");
}

fn throughput<Pipeline: Bit, R: ArrayLength + NonZero>(
    num_threads: NonZeroU32,
    cf: NonZeroU8,
    #[cfg(feature = "core_affinity")] core_stride: NonZeroUsize,
) {
    let counter = AtomicU64::new(0);

    let required_blocks = scrypt_opt::minimum_blocks(cf);

    let mut full_slice = MultiThreadedHugeSlice::<Align64<scrypt_opt::Block<R>>>::new(
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

                    let mut buffers0 = scrypt_opt::BufferSet::<
                        &mut [Align64<scrypt_opt::Block<R>>],
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

                    let mut buffers1 = scrypt_opt::BufferSet::<
                        &mut [Align64<scrypt_opt::Block<R>>],
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
                        PipelineContext<&AtomicU64, &mut [Align64<scrypt_opt::Block<R>>], R, ()>
                        for Context
                    {
                        #[inline(always)]
                        fn begin(
                            &mut self,
                            _state: &mut &AtomicU64,
                            buffer_set: &mut scrypt_opt::BufferSet<
                                &mut [Align64<scrypt_opt::Block<R>>],
                                R,
                            >,
                        ) {
                            buffer_set.set_input(&self.hmac_state, KAT_SALT);
                        }

                        #[inline(always)]
                        fn drain(
                            self,
                            counter: &mut &AtomicU64,
                            buffer_set: &mut scrypt_opt::BufferSet<
                                &mut [Align64<scrypt_opt::Block<R>>],
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
            if !scrypt_opt::compat::scrypt(&key, &salt, cf, r, p, &mut output) {
                panic!("invalid/unsupported r value");
            }

            if output_raw {
                stdout.write_all(&output).unwrap();
            } else {
                let encoder = base64::engine::general_purpose::STANDARD_NO_PAD;
                write!(stdout, "$scrypt$ln={cf}$r={r}$p={p}$").unwrap();

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
        Command::Throughput { cf, r, no_pipeline } => match_r!(r, R, {
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
        .expect("invalid/unsupported r value"),
        Command::Pow {
            cf,
            r,
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

            let output = vec![0; output_len].into_boxed_slice();

            let estimated_cs = target_mask.get().div_ceil(target_u64 + 1) / 2;
            if !quiet {
                eprintln!(
                    "spawning {} threads for an estimated iteration count of {}",
                    num_threads, estimated_cs
                );
            }
            eprintln!("Nonce\tResult\tN\tR\tEstimatedCands\tRealCands\tLuck%\tCPS");
            let Some(output) = match_r!(r, R, {
                pow::<R>(
                    salt_decoded.into_boxed_slice(),
                    cf,
                    target_mask,
                    target_u64,
                    num_threads,
                    byte_offset,
                    output,
                    nonce_len,
                    #[cfg(feature = "core_affinity")]
                    core_stride,
                )
            })
            .expect("invalid/unsupported r value") else {
                panic!("no solution found");
            };

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
