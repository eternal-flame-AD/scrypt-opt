# scrypt-opt

A pure-rust, permissively licensed, optimized scrypt implementation for moderate to high difficulty cases with AVX2 and AVX-512 intrinsics core and a portable-simd core.

## System Requirements

- Rust 1.85+ for general/AVX2 support, Rust 1.89+ for AVX512F support, nightly for portable-simd support
- AVX2 is good, AVX512F is great (hand tuned, about 10% extra throughput), but at least a system with **256-bit SIMD** support with the "portable-simd" feature

## Building Instructions

General/AVX2 support does not need any special options. `-Ctarget-feature=+avx2` can squeeze ~3% more throughput by eliding the runtime dispatch.

AVX-512 support requires a 1.89+ compiler and an explicit`-Ctarget-feature=+avx512f`, `-Ctarget-feature=+avx512vl` or an applicable `-Ctarget-cpu` flag.

Portable-simd support requires a nightly compiler and `--features portable-simd` and an applicable `-Ctarget-cpu` flag.

## Applications

- Flexible CPU-based Mining/Proof of Work (PoW) Infrastructure with intuitive pluggable API
- Password Cracking
- System Benchmarking

This is _NOT_ audited cryptography! Don't use it for password hashing, etc.

## Limitations

- `R` must be a compile time constant or monomorphized, the demo binary has code for R=1..=32 and R=64.
- For mining or cases with low difficulty you might want to bring your own multi-buffer PBKDF core, the built in `Pbkdf2HmacSha256State` is designed for moderate to high difficulty cases where it is not called a lot. There are raw buffer APIs that allow you to do it easily. For really really low difficulty where the problem becomes more about data locality than software pipelining this program is may not be optimal, please compare with a full multi-buffer implementation.

## Demo Binary

Things to try out:

Algorithm Self Test (CAST):

```sh
> scrypt-opt cast
```

Compute a single key (uses pipelining if P>1)

```sh
echo -n "password" | scrypt-opt compute -s NaCl --cf 10 -r 8 -p 16
/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIurzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA== 
```

Solve a 💥PoW! Bot Deterrent PoW:

```sh
> scrypt-opt --num-threads 16 pow --target 0002 --salt KTlmPG9GFcM= --cf 14 --r 8
spawning 16 threads for an estimated iteration count of 10922
Nonce   Result  N       R       EstimatedCands  RealCands       Luck%   RealCPS
cf40000000000000        08402d18d2ba3be9ee4b620f8a840000        16384   8       10922    16975   21.13   1310.7
```

Spin loop and print throughput:

```sh
> scrypt-opt --num-threads 16 throughput --cf 14 --r 8
```

## API Walkthrough

The high level idea of scrypt is $P$ _RoMix_ operations, each involves $N$ blocks of $128R$ byte blocks. The initialization phase "scatters" the a large HMAC-SHA-256 to $N$ blocks. The finalization phase "gathers" another HMAC-SHA-256 from the current blocks as new salt. This program split it into two halves, let's call them $RoMix_{Front}$ and $RoMix_{Back}$.

Each hash is pipelined into 4 steps: 

1. "Scatter" the password/nonce into $PN$ blocks.
2. For each of the $P$ chunks: Run $RoMix_{Front}$ then $RoMix_{Back}$.
3. "Gather" all the blocks into a single HMAC-SHA-256 output.

These APIs facilitate these:

- `Block<R>` represents a 512-bit block in u32 form, it can be transmuted to/from a `BlockU8<R>` which is a 64-byte block in u8 form.
- `BufferSet::new`, `BufferSet::new_boxed`,  `BufferSet::new_maybe_huge_slice` create a new buffer set using an existing buffer or a new heap or huge page backed buffer. `BufferSet::minimum_blocks` returns the minimum number of blocks required to be allocated for a given Cost Factor (log2(N)).
- `BufferSet::scrypt_ro_mix` performs the $RoMix_{Front}$ and then $RoMix_{Back}$ operation serially.
- `BufferSet::pipeline_start` performs the $RoMix_{Front}$ operation.
- `BufferSet::pipeline_drain` performs the $RoMix_{Back}$ operation.
- `BufferSet::scrypt_ro_mix_interleaved` takes an auxiliary buffer set and performs the $RoMix_{Back}$ operation on _Self_ and $RoMix_{Front}$ on the auxiliary buffer set.
- `BufferSet::pipeline` is a convenience method that takes an iterator implementing `PipelineContext` trait and performs the pipeline by calling into `PipelineContext::begin` and `PipelineContext::drain` at appropriate times. `PipelineContext` is already implemented for `(&'a Align64<Block<R>>, &'b mut Align64<Block<R>>)`, which simplifies the pipelining for computing hashes with a large $P$ (see [examples/large_p.rs](examples/large_p.rs)).
- `Pbkdf2HmacSha256State` stores the internal state of the HMAC-SHA-256 operation (512-bit, copyable)
- `Pbkdf2HmacSha256State::new` and `Pbkdf2HmacSha256State::new_short` create a new state from a password.
- `Pbkdf2HmacSha256State::emit_gather` and `Pbkdf2HmacSha256State::emit_scatter` either take a salt from block buffers and emit to an arbitrary mutable slice or take an arbitrary salt and emit to block buffers.
- `BufferSet::input_buffer` and `BufferSet::input_buffer_mut` return references to the input block buffer.
- `BufferSet::raw_salt_output` returns a reference to the last block buffer (the input of the final HMAC-SHA-256 operation), which is useful for concatenation for $P>1$ cases.
- `BufferSet::set_input` and `BufferSet::extract_output` are mnemonic wrappers for `Pbkdf2HmacSha256State::emit_scatter` and `Pbkdf2HmacSha256State::emit_gather` when $P=1$.


The independent work can be sourced from the next block when $P>1$ (see [examples/large_p.rs](examples/large_p.rs)) or from another task (for ex. the next PoW nonce or password candidate) when P=1 (this is called "interleaving").

## Benchmarks

RS 4000=Root Server by Netcup, ~$30/month, backed by EPYC 9634. Epsv6=Azure, backed by Cobalt 100 (aarch64). All hardware come in stock configuration. All tested programs except Android/WASM builds are linked with glibc.

Note: On the Ryzen 9 7950X, since the amount of core per memory channel is high and each core is extremely high frequency, using only 16 threads and keeping them at turbo frequency is better than using 32 threads for scrypt-opt to keep the thermal throttling in check.

Litecoin equiv. hash rate (>100kH/s) numbers may be bottlenecked by the HMAC-SHA256 phase which is as of now only lightly optimized, but you can plug in your own batch HMAC-SHA-256 implementation to bypass this bottleneck.

Core observations:

- Latency of scrypt-opt is comparable to a native JtR build, pipelined throughput is ~1.5-2x faster than single-shot version on machines with high memory bandwidth.
- On memory bandwidth limited systems, pipelined scrypt-opt can extract the full throughput at much lower thread count (and power consumption) than single-shot version.

Sample parameters for reference recommended/hardcoded by various sources:

- Litecoin: N=1024 (10), R=1, P=1.
- Cisco "Type 9" KDF: N=16384 (14), R=1, P=1.
- RustCrypto KDF: N=131072 (17), R=8, P=1.
- 💥PoW! Bot Deterrent: N=16384 (14), R=8, P=1, DF=5 is recommended, DF=7 is for desktop only use. For pps shift right by DF.

Differences are computed against a native JtR build with AVX512VL enabled.

Memory traffic is approximated as $2 \times N \times 128 \times R$ bytes/s, effective utilization is computed by dividing by STREAM benchmark results. >100% results are possible for cache-bound workloads.

| Host          | Threads | Program     | N (CF)      | R   | Thrpt. (c/s)   | Eff. B/W Utilization (%) |
| ------------- | ------- | ----------- | ----------- | --- | -------------- | ------------------------ |
| EPYC 9334     | 64      | scrypt-opt  | 1024  (10)  | 1   | 750894         | 157.47/195.91 (80.37%)   |
| EPYC 9334     | 64      | scrypt-opt  | 4096  (12)  | 8   | 20964          |                          |
| EPYC 9334     | 64      | scrypt-opt  | 8192  (13)  | 8   | 9458           |                          |
| EPYC 9334     | 64      | scrypt-opt  | 16384 (14)  | 8   | 4501 (+60.69%) | 151.03/195.91 (77.09%)   |
| EPYC 9334     | 64      | john --test | 16384 (14)  | 8   | 2801           |                          |
| EPYC 9334     | 64      | scrypt-opt  | 32768 (15)  | 8   | 2202           |                          |
| EPYC 9334     | 64      | scrypt-opt  | 16384 (14)  | 16  | 2462           |                          |
| EPYC 9334     | 64      | scrypt-opt  | 65536 (16)  | 8   | 1084           |                          |
| EPYC 9334     | 64      | scrypt-opt  | 131072 (17) | 8   | 536  (+53.14%) | 143.88/195.91 (73.44%)   |
| EPYC 9334     | 64      | john --mask | 131072 (17) | 8   | 350            |                          |
| Ryzen 9 7950X | *32*    | scrypt-opt  | 1024  (10)  | 1   | 439933         | 92.26/63.34 (145.66%)    |
| Ryzen 9 7950X | 16      | scrypt-opt  | 4096  (12)  | 8   | 6850           |                          |
| Ryzen 9 7950X | 16      | scrypt-opt  | 8192  (13)  | 8   | 2878           |                          |
| Ryzen 9 7950X | 16      | scrypt-opt  | 16384 (14)  | 8   | 1320 (+10.46%) | 44.29/63.34 (69.93%)     |
| Ryzen 9 7950X | 32      | john --mask | 16384 (14)  | 8   | 1195           |                          |
| Ryzen 9 7950X | *32*    | scrypt-opt  | 16384 (14)  | 1   | 16226          |                          |
| Ryzen 9 7950X | 16      | scrypt-opt  | 32768 (15)  | 8   | 635  (+9.29%)  | 42.61/63.34 (67.27%)     |
| Ryzen 9 7950X | 32      | john --mask | 32768 (15)  | 8   | 581            |                          |
| Ryzen 9 7950X | 16      | scrypt-opt  | 16384 (14)  | 16  | 657  (+9.50%)  | 44.09/63.34 (69.61%)     |
| Ryzen 9 7950X | 32      | john --mask | 16384 (14)  | 16  | 600            |                          |
| Ryzen 9 7950X | 16      | scrypt-opt  | 131072 (17) | 8   | 150  (+8.70%)  | 40.27/63.34 (63.57%)     |
| Ryzen 9 7950X | 32      | john --mask | 131072 (17) | 8   | 138            |                          |
| i7-11370H     | 8       | scrypt-opt  | 1024  (10)  | 1   | 78920          | 20.69/37.59 (55.05%)     |
| i7-11370H     | 8       | scrypt-opt  | 16384 (14)  | 8   | 407            | 35.55/37.59 (94.58%)     |
| RS 4000 G11   | 12      | scrypt-opt  | 16384 (14)  | 8   | 740            |                          |
| RS 4000 G11   | 12      | scrypt-opt  | 16384 (14)  | 16  | 414            |                          |
| RS 4000 G11   | 12      | scrypt-opt  | 32768 (15)  | 8   | 355            |                          |

These machines only have 128-bit SIMD and tests were performed using a plain old scalar/auto-vectorized core.

| Host             | Threads | Program    | N (CF)     | R   | Throughput (c/s) |
| ---------------- | ------- | ---------- | ---------- | --- | ---------------- |
| Azure Cobalt 100 | 96      | scrypt-opt | 1024  (10) | 1   | 684656           |
| Azure Cobalt 100 | 96      | scrypt-opt | 16384 (14) | 8   | 4731             |
| Azure Cobalt 100 | 96      | scrypt-opt | 16384 (14) | 16  | 2399             |
| Azure Cobalt 100 | 96      | scrypt-opt | 16384 (17) | 8   | 586              |

### Browser WASM Comparison

WASM tests are performed on Chromium 138.0.7204.157, worker message passing overhead is excluded. Mobile devices are plugged in. MEW=MyEtherWallet. 

| Host          | Threads | Program                    | N (CF)     | R   | Throughput (c/s) |
| ------------- | ------- | -------------------------- | ---------- | --- | ---------------- |
| Ryzen 9 7950X | 32      | MEW/scrypt-wasm (+simd128) | 16384 (14) | 8   | 717              |
| Ryzen 9 7950X | 16      | MEW/scrypt-wasm (+simd128) | 16384 (14) | 8   | 631              |
| Ryzen 9 7950X | 1       | MEW/scrypt-wasm (+simd128) | 16384 (14) | 8   | 49               |
| Ryzen 9 7950X | 32      | MEW/scrypt-wasm            | 16384 (14) | 8   | 425              |
| Ryzen 9 7950X | 16      | MEW/scrypt-wasm            | 16384 (14) | 8   | 394              |
| Ryzen 9 7950X | 1       | MEW/scrypt-wasm            | 16384 (14) | 8   | 29               |
| Pixel 9 Pro   | 8       | MEW/scrypt-wasm (+simd128) | 16384 (14) | 8   | 140              |
| Pixel 9 Pro   | 1       | MEW/scrypt-wasm (+simd128) | 16384 (14) | 8   | 39               |
| Pixel 9 Pro   | 8       | MEW/scrypt-wasm            | 16384 (14) | 8   | 44               |
| Pixel 9 Pro   | 1       | MEW/scrypt-wasm            | 16384 (14) | 8   | 16               |

## Usage Example

See [examples](examples) for usage examples.

## Strategy Overview

Traditional approaches focus on software prefetching, but scrypt is purposefully designed to be serialized in both the Salsa20 core and $V_j$ access step. The address is only known at the last moment, so software prefetching cannot really significantly soften that latency. 

Instead, the optimal use of hardware is to perform one $RoMix_{Back}$ and one independent $RoMix_{Front}$ at once per thread. 

We can observe that $RoMix_{Front}$ and $RoMix_{Back}$ have identical arithmetic and increase power efficiency by zipping each $BlockMix$ operation from the two halves together and widening the Salsa20 core to dual-buffer. On platforms with advanced SIMD (AVX512) we can handle the permutation and extraction with high efficiency.
 
This also ensures that when the inevitable DRAM latency hits in the $V_j$ access step, the processor has more work to do per block and if we can issue more useful work (even if stolen from the other half) in the latency bubble then our overall efficiency in that bubble is higher.

The biggest limitation of this is we are working against the limitation of the latency bubble, which is usually counted in $\mu$-ops. If we can increase the amount of useful work with a sub-linear increase in $\mu$-ops, then we can achieve higher throughput. The trick is to use the other 128-bit half to smuggle another half of the work from $RoMix_{Front}$ without significantly increasing total $\mu$-ops/round. This way when the processor stalls at +32 bytes w.r.t. to the $RoMix_{Back}$ operation we have completed 64 bytes overall. However on machines with 128-bit SIMD, the compiler will be forced to emit 2x+ amount of instructions to do the same thing, which means the processor will stall at ~+16 bytes instead, that is not helpful.

On the data layout side, we can also optimize this $X \leftarrow BlockMix(X \oplus V_j)$ step by ping-ponging between two buffers (and optionally keeping one of them in registers to babysit MLP to really focus on the hard part), this makes sure writes to the buffer will be immediately read back one $BlockMix$ round later and keep them naturally in cache without requiring high latency nontemporal instructions.

Annotated Zen 4 build:

```asm
vpmovsxbd zmm17, xmmword ptr [rip + .LCPI88_8]   ; gather data, perform final round shuffle and permute into memory layout
vpmovsxbd zmm18, xmmword ptr [rip + .LCPI88_9]

; ...

vpxord ymm2, ymm19, ymm2
vpaddd ymm19, ymm2, ymm1
vinserti64x4 zmm1, zmm2, ymm1, 1      ; recombine results from two blocks
vprold ymm19, ymm19, 18
vpxord ymm16, ymm19, ymm16            ; last round of previous 2-buffer ARX, dual buffer version of the ARX+vpshufd stuff
vinserti64x4 zmm3, zmm16, ymm3, 1
vmovdqa64 zmm2, zmm3
vpermt2d zmm3, zmm18, zmm1            ; combine the final Salsa20 shuffle and pivot back to memory layout (A, B, D, C)
vpermt2d zmm2, zmm17, zmm1
vpaddd zmm1, zmm2, zmm8               ; feedbacks
vpaddd zmm0, zmm3, zmm0
vmovdqa64 zmmword ptr [rdx + r9 - 1728], zmm1
vmovdqa64 zmmword ptr [rax + 896], zmm0
vpxord zmm8, zmm1, zmmword ptr [rdx + r9 - 2560]
vpternlogd zmm9, zmm0, zmmword ptr [rdi + r10 + 64], 150
vextracti64x4 ymm0, zmm8, 1           ; Extract DC
vextracti64x4 ymm1, zmm9, 1           ; Extract AB
vinserti128 ymm2, ymm8, xmm9, 1       ; Pack A
vinserti128 ymm3, ymm0, xmm1, 1       ; Pack B
#APP                                  ; manually enforced instruction order to put C in the highest latency position
vperm2i128 ymm4, ymm8, ymm9, 49       ; select B
vperm2i128 ymm0, ymm0, ymm1, 49       ; select C
#NO_APP
vpaddd ymm1, ymm3, ymm2               ; Next Salsa20/8 rounds
vprold ymm1, ymm1, 7
```

## License

Copyright 2025 [Yumechi](inquiry@yumechi.jp) Licensed under the Apache License, Version 2.0.