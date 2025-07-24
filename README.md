# scrypt-opt

A pure-rust, permissively licensed, optimized scrypt implementation for moderate to high difficulty cases with an AVX512VL intrinsics core and a portable-simd core.

## System Requirements

- Rust 1.89+ or nightly
- AVX512F is great (hand tuned), but at least a system with 256-bit SIMD support with the "portable-simd" feature

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

The independent work can be sourced from the next block when $P>1$ (see [examples/large_p.rs](examples/large_p.rs)) or from another task (for ex. the next PoW nonce or password candidate) when P=1 (this is called "interleaving").

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

## Benchmarks

RS 4000=Root Server by Netcup, ~$30/month, backed by EPYC 9634. All hardware come in stock configuration. All tested programs except Android/WASM builds are linked with glibc.

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

Memory bandwidth can be approximated as $2 \times N \times 128 \times R$ bytes/s.

| Host          | Threads | Program                  | N (CF)      | R   | Throughput (c/s) |
| ------------- | ------- | ------------------------ | ----------- | --- | ---------------- |
| EPYC 9334     | 64      | scrypt-opt               | 1024  (10)  | 1   | 726363           |
| EPYC 9334     | 64      | scrypt-opt               | 4096  (12)  | 8   | 20623            |
| EPYC 9334     | 64      | scrypt-opt               | 8192  (13)  | 8   | 9374             |
| EPYC 9334     | 64      | scrypt-opt               | 16384 (14)  | 8   | 4339             |
| EPYC 9334     | 64      | john --test (AVX512VL)   | 16384 (14)  | 8   | 2801             |
| EPYC 9334     | 64      | scrypt-opt               | 32768 (15)  | 8   | 2127             |
| EPYC 9334     | 64      | scrypt-opt               | 16384 (14)  | 16  | 1213             |
| EPYC 9334     | 64      | scrypt-opt               | 65536 (16)  | 8   | 1053             |
| EPYC 9334     | 64      | scrypt-opt (single shot) | 16384 (14)  | 8   | 2853             |
| Ryzen 9 7950X | 16      | scrypt-opt               | 1024  (10)  | 1   | 429985           |
| Ryzen 9 7950X | 32      | scrypt-opt (single shot) | 1024  (10)  | 1   | 238325           |
| Ryzen 9 7950X | 16      | scrypt-opt               | 4096  (12)  | 8   | 6100             |
| Ryzen 9 7950X | 16      | scrypt-opt               | 8192  (13)  | 8   | 2827             |
| Ryzen 9 7950X | 16      | scrypt-opt               | 16384 (14)  | 8   | 1312             |
| Ryzen 9 7950X | 32      | scrypt-opt (single shot) | 16384 (14)  | 8   | 1255             |
| Ryzen 9 7950X | 32      | john --mask (AVX512VL)   | 16384 (14)  | 8   | 1195             |
| Ryzen 9 7950X | *32*    | scrypt-opt               | 16384 (14)  | 1   | 15040            |
| Ryzen 9 7950X | 16      | scrypt-opt               | 32768 (15)  | 8   | 632              |
| Ryzen 9 7950X | 32      | scrypt-opt (single shot) | 32768 (15)  | 8   | 610              |
| Ryzen 9 7950X | 16      | scrypt-opt               | 16384 (14)  | 16  | 652              |
| Ryzen 9 7950X | 32      | scrypt-opt (single shot) | 16384 (14)  | 16  | 654              |
| Ryzen 9 7950X | 16      | scrypt-opt               | 131072 (17) | 8   | 148              |
| Ryzen 9 7950X | 32      | john --mask (AVX512VL)   | 32768 (15)  | 8   | 581              |
| Ryzen 9 7950X | 32      | john --mask (AVX512VL)   | 16384 (14)  | 16  | 600              |
| Ryzen 9 7950X | 32      | john --mask (AVX512VL)   | 131072 (17) | 8   | 56               |
| i7-11370H     | 8       | scrypt-opt               | 1024  (10)  | 1   | 78920            |
| i7-11370H     | 8       | scrypt-opt               | 16384 (14)  | 8   | 407              |
| RS 4000 G11   | 12      | scrypt-opt               | 16384 (14)  | 8   | 740              |
| RS 4000 G11   | 12      | scrypt-opt               | 16384 (14)  | 16  | 414              |
| RS 4000 G11   | 12      | scrypt-opt               | 32768 (15)  | 8   | 355              |


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

Instead, the optimal use of hardware is to perform one $RoMix_{Back}$ and one independent $RoMix_{Front}$ at once per thread. This ensures that when the inevitable DRAM latency hits in the $Vj$ access step, the processor has more work to do per block and thus has to track fewer outstanding memory requests before stalling. We can also increase power efficiency by zipping each $BlockMix$ operation from the two halves together and widening the Salsa20 core to 2 buffers. On platforms with advanced SIMD (AVX512) we can handle the permutation and extraction with high efficiency.

We can also optimize this $X \leftarrow BlockMix(X \oplus V_j)$ step by ping-ponging between two buffers (and optionally keeping one of them in registers to babysit MLP to really focus on the hard part), this makes sure writes to the buffer will be immediately read back one $BlockMix$ round later and keep them naturally in cache without requiring high latency nontemporal instructions.

Annotated Zen 4 build:

```asm
vmovdqa64 zmm1, zmmword ptr [rip + scrypt_opt::salsa20::PIVOT2_AB]        ; permutation constants stay in registers
vmovdqa64 zmm2, zmmword ptr [rip + scrypt_opt::salsa20::PIVOT2_CD]
vmovdqa64 zmm0, zmmword ptr [rip + scrypt_opt::salsa20::SHUFFLE_UNPIVOT2]
; ...
vpxord ymm13, ymm16, ymm13
vpaddd ymm16, ymm13, ymm10
vprold ymm16, ymm16, 18
vpxord ymm9, ymm16, ymm9               ; last round of previous 2-buffer ARX, dual buffer version of the ARX+vpshufd stuff
vinserti32x4 ymm16, ymm9, xmm12, 1     ; recombine results from two blocks
vperm2i128 ymm9, ymm9, ymm12, 49       ; shuffle buffers back to input order
vinserti128 ymm12, ymm10, xmm13, 1
vperm2i128 ymm10, ymm10, ymm13, 49
vpermt2d zmm16, zmm0, zmm12            ; combine the final Salsa20 shuffle and pivot back to row-major
vpermt2d zmm9, zmm0, zmm10
vpaddd zmm13, zmm16, zmm6              ; feedbacks
vpaddd zmm16, zmm9, zmm4
vmovdqa64 zmmword ptr [r11 - 960], zmm13      ; write the result back for the next block
vpxord zmm4, zmm13, zmmword ptr [r11 - 1408]  ; XOR for X ← BlockMix(X xor Vj) step, X is already register resident
vpternlogd zmm14, zmm16, zmmword ptr [r12 + r10 + 64], 150 ; 3-input AND-OR-XOR for RoMix_Front part
vmovdqa64 zmm9, zmm4                          ; save the result for the next block feedback
vpermt2d zmm9, zmm2, zmm14                    ; Distribute CD to column-major for the next block
vmovdqa64 zmm6, zmm4                          ; save the result for the next block feedback
vpermt2d zmm6, zmm1, zmm14                    ; Distribute AB to column-major for the next block
vextracti64x4 ymm10, zmm9, 1                  ; split C and D for the next block
vextracti64x4 ymm18, zmm6, 1                  ; split A and B for the next block
vpaddd ymm12, ymm10, ymm6                     ; start 8 ARX rounds
vprold ymm12, ymm12, 7
vpxord ymm12, ymm12, ymm18
```

## License

Copyright 2025 [Yumechi](inquiry@yumechi.jp) Licensed under the Apache License, Version 2.0.