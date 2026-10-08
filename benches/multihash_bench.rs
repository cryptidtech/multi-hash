// SPDX-License-Identifier: Apache-2.0
//! Performance benchmarks for multi-hash

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use multi_codec::Codec;
use multi_hash::{Builder, Multihash};
use multi_trait::TryDecodeFrom;
use std::hint::black_box;

/// build a multihash of `data` with `codec`, streaming the data
fn hash_bytes(codec: Codec, data: &[u8]) -> Multihash {
    let mut builder = Builder::new(codec).unwrap();
    builder.update(data);
    if let Some(output_len) = xof_output_len(codec) {
        builder.output_len(output_len);
    }
    builder.try_build().unwrap()
}

/// the output length the computation bench requests for an XOF codec
///
/// Fixed-output codecs ignore an output length, so the check applies
/// only to the XOF arms, `Blake3`, `Shake128`, and `Shake256`.
const fn xof_output_len(codec: Codec) -> Option<usize> {
    match codec {
        Codec::Blake3 | Codec::Shake128 => Some(32),
        Codec::Shake256 => Some(64),
        _ => None,
    }
}

/// Benchmark hash computation for various algorithms
fn bench_hash_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_computation");
    let data = black_box(b"benchmark data for hashing");

    let algorithms = vec![
        ("Blake3", Codec::Blake3),
        ("SHA2-256", Codec::Sha2256),
        ("SHA2-512", Codec::Sha2512),
        ("SHA3-256", Codec::Sha3256),
        ("SHA3-512", Codec::Sha3512),
        ("Shake256", Codec::Shake256),
    ];

    for (name, codec) in algorithms {
        group.bench_with_input(BenchmarkId::new("compute", name), &codec, |b, &codec| {
            b.iter(|| {
                let mut builder = Builder::new(codec).unwrap();
                builder.update(data);
                if let Some(output_len) = xof_output_len(codec) {
                    builder.output_len(output_len);
                }
                builder.try_build()
            });
        });
    }

    group.finish();
}

/// Benchmark encoding multihash to bytes
fn bench_encoding(c: &mut Criterion) {
    let mh = hash_bytes(Codec::Sha2256, b"test data");

    c.bench_function("multihash_to_bytes", |b| {
        b.iter(|| {
            let _bytes: Vec<u8> = black_box(mh.clone()).into();
        });
    });
}

/// Benchmark decoding multihash from bytes
fn bench_decoding(c: &mut Criterion) {
    let mh = hash_bytes(Codec::Sha2256, b"test data");
    let bytes: Vec<u8> = mh.into();

    c.bench_function("multihash_from_bytes", |b| {
        b.iter(|| Multihash::try_from(black_box(bytes.as_ref())));
    });
}

/// Benchmark roundtrip (encode + decode)
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    let data = b"roundtrip benchmark data";

    for &codec in &[Codec::Blake3, Codec::Sha2256, Codec::Sha3256] {
        let name = format!("{codec:?}");
        group.bench_with_input(BenchmarkId::new("full", &name), &codec, |b, &codec| {
            b.iter(|| {
                let mh1 = hash_bytes(codec, data);
                let bytes: Vec<u8> = mh1.into();
                let _mh2 = Multihash::try_from(bytes.as_ref()).unwrap();
            });
        });
    }

    group.finish();
}

/// Benchmark hash computation with varying data sizes
fn bench_data_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_sizes");

    let sizes = vec![16, 256, 1024, 4096];

    for size in sizes {
        let data = vec![0u8; size];
        group.bench_with_input(BenchmarkId::new("sha2-256", size), &data, |b, data| {
            b.iter(|| {
                let mut builder = Builder::new(Codec::Sha2256).unwrap();
                builder.update(black_box(data));
                builder.try_build()
            });
        });
    }

    group.finish();
}

/// Benchmark builder pattern operations
fn bench_builder(c: &mut Criterion) {
    c.bench_function("builder_streaming", |b| {
        b.iter(|| {
            let mut builder = Builder::new(black_box(Codec::Sha2256)).unwrap();
            builder.update(black_box(b"data"));
            builder.try_build()
        });
    });

    let hash = vec![0u8; 32];
    c.bench_function("builder_with_hash", |b| {
        b.iter(|| {
            Builder::new(black_box(Codec::Sha2256))
                .unwrap()
                .with_hash(black_box(hash.clone()))
                .try_build()
        });
    });
}

/// Benchmark `TryDecodeFrom` with varying encoded sizes
fn bench_decode_from(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_from");

    let test_cases = vec![
        ("small", Codec::Md5),      // 16 byte output
        ("medium", Codec::Sha2256), // 32 byte output
        ("large", Codec::Sha2512),  // 64 byte output
    ];

    for (name, codec) in test_cases {
        let mh = hash_bytes(codec, b"test");
        let bytes: Vec<u8> = mh.into();

        group.bench_with_input(BenchmarkId::new("decode", name), &bytes, |b, bytes| {
            b.iter(|| Multihash::try_decode_from(black_box(bytes.as_ref())));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_computation,
    bench_encoding,
    bench_decoding,
    bench_roundtrip,
    bench_data_sizes,
    bench_builder,
    bench_decode_from
);

criterion_main!(benches);
