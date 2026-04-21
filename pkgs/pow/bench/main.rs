//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the Dash proof-of-work hash.

macro_rules! bench_hash512 {
  ($name:ident, $path:path) => {
    #[divan::bench(args = [32, 80, 128, 512, 1024, 2048])]
    fn $name(bencher: divan::Bencher, n: usize) {
      let input = vec![0u8; n];
      bencher
        .counter(1u32)
        .bench(|| divan::black_box($path(divan::black_box(&input))));
    }
  };
}

macro_rules! bench_algo {
  ($algo:ident) => {
    mod $algo {
      mod scalar {
        bench_hash512!(hash512, dash_pow::$algo::scalar::hash512);
      }
      #[cfg(feature = "simd")]
      mod simd {
        bench_hash512!(hash512, dash_pow::$algo::simd::hash512);
      }
    }
  };
}

bench_algo!(blake);
bench_algo!(bmw);
bench_algo!(cubehash);
bench_algo!(echo);
bench_algo!(groestl);
bench_algo!(jh);
mod keccak {
  mod scalar {
    bench_hash512!(hash512, dash_pow::keccak::scalar::hash512);
  }
  #[cfg(feature = "simd")]
  mod simd {
    bench_hash512!(hash512, dash_pow::keccak::simd::hash512);
  }
}
bench_algo!(luffa);
bench_algo!(shavite);
bench_algo!(simd_hash);
bench_algo!(skein);

mod pow {
  #[divan::bench(args = [32, 80, 128, 512, 1024, 2048])]
  fn hash(bencher: divan::Bencher, n: usize) {
    let input = vec![0u8; n];
    bencher
      .counter(1u32)
      .bench(|| divan::black_box(dash_pow::hash(divan::black_box(&input))));
  }

  #[cfg(feature = "std")]
  #[divan::bench(args = [32, 80, 128, 512, 1024, 2048])]
  fn par(bencher: divan::Bencher, n: usize) {
    let buf = vec![0u8; n];
    let inputs: Vec<&[u8]> = vec![buf.as_slice(); 1000];
    bencher
      .counter(inputs.len() as u32)
      .bench(|| divan::black_box(dash_pow::worker::par_hash(&inputs)));
  }
}

fn main() {
  divan::main();
}
