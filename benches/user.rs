/*
 * Copyright 2020 Two Sigma Open Source, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nix::unistd::{Uid, User};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("User::from_uid", |b| {
        b.iter(|| User::from_uid(Uid::from_raw(black_box(1000))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
