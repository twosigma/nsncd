use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nix::unistd::{Uid, User};

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("User::from_uid", |b| {
        b.iter(|| User::from_uid(Uid::from_raw(black_box(1000))))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
