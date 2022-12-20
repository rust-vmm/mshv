use criterion::{criterion_group, criterion_main, Criterion};
use mshv_bindings::{hv_message, hv_message_header};

// How bindgen generates default()
trait BindgenDefaultExt {
    type Item;
    fn bindgen_default() -> Self::Item {
        let mut s = ::std::mem::MaybeUninit::<Self::Item>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

impl BindgenDefaultExt for hv_message {
    type Item = Self;
}

impl BindgenDefaultExt for hv_message_header {
    type Item = Self;
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("hv_message_default", |b| b.iter(hv_message::default));
    c.bench_function("hv_message_bindgen_default", |b| {
        b.iter(hv_message::bindgen_default)
    });
    c.bench_function("hv_message_header_default", |b| {
        b.iter(hv_message_header::default)
    });
    c.bench_function("hv_message_header_bindgen_default", |b| {
        b.iter(hv_message_header::bindgen_default)
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
