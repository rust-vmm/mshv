/// Set bits by index and OR them together
#[macro_export]
macro_rules! set_bits {
    ($int_type:ty, $bit:expr) => {{
        let bit: $int_type = (1 << $bit).into();
        bit
    }};
    ($int_type:ty, $bit:expr, $($bits:expr),+) => {{
        set_bits!($int_type, $bit) | set_bits!($int_type, $($bits),+)
    }};
}
