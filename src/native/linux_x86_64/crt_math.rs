//! UCRT `<math.h>` functions over Rust's floating-point operations.

pub(super) extern "win64" fn native_crt_acos(x: f64) -> f64 {
    x.acos()
}
pub(super) extern "win64" fn native_crt_acosf(x: f32) -> f32 {
    x.acos()
}
pub(super) extern "win64" fn native_crt_acosh(x: f64) -> f64 {
    x.acosh()
}
pub(super) extern "win64" fn native_crt_acoshf(x: f32) -> f32 {
    x.acosh()
}
pub(super) extern "win64" fn native_crt_asin(x: f64) -> f64 {
    x.asin()
}
pub(super) extern "win64" fn native_crt_asinf(x: f32) -> f32 {
    x.asin()
}
pub(super) extern "win64" fn native_crt_asinh(x: f64) -> f64 {
    x.asinh()
}
pub(super) extern "win64" fn native_crt_asinhf(x: f32) -> f32 {
    x.asinh()
}
pub(super) extern "win64" fn native_crt_atan(x: f64) -> f64 {
    x.atan()
}
pub(super) extern "win64" fn native_crt_atanf(x: f32) -> f32 {
    x.atan()
}
pub(super) extern "win64" fn native_crt_atanh(x: f64) -> f64 {
    x.atanh()
}
pub(super) extern "win64" fn native_crt_atanhf(x: f32) -> f32 {
    x.atanh()
}
pub(super) extern "win64" fn native_crt_cbrt(x: f64) -> f64 {
    x.cbrt()
}
pub(super) extern "win64" fn native_crt_cbrtf(x: f32) -> f32 {
    x.cbrt()
}
pub(super) extern "win64" fn native_crt_ceil(x: f64) -> f64 {
    x.ceil()
}
pub(super) extern "win64" fn native_crt_ceilf(x: f32) -> f32 {
    x.ceil()
}
pub(super) extern "win64" fn native_crt_cos(x: f64) -> f64 {
    x.cos()
}
pub(super) extern "win64" fn native_crt_cosf(x: f32) -> f32 {
    x.cos()
}
pub(super) extern "win64" fn native_crt_cosh(x: f64) -> f64 {
    x.cosh()
}
pub(super) extern "win64" fn native_crt_coshf(x: f32) -> f32 {
    x.cosh()
}
pub(super) extern "win64" fn native_crt_exp(x: f64) -> f64 {
    x.exp()
}
pub(super) extern "win64" fn native_crt_expf(x: f32) -> f32 {
    x.exp()
}
pub(super) extern "win64" fn native_crt_floor(x: f64) -> f64 {
    x.floor()
}
pub(super) extern "win64" fn native_crt_floorf(x: f32) -> f32 {
    x.floor()
}
pub(super) extern "win64" fn native_crt_log(x: f64) -> f64 {
    x.ln()
}
pub(super) extern "win64" fn native_crt_logf(x: f32) -> f32 {
    x.ln()
}
pub(super) extern "win64" fn native_crt_log10(x: f64) -> f64 {
    x.log10()
}
pub(super) extern "win64" fn native_crt_log10f(x: f32) -> f32 {
    x.log10()
}
pub(super) extern "win64" fn native_crt_log2(x: f64) -> f64 {
    x.log2()
}
pub(super) extern "win64" fn native_crt_log2f(x: f32) -> f32 {
    x.log2()
}
pub(super) extern "win64" fn native_crt_sin(x: f64) -> f64 {
    x.sin()
}
pub(super) extern "win64" fn native_crt_sinf(x: f32) -> f32 {
    x.sin()
}
pub(super) extern "win64" fn native_crt_sinh(x: f64) -> f64 {
    x.sinh()
}
pub(super) extern "win64" fn native_crt_sinhf(x: f32) -> f32 {
    x.sinh()
}
pub(super) extern "win64" fn native_crt_sqrt(x: f64) -> f64 {
    x.sqrt()
}
pub(super) extern "win64" fn native_crt_sqrtf(x: f32) -> f32 {
    x.sqrt()
}
pub(super) extern "win64" fn native_crt_tan(x: f64) -> f64 {
    x.tan()
}
pub(super) extern "win64" fn native_crt_tanf(x: f32) -> f32 {
    x.tan()
}
pub(super) extern "win64" fn native_crt_tanh(x: f64) -> f64 {
    x.tanh()
}
pub(super) extern "win64" fn native_crt_tanhf(x: f32) -> f32 {
    x.tanh()
}
pub(super) extern "win64" fn native_crt_round(x: f64) -> f64 {
    x.round()
}
pub(super) extern "win64" fn native_crt_roundf(x: f32) -> f32 {
    x.round()
}
pub(super) extern "win64" fn native_crt_trunc(x: f64) -> f64 {
    x.trunc()
}
pub(super) extern "win64" fn native_crt_truncf(x: f32) -> f32 {
    x.trunc()
}
pub(super) extern "win64" fn native_crt_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}
pub(super) extern "win64" fn native_crt_atan2f(y: f32, x: f32) -> f32 {
    y.atan2(x)
}
pub(super) extern "win64" fn native_crt_pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}
pub(super) extern "win64" fn native_crt_powf(x: f32, y: f32) -> f32 {
    x.powf(y)
}
/// `fmod`: Rust's `%` on floats has C's truncated-remainder semantics.
pub(super) extern "win64" fn native_crt_fmod(x: f64, y: f64) -> f64 {
    x % y
}
pub(super) extern "win64" fn native_crt_fmodf(x: f32, y: f32) -> f32 {
    x % y
}
pub(super) extern "win64" fn native_crt_fma(x: f64, y: f64, z: f64) -> f64 {
    x.mul_add(y, z)
}
pub(super) extern "win64" fn native_crt_fmaf(x: f32, y: f32, z: f32) -> f32 {
    x.mul_add(y, z)
}
/// `modf`: the fractional part, with the integral part stored through
/// `integral`; both keep the sign of `x`.
pub(super) extern "win64" fn native_crt_modf(x: f64, integral: *mut f64) -> f64 {
    let whole = x.trunc();
    if !integral.is_null() {
        unsafe { integral.write_unaligned(whole) };
    }
    if x.is_infinite() {
        0.0f64.copysign(x)
    } else {
        (x - whole).copysign(x)
    }
}
pub(super) extern "win64" fn native_crt_modff(x: f32, integral: *mut f32) -> f32 {
    let whole = x.trunc();
    if !integral.is_null() {
        unsafe { integral.write_unaligned(whole) };
    }
    if x.is_infinite() {
        0.0f32.copysign(x)
    } else {
        (x - whole).copysign(x)
    }
}

/// `_dsign`/`_fdsign`: the sign bit, as the UCRT reports it (0x8000 when set).
pub(super) extern "win64" fn native_crt_dsign(x: f64) -> i32 {
    if x.is_sign_negative() { 0x8000 } else { 0 }
}
pub(super) extern "win64" fn native_crt_fdsign(x: f32) -> i32 {
    if x.is_sign_negative() { 0x8000 } else { 0 }
}
pub(super) extern "win64" fn native_crt_exp2(x: f64) -> f64 {
    x.exp2()
}
pub(super) extern "win64" fn native_crt_log1p(x: f64) -> f64 {
    x.ln_1p()
}
/// `nearbyint` in the default round-to-nearest-even mode, without raising
/// the inexact exception.
pub(super) extern "win64" fn native_crt_nearbyint(x: f64) -> f64 {
    x.round_ties_even()
}
pub(super) extern "win64" fn native_crt_nearbyintf(x: f32) -> f32 {
    x.round_ties_even()
}

/// `ldexp(x, exponent)`: x * 2^exponent, scaled in steps so intermediate
/// powers of two neither overflow nor flush to zero early.
pub(super) extern "win64" fn native_crt_ldexp(x: f64, exponent: i32) -> f64 {
    let mut value = x;
    let mut remaining = exponent;
    while remaining > 1000 {
        value *= 2f64.powi(1000);
        remaining -= 1000;
    }
    while remaining < -1000 {
        value *= 2f64.powi(-1000);
        remaining += 1000;
    }
    value * 2f64.powi(remaining)
}

/// `frexp(x, exponent)`: the mantissa in [0.5, 1) and the power of two.
pub(super) extern "win64" fn native_crt_frexp(x: f64, exponent: *mut i32) -> f64 {
    let write = |value: i32| {
        if !exponent.is_null() {
            unsafe { exponent.write_unaligned(value) };
        }
    };
    if x == 0.0 || !x.is_finite() {
        write(0);
        return x;
    }
    let (value, bias) = if x.is_subnormal() { (x * 2f64.powi(54), -54) } else { (x, 0) };
    let bits = value.to_bits();
    let biased = ((bits >> 52) & 0x7ff) as i32;
    write(biased - 1022 + bias);
    f64::from_bits((bits & !(0x7ffu64 << 52)) | (1022u64 << 52))
}

/// `nextafter(x, y)`: the adjacent representable value from x toward y.
pub(super) extern "win64" fn native_crt_nextafter(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    if x == y {
        return y;
    }
    if x == 0.0 {
        return f64::from_bits(1).copysign(y);
    }
    let bits = x.to_bits();
    let away_from_zero = (y > x) == (x > 0.0);
    f64::from_bits(if away_from_zero { bits + 1 } else { bits - 1 })
}
pub(super) extern "win64" fn native_crt_nextafterf(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    if x == y {
        return y;
    }
    if x == 0.0 {
        return f32::from_bits(1).copysign(y);
    }
    let bits = x.to_bits();
    let away_from_zero = (y > x) == (x > 0.0);
    f32::from_bits(if away_from_zero { bits + 1 } else { bits - 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frexp_ldexp_and_nextafter_follow_c_semantics() {
        let mut exponent = 0;
        assert_eq!(native_crt_frexp(8.0, &mut exponent), 0.5);
        assert_eq!(exponent, 4);
        assert_eq!(native_crt_frexp(-0.75, &mut exponent), -0.75);
        assert_eq!(exponent, 0);
        let tiny = f64::from_bits(1);
        let mantissa = native_crt_frexp(tiny, &mut exponent);
        assert_eq!((mantissa, exponent), (0.5, -1073));
        assert_eq!(native_crt_ldexp(0.5, 4), 8.0);
        assert_eq!(native_crt_ldexp(1.0, -1074), tiny);
        assert_eq!(native_crt_ldexp(1.0, 1024), f64::INFINITY);
        assert_eq!(native_crt_nextafter(1.0, 2.0), 1.0 + f64::EPSILON);
        assert_eq!(native_crt_nextafter(0.0, -1.0), -tiny);
        assert_eq!(native_crt_nextafter(-1.0, 0.0), -1.0 + f64::EPSILON / 2.0);
        assert_eq!(native_crt_nextafterf(1.0, 0.0), 1.0 - f32::EPSILON / 2.0);
        assert_eq!(native_crt_nearbyint(2.5), 2.0);
        assert_eq!(native_crt_nearbyintf(3.5), 4.0);
        assert_eq!(native_crt_dsign(-0.0), 0x8000);
        assert_eq!(native_crt_fdsign(1.0), 0);
        assert_eq!(native_crt_exp2(10.0), 1024.0);
        assert!((native_crt_log1p(1e-10) - 1e-10).abs() < 1e-20);
    }

    #[test]
    fn math_functions_follow_c_semantics() {
        assert_eq!(native_crt_ceilf(1.2), 2.0);
        assert_eq!(
            native_crt_round(-2.5),
            -3.0,
            "halfway rounds away from zero"
        );
        assert_eq!(native_crt_fmod(-7.0, 3.0), -1.0);
        assert_eq!(native_crt_pow(2.0, 10.0), 1024.0);
        assert!((native_crt_atan2(1.0, 1.0) - std::f64::consts::FRAC_PI_4).abs() < 1e-15);
        assert_eq!(native_crt_log2(8.0), 3.0);
        assert_eq!(native_crt_fma(2.0, 3.0, 4.0), 10.0);
        let mut whole = 0.0;
        assert_eq!(native_crt_modf(-3.75, &mut whole), -0.75);
        assert_eq!(whole, -3.0);
        assert!(native_crt_sqrt(-1.0).is_nan());
    }
}
