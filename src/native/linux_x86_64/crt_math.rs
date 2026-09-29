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

#[cfg(test)]
mod tests {
    use super::*;

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
