//! Language-construct guest for Win-Runner: conditionals, loops, match, calls.
//!
//! Each phase prints `P<n>` on success; any mismatch prints `FAIL<n>` and
//! exits 1. Final `PASS` + exit 0 means every construct below runs.
//! Build with `guests/build.sh`. Guest rules: `no_std`, no unproven bounds
//! checks (see argv_echo.rs), plain scalar code.

#![no_std]
#![no_main]

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { ExitProcess(99) }
}

fn print(s: &[u8]) {
    unsafe {
        let mut w: u32 = 0;
        WriteFile(GetStdHandle(-11), s.as_ptr(), s.len() as u32, &mut w, 0);
    }
}

fn fail(n: u8) -> ! {
    print(b"FAIL");
    print(&[b'0' + n]);
    print(b"\n");
    unsafe { ExitProcess(1) }
}

fn check(ok: bool, n: u8) {
    if !ok {
        fail(n);
    }
}

fn add(a: u32, b: u32) -> u32 {
    a + b
}

fn fact(n: u32) -> u32 {
    if n <= 1 {
        1
    } else {
        n * fact(n - 1)
    }
}

fn classify(x: i32) -> u8 {
    if x < 0 {
        0
    } else if x == 0 {
        1
    } else if x <= 10 {
        2
    } else {
        3
    }
}

fn pick(v: u32) -> u32 {
    match v {
        0 => 100,
        1 | 2 => 200,
        3..=9 => 300,
        _ => 400,
    }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    // P1: if/else comparisons.
    check(classify(-5) == 0, 1);
    check(classify(0) == 1, 1);
    check(classify(7) == 2, 1);
    check(classify(42) == 3, 1);
    print(b"P1\n");

    // P2: while loop + break/continue.
    let mut sum = 0u32;
    let mut i = 0u32;
    while i < 100 {
        i += 1;
        if i % 2 == 0 {
            continue;
        }
        if i > 21 {
            break;
        }
        sum += i;
    }
    check(sum == 1 + 3 + 5 + 7 + 9 + 11 + 13 + 15 + 17 + 19 + 21, 2);
    print(b"P2\n");

    // P3: match.
    check(pick(0) == 100, 3);
    check(pick(2) == 200, 3);
    check(pick(5) == 300, 3);
    check(pick(99) == 400, 3);
    print(b"P3\n");

    // P4: boolean logic.
    let a = true;
    let b = false;
    check(a && !b, 4);
    check(!(a && b), 4);
    check(a || b, 4);
    check(!(!a || !b) == (a && b), 4);
    print(b"P4\n");

    // P5: calls + recursion.
    check(add(20, 22) == 42, 5);
    check(fact(5) == 120, 5);
    print(b"P5\n");

    // P6: u64 arithmetic.
    let x: u64 = 0x1234_5678_9ABC_DEF0;
    check(x.wrapping_add(0x10) == 0x1234_5678_9ABC_DF00, 6);
    check(x >> 32 == 0x1234_5678, 6);
    check(x.wrapping_mul(3) >> 2 == x.wrapping_mul(3) >> 2, 6);
    check(100u64 / 7 == 14 && 100u64 % 7 == 2, 6);
    check((1u64 << 63) != 0 && (1u64 << 63) >> 63 == 1, 6);
    print(b"P6\n");

    // P7: option/result + iterator loop (no unproven bounds checks).
    let o: Option<u32> = Some(7);
    check(o.unwrap_or(0) == 7, 7);
    let n: Option<u32> = None;
    check(n.unwrap_or(9) == 9, 7);
    let r: Result<u32, u32> = Ok(5);
    check(r.unwrap_or(0) == 5, 7);
    let arr = [3u32, 1, 4, 1, 5, 9, 2, 6];
    let mut total = 0u32;
    for &v in arr.iter() {
        total += v;
    }
    check(total == 31, 7);
    print(b"P7\n");

    // P8: mutable references.
    let mut x = 10u32;
    let mut y = 20u32;
    swap(&mut x, &mut y);
    check(x == 20 && y == 10, 8);
    bump(&mut x);
    check(x == 21, 8);
    print(b"P8\n");

    // P9: structs + enums with data + methods.
    let p = Point { x: 3, y: 4 };
    check(p.len2() == 25, 9);
    let e = Shape::Rect { w: 6, h: 7 };
    check(e.area() == 42, 9);
    let c = Shape::Circle(5);
    check(c.area() == 25, 9);
    print(b"P9\n");

    // P10: casts and sign extension.
    let neg8: i8 = -5;
    check(neg8 as i32 == -5, 10);
    check(neg8 as u8 == 251, 10);
    let big: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    check(big as u32 == 0xFFFF_FFFF, 10);
    check(0xABCDu32 as u16 as u32 == 0xABCD, 10);
    print(b"P10\n");

    // P11: bitwise ops.
    let v: u32 = 0xF0F0_0F0F;
    check(!v == 0x0F0F_F0F0, 11);
    check((v ^ 0xFFFF_FFFF) == 0x0F0F_F0F0, 11);
    check((v | 0x00FF_00FF) == 0xF0FF_0FFF, 11);
    check((v & 0xFF00_FF00) == 0xF000_0F00, 11);
    check((v << 4) == 0x0F00_F0F0, 11);
    check((v >> 4) == 0x0F0F_00F0, 11);
    check(v.rotate_left(8) == 0xF00F_0FF0, 11);
    print(b"P11\n");

    // P12: byte-string scan (pointer loop, no bounds checks).
    let s = b"hello world";
    check(count_byte(s, b'o') == 2, 12);
    check(count_byte(s, b'z') == 0, 12);
    print(b"P12\n");

    // P13: u128 add/mul (inline, no intrinsics).
    let a: u128 = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0001;
    let b: u128 = 0x1234;
    check(a.wrapping_add(b) == 0x0000_0000_0000_0000_0000_0000_0000_0001u128.wrapping_add(0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000u128).wrapping_add(b), 13);
    check(a.wrapping_mul(2) == (a << 1), 13);
    print(b"P13\n");

    // P14: signed division/modulo.
    check(-42i32 / 5 == -8 && -42i32 % 5 == -2, 14);
    check(42i32 / -5 == -8 && 42i32 % -5 == 2, 14);
    check(-100i64 / 3 == -33, 14);
    print(b"P14\n");

    // P15: function pointers.
    let ops: [fn(u32, u32) -> u32; 2] = [add, mul2];
    check(apply(ops[0], 6, 7) == 13, 15);
    check(apply(ops[1], 6, 7) == 42, 15);
    print(b"P15\n");

    // P16: bit intrinsics.
    check(0b10100u32.trailing_zeros() == 2, 16);
    check(0b10100u32.leading_zeros() == 27, 16);
    check(0x12345678u32.swap_bytes() == 0x78563412, 16);
    check(0b10100u32.count_ones() == 2, 16);
    print(b"P16\n");

    print(b"PASS\n");
    unsafe { ExitProcess(0) }
}

fn swap(a: &mut u32, b: &mut u32) {
    let t = *a;
    *a = *b;
    *b = t;
}

fn mul2(a: u32, b: u32) -> u32 {
    a * b
}

fn apply(f: fn(u32, u32) -> u32, x: u32, y: u32) -> u32 {
    f(x, y)
}

fn bump(v: &mut u32) {
    *v += 1;
}

struct Point {
    x: i32,
    y: i32,
}

impl Point {
    fn len2(&self) -> i32 {
        self.x * self.x + self.y * self.y
    }
}

enum Shape {
    Rect { w: u32, h: u32 },
    Circle(u32),
}

impl Shape {
    fn area(&self) -> u32 {
        match self {
            Shape::Rect { w, h } => w * h,
            Shape::Circle(r) => r * r,
        }
    }
}

fn count_byte(s: &[u8], needle: u8) -> u32 {
    let mut n = 0u32;
    let mut p = s.as_ptr();
    // INVARIANT: p stays within the slice; counted down from len.
    let mut left = s.len();
    while left > 0 {
        if unsafe { *p } == needle {
            n += 1;
        }
        p = unsafe { p.offset(1) };
        left -= 1;
    }
    n
}
