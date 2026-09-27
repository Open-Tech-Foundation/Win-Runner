//! HashMap guest for Win-Runner: hand-rolled open-addressing map.
//!
//! `std` has no `HashMap` in `no_std`, so this guest carries a minimal one:
//! FNV-1a hashing, linear probing, backward-shift deletion, doubling growth
//! with full rehash. Exercises hashing loops, modulo division, table growth
//! (`realloc` path), and runtime-index bounds checks (which route to our
//! panic handler via the linked core rlib if ever violated).
//! Phases print `H<n>`; final `PASS`, exit 0. Build with `guests/build.sh`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

include!("support.rs");

extern "C" {
    fn GetStdHandle(nStdHandle: i32) -> u64;
    fn WriteFile(h: u64, buf: *const u8, n: u32, written: *mut u32, ov: u64) -> i32;
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

#[derive(Clone, Copy)]
enum Slot {
    Empty,
    Filled(u64, u64),
}

struct Map {
    slots: Vec<Slot>,
    len: usize,
}

fn hash(mut x: u64) -> u64 {
    // FNV-1a over the 8 key bytes.
    let mut h: u64 = 0xcbf29ce484222325;
    let mut i = 0;
    while i < 8 {
        h ^= (x & 0xFF) as u64;
        h = h.wrapping_mul(0x100000001b3);
        x >>= 8;
        i += 1;
    }
    h
}

impl Map {
    fn new() -> Map {
        Map {
            slots: Vec::new(),
            len: 0,
        }
    }

    fn find_slot(&self, key: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mut i = (hash(key) as usize) % self.slots.len();
        loop {
            match self.slots[i] {
                Slot::Empty => return None,
                Slot::Filled(k, _) if k == key => return Some(i),
                _ => {
                    i += 1;
                    if i == self.slots.len() {
                        i = 0;
                    }
                }
            }
        }
    }

    fn get(&self, key: u64) -> Option<u64> {
        match self.find_slot(key) {
            Some(i) => match self.slots[i] {
                Slot::Filled(_, v) => Some(v),
                Slot::Empty => None,
            },
            None => None,
        }
    }

    fn insert(&mut self, key: u64, val: u64) {
        if self.slots.is_empty() {
            self.slots.resize(16, Slot::Empty);
        }
        if self.len * 8 >= self.slots.len() * 7 {
            self.grow();
        }
        let mut i = (hash(key) as usize) % self.slots.len();
        loop {
            match self.slots[i] {
                Slot::Empty => {
                    self.slots[i] = Slot::Filled(key, val);
                    self.len += 1;
                    return;
                }
                Slot::Filled(k, _) if k == key => {
                    self.slots[i] = Slot::Filled(key, val);
                    return;
                }
                _ => {
                    i += 1;
                    if i == self.slots.len() {
                        i = 0;
                    }
                }
            }
        }
    }

    fn remove(&mut self, key: u64) -> Option<u64> {
        let mut i = match self.find_slot(key) {
            Some(i) => i,
            None => return None,
        };
        let out = match self.slots[i] {
            Slot::Filled(_, v) => v,
            Slot::Empty => return None,
        };
        // Backward-shift deletion: close the probe gap.
        let n = self.slots.len();
        self.slots[i] = Slot::Empty;
        self.len -= 1;
        let mut j = i;
        loop {
            j += 1;
            if j == n {
                j = 0;
            }
            let (k, v) = match self.slots[j] {
                Slot::Empty => break,
                Slot::Filled(k, v) => (k, v),
            };
            let home = (hash(k) as usize) % n;
            // Move (k,v) back iff its probe path passes through i.
            let mut x = home;
            let mut move_it = false;
            loop {
                if x == i {
                    move_it = true;
                    break;
                }
                if x == j {
                    break;
                }
                x += 1;
                if x == n {
                    x = 0;
                }
            }
            if move_it {
                self.slots[i] = Slot::Filled(k, v);
                self.slots[j] = Slot::Empty;
                i = j;
            }
        }
        Some(out)
    }

    fn grow(&mut self) {
        let new_n = if self.slots.is_empty() {
            16
        } else {
            self.slots.len() * 2
        };
        let mut fresh: Vec<Slot> = Vec::new();
        fresh.resize(new_n, Slot::Empty);
        let mut k = 0;
        while k < self.slots.len() {
            if let Slot::Filled(key, val) = self.slots[k] {
                let mut i = (hash(key) as usize) % new_n;
                loop {
                    match fresh[i] {
                        Slot::Empty => {
                            fresh[i] = Slot::Filled(key, val);
                            break;
                        }
                        _ => {
                            i += 1;
                            if i == new_n {
                                i = 0;
                            }
                        }
                    }
                }
            }
            k += 1;
        }
        self.slots = fresh;
    }
}

#[no_mangle]
pub extern "C" fn guest_entry() {
    // H1: insert 0..100, read all back.
    let mut m = Map::new();
    let mut i = 0u64;
    while i < 100 {
        m.insert(i, i * 3 + 1);
        i += 1;
    }
    check(m.len == 100, 1);
    print(b"H1a\n");
    let mut j = 0u64;
    while j < 100 {
        check(m.get(j) == Some(j * 3 + 1), 1);
        j += 1;
    }
    print(b"H1\n");

    // H2: overwrite (len unchanged, value updated).
    m.insert(42, 999);
    m.insert(42, 1000);
    check(m.get(42) == Some(1000), 2);
    check(m.len == 100, 2);
    print(b"H2\n");

    // H3: remove half (backward-shift deletion under probe chains).
    let mut k = 0u64;
    while k < 100 {
        if k % 2 == 0 {
            check(m.remove(k) == Some(if k == 42 { 1000 } else { k * 3 + 1 }), 3);
        }
        k += 1;
    }
    check(m.len == 50, 3);
    let mut k = 1u64;
    while k < 100 {
        check(m.get(k) == Some(k * 3 + 1), 3);
        k += 2;
    }
    check(m.get(0).is_none() && m.get(98).is_none(), 3);
    print(b"H3\n");

    // H4: growth storm (1000 inserts, several rehashes), verify all.
    let mut g = Map::new();
    let mut k = 0u64;
    while k < 1000 {
        g.insert(k.wrapping_mul(0x9E3779B97F4A7C15), k);
        k += 1;
    }
    check(g.len == 1000, 4);
    let mut k = 0u64;
    while k < 1000 {
        check(g.get(k.wrapping_mul(0x9E3779B97F4A7C15)) == Some(k), 4);
        k += 1;
    }
    print(b"H4\n");

    // H5: missing keys.
    check(g.get(0xDEAD_BEEF_DEAD_BEEF).is_none(), 5);
    check(m.get(0xFFFF_FFFF_FFFF_FFFF).is_none(), 5);
    print(b"H5\n");

    print(b"PASS\n");
    unsafe { ExitProcess(0) }
}
