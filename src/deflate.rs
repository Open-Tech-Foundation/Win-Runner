//! Minimal raw DEFLATE decoder (RFC 1951, zlib wrapper NOT included).
//!
//! Supports stored, fixed- and dynamic-Huffman blocks with LZ77 matches.
//! Used to extract real-world release zips (e.g. ripgrep). Deliberately
//! small: puff-style canonical decoding, no fancy table speedups, output
//! capped to bound zip-bomb risk.

const MAXBITS: usize = 15;
const MAXLCODES: usize = 288;
const MAXDCODES: usize = 30;
/// Refuse to expand beyond this (zip-bomb guard).
pub const MAX_OUTPUT: usize = 256 * 1024 * 1024;

// Length codes 257..285: base + extra bits.
const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83,
    99, 115, 131, 163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5,
    5, 0,
];
// Distance codes 0..29: base + extra bits.
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11,
    11, 12, 12, 13, 13,
];
// Order of the code-length alphabet.
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

struct Bits<'a> {
    data: &'a [u8],
    pos: usize, // byte position
    bit: u8,    // bit position within byte (0..8), LSB-first
}

impl<'a> Bits<'a> {
    fn get(&mut self, n: u8) -> Result<u32, String> {
        let mut out: u32 = 0;
        for i in 0..n {
            let b = *self.data.get(self.pos).ok_or("truncated deflate stream")?;
            out |= (((b >> self.bit) & 1) as u32) << i;
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.pos += 1;
            }
        }
        Ok(out)
    }
    fn align_byte(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }
}

/// Huffman decoder from code lengths (canonical codes, LSB-first on the wire).
struct Huff {
    /// counts[len] = number of codes of that length
    counts: [u16; MAXBITS + 1],
    /// symbols sorted by (len, symbol)
    symbols: Vec<u16>,
}

impl Huff {
    fn build(lengths: &[u8]) -> Result<Self, String> {
        let mut counts = [0u16; MAXBITS + 1];
        for &l in lengths {
            if l as usize > MAXBITS {
                return Err("invalid Huffman code length".to_string());
            }
            counts[l as usize] += 1;
        }
        if counts[0] == lengths.len() as u16 {
            return Err("incomplete Huffman code (all zero)".to_string());
        }
        // Over-subscribed check.
        let mut left: i32 = 1;
        for len in 1..=MAXBITS {
            left <<= 1;
            left -= counts[len] as i32;
            if left < 0 {
                return Err("over-subscribed Huffman code".to_string());
            }
        }
        let mut offsets = [0usize; MAXBITS + 1];
        for len in 1..MAXBITS {
            offsets[len + 1] = offsets[len] + counts[len] as usize;
        }
        let mut symbols = vec![0u16; lengths.len()];
        let mut next = offsets;
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[next[l as usize]] = sym as u16;
                next[l as usize] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, b: &mut Bits) -> Result<u16, String> {
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: usize = 0;
        for len in 1..=MAXBITS {
            code |= b.get(1)?;
            let count = self.counts[len] as u32;
            if code - first < count {
                return Ok(self.symbols[index + (code - first) as usize]);
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("invalid Huffman code".to_string())
    }
}

/// Decompress raw DEFLATE bytes.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut b = Bits {
        data,
        pos: 0,
        bit: 0,
    };
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = b.get(1)?;
        let btype = b.get(2)?;
        match btype {
            0 => {
                // stored
                b.align_byte();
                if b.pos + 4 > data.len() {
                    return Err("truncated stored block header".to_string());
                }
                let len = u16::from_le_bytes([data[b.pos], data[b.pos + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[b.pos + 2], data[b.pos + 3]]);
                if nlen != !(len as u16) {
                    return Err("bad stored block lengths".to_string());
                }
                b.pos += 4;
                if b.pos + len > data.len() {
                    return Err("truncated stored block".to_string());
                }
                if out.len() + len > MAX_OUTPUT {
                    return Err("deflate output too large".to_string());
                }
                out.extend_from_slice(&data[b.pos..b.pos + len]);
                b.pos += len;
            }
            1 | 2 => {
                let (litlen, dist) = if btype == 1 {
                    // fixed Huffman
                    let mut ll = [0u8; MAXLCODES];
                    for (i, l) in ll.iter_mut().enumerate() {
                        *l = if i < 144 {
                            8
                        } else if i < 256 {
                            9
                        } else if i < 280 {
                            7
                        } else {
                            8
                        };
                    }
                    let dd = [5u8; MAXDCODES];
                    (Huff::build(&ll)?, Huff::build(&dd)?)
                } else {
                    let hlit = b.get(5)? as usize + 257;
                    let hdist = b.get(5)? as usize + 1;
                    let hclen = b.get(4)? as usize + 4;
                    if hlit > MAXLCODES || hdist > MAXDCODES {
                        return Err("bad dynamic header".to_string());
                    }
                    let mut cl_lens = [0u8; 19];
                    for i in 0..hclen {
                        cl_lens[CL_ORDER[i]] = b.get(3)? as u8;
                    }
                    let cl = Huff::build(&cl_lens)?;
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut i = 0;
                    while i < lengths.len() {
                        let sym = cl.decode(&mut b)? as usize;
                        match sym {
                            0..=15 => {
                                lengths[i] = sym as u8;
                                i += 1;
                            }
                            16 => {
                                if i == 0 {
                                    return Err("bad repeat-16".to_string());
                                }
                                let rep = b.get(2)? as usize + 3;
                                let v = lengths[i - 1];
                                if i + rep > lengths.len() {
                                    return Err("repeat overflow".to_string());
                                }
                                for j in 0..rep {
                                    lengths[i + j] = v;
                                }
                                i += rep;
                            }
                            17 => {
                                let rep = b.get(3)? as usize + 3;
                                if i + rep > lengths.len() {
                                    return Err("repeat overflow".to_string());
                                }
                                for j in 0..rep {
                                    lengths[i + j] = 0;
                                }
                                i += rep;
                            }
                            18 => {
                                let rep = b.get(7)? as usize + 11;
                                if i + rep > lengths.len() {
                                    return Err("repeat overflow".to_string());
                                }
                                for j in 0..rep {
                                    lengths[i + j] = 0;
                                }
                                i += rep;
                            }
                            _ => return Err("bad code-length symbol".to_string()),
                        }
                    }
                    if lengths[256] == 0 {
                        return Err("missing end-of-block code".to_string());
                    }
                    (
                        Huff::build(&lengths[..hlit])?,
                        Huff::build(&lengths[hlit..])?,
                    )
                };
                // codes
                loop {
                    let sym = litlen.decode(&mut b)? as usize;
                    if sym < 256 {
                        if out.len() >= MAX_OUTPUT {
                            return Err("deflate output too large".to_string());
                        }
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        let li = sym - 257;
                        if li >= LEN_BASE.len() {
                            return Err("bad length code".to_string());
                        }
                        let len = LEN_BASE[li] as usize + b.get(LEN_EXTRA[li])? as usize;
                        let dsym = dist.decode(&mut b)? as usize;
                        if dsym >= DIST_BASE.len() {
                            return Err("bad distance code".to_string());
                        }
                        let d = DIST_BASE[dsym] as usize + b.get(DIST_EXTRA[dsym])? as usize;
                        if d == 0 || d > out.len() {
                            return Err("bad match distance".to_string());
                        }
                        if out.len() + len > MAX_OUTPUT {
                            return Err("deflate output too large".to_string());
                        }
                        for _ in 0..len {
                            let c = out[out.len() - d];
                            out.push(c);
                        }
                    }
                }
            }
            _ => return Err("invalid deflate block type".to_string()),
        }
        if last == 1 {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const PLAIN: &[u8] = b"hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. hello wincli deflate test. ";

    // Raw deflate streams from Python (zlib.compressobj(level, DEFLATED, -15)).
    const LEVEL1: &str = "cb48cdc9c95728cfcc4bcec95448494dcb492c495528492d2ed153c818951a0d8dd1b4319a1db0150e00";
    const LEVEL6: &str = "cb48cdc9c95728cfcc4bcec95448494dcb492c495528492d2ed153c818951a951a951a95c2260500";
    const LEVEL9: &str = "cb48cdc9c95728cfcc4bcec95448494dcb492c495528492d2ed153c818951a951a951a95c2260500";

    #[test]
    fn inflate_levels() {
        for raw in [LEVEL1, LEVEL6, LEVEL9] {
            assert_eq!(inflate(&hex(raw)).unwrap(), PLAIN);
        }
    }

    #[test]
    fn inflate_garbage_fails_clearly() {
        assert!(inflate(b"").is_err());
        assert!(inflate(b"\xff\xff\xff\xff").is_err());
        assert!(inflate(&hex(LEVEL6)[..10]).is_err()); // truncated
    }
}
