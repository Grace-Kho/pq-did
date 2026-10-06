//! FIPS 204 ML-DSA-65 bounded verifier: exact pure context, real software SHAKE.
//! Port of pqdid.bounded_mldsa; no signatures or challenges accepted from a host oracle.
use crate::{diagnostic::mark, Result};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};
const Q: i64 = 8380417;
const N: usize = 256;
const K: usize = 6;
const L: usize = 5;
const GAMMA1: i64 = 1 << 19;
const GAMMA2: i64 = (Q - 1) / 32;
type Poly = [i64; N];
fn shake(bits: u16, data: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    match bits {
        128 => {
            let mut h = Shake128::default();
            h.update(data);
            h.finalize_xof().read(&mut out);
        }
        256 => {
            let mut h = Shake256::default();
            h.update(data);
            h.finalize_xof().read(&mut out);
        }
        _ => unreachable!(),
    };
    out
}
struct Stream<'a> {
    bytes: &'a [u8],
    consumed: usize,
    limit: usize,
}
impl<'a> Stream<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.consumed.checked_add(n).ok_or("budget overflow")? > self.limit {
            return Err("sampler exhausted");
        }
        let end = self.consumed + n;
        let b = self
            .bytes
            .get(self.consumed..end)
            .ok_or("internal stream length")?;
        self.consumed = end;
        Ok(b)
    }
}
fn rej_ntt(s: &mut Stream<'_>) -> Result<Poly> {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        let b = s.take(3)?;
        let v = i64::from(b[0]) + (i64::from(b[1]) << 8) + ((i64::from(b[2]) & 127) << 16);
        if v < Q {
            out[i] = v;
            i += 1;
        }
    }
    Ok(out)
}
fn ball(s: &mut Stream<'_>) -> Result<Poly> {
    let mut signs = u64::from_le_bytes(s.take(8)?.try_into().unwrap());
    let mut out = [0; N];
    for i in N - 49..N {
        let mut j = usize::from(s.take(1)?[0]);
        while j > i {
            j = usize::from(s.take(1)?[0]);
        }
        out[i] = out[j];
        out[j] = 1 - 2 * ((signs & 1) as i64);
        signs >>= 1;
    }
    Ok(out)
}
fn unpack(data: &[u8], width: usize) -> Result<Poly> {
    if data.len() != 32 * width {
        return Err("polynomial length");
    }
    let mut out = [0; N];
    for (i, v) in out.iter_mut().enumerate() {
        for bit in 0..width {
            let k = i * width + bit;
            *v |= i64::from((data[k / 8] >> (k % 8)) & 1) << bit;
        }
    }
    Ok(out)
}
fn zetas() -> Poly {
    let mut out = [0; N];
    for (i, v) in out.iter_mut().enumerate() {
        let mut exponent = (i as u8).reverse_bits();
        let mut base = 1753;
        let mut result = 1;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * base % Q;
            }
            base = base * base % Q;
            exponent >>= 1;
        }
        *v = result;
    }
    out
}
fn ntt(input: &Poly, z: &Poly) -> Poly {
    let mut a = input.map(|v| v.rem_euclid(Q));
    let mut m = 0;
    let mut length = 128;
    while length >= 1 {
        for start in (0..N).step_by(2 * length) {
            m += 1;
            for j in start..start + length {
                let product = (z[m] * a[j + length]).rem_euclid(Q);
                a[j + length] = (a[j] - product).rem_euclid(Q);
                a[j] = (a[j] + product).rem_euclid(Q);
            }
        }
        length /= 2;
    }
    a
}
fn inv_ntt(input: &Poly, z: &Poly) -> Poly {
    let mut a = *input;
    let mut m = 256;
    let mut length = 1;
    while length < N {
        for start in (0..N).step_by(2 * length) {
            m -= 1;
            for j in start..start + length {
                let left = a[j];
                a[j] = (left + a[j + length]).rem_euclid(Q);
                a[j + length] = (-z[m] * (left - a[j + length]).rem_euclid(Q)).rem_euclid(Q);
            }
        }
        length *= 2;
    }
    a.map(|v| (v * 8347681).rem_euclid(Q))
}
fn decompose(value: i64) -> (i64, i64) {
    let positive = value.rem_euclid(Q);
    let mut low = positive % (2 * GAMMA2);
    if low > GAMMA2 {
        low -= 2 * GAMMA2;
    }
    if positive - low == Q - 1 {
        (0, low - 1)
    } else {
        ((positive - low).div_euclid(2 * GAMMA2), low)
    }
}
fn hint(h: i64, v: i64) -> i64 {
    let (high, low) = decompose(v);
    if h != 0 {
        (high + if low > 0 { 1 } else { -1 }).rem_euclid(16)
    } else {
        high
    }
}
pub fn verify(pk: &[u8], message: &[u8], sig: &[u8], context: &[u8]) -> Result<()> {
    mark(50);
    if pk.len() != 1952 || sig.len() != 3309 || context.len() > 255 {
        return Err("signature domain");
    }
    let mut formatted = vec![0, context.len() as u8];
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(message);
    mark(51);
    let mut t1 = [[0; N]; K];
    for (i, row) in t1.iter_mut().enumerate() {
        *row = unpack(&pk[32 + i * 320..32 + (i + 1) * 320], 10)?;
    }
    mark(52);
    let mut response = [[0; N]; L];
    for (i, row) in response.iter_mut().enumerate() {
        *row = unpack(&sig[48 + i * 640..48 + (i + 1) * 640], 20)?.map(|v| GAMMA1 - v);
    }
    mark(53);
    let bytes = &sig[3248..];
    let mut hints = [[0; N]; K];
    let mut index = 0;
    for (row, h) in hints.iter_mut().enumerate() {
        let end = usize::from(bytes[55 + row]);
        if end < index || end > 55 {
            return Err("hint endpoint");
        }
        let first = index;
        while index < end {
            if index > first && bytes[index - 1] >= bytes[index] {
                return Err("hint order");
            }
            h[usize::from(bytes[index])] = 1;
            index += 1;
        }
    }
    if bytes[index..55].iter().any(|b| *b != 0) {
        return Err("hint padding");
    }
    mark(54);
    // Match the reference schedule: expand all 30 matrices before message/challenge.
    mark(60);
    let mut matrix = vec![[[0; N]; L]; K];
    for (row, polys) in matrix.iter_mut().enumerate() {
        for (column, poly) in polys.iter_mut().enumerate() {
            mark(1000 + (row * 5 + column) as u32 * 4);
            let mut seed = pk[..32].to_vec();
            seed.extend_from_slice(&[column as u8, row as u8]);
            let bytes = shake(128, &seed, 1026);
            mark(1001 + (row * 5 + column) as u32 * 4);
            *poly = rej_ntt(&mut Stream {
                bytes: &bytes,
                consumed: 0,
                limit: 1026,
            })?;
            mark(1002 + (row * 5 + column) as u32 * 4);
        }
    }
    mark(61);
    mark(70);
    let tr = shake(256, pk, 64);
    mark(71);
    let mut pre = tr;
    pre.extend_from_slice(&formatted);
    let mu = shake(256, &pre, 64);
    mark(72);
    mark(73);
    let bytes = shake(256, &sig[..48], 256);
    mark(74);
    let challenge = ball(&mut Stream {
        bytes: &bytes,
        consumed: 0,
        limit: 256,
    })?;
    mark(75);
    mark(80);
    let z = zetas();
    mark(81);
    let zh = response.map(|r| ntt(&r, &z));
    mark(82);
    let mut az = [[0; N]; K];
    for row in 0..K {
        for column in 0..L {
            for i in 0..N {
                az[row][i] = (az[row][i] + matrix[row][column][i] * zh[column][i] % Q) % Q;
            }
        }
    }
    mark(83);
    let ch = ntt(&challenge, &z);
    mark(84);
    let th = t1.map(|r| ntt(&r.map(|v| (v * (1 << 13)) % Q), &z));
    mark(85);
    let mut w1 = Vec::with_capacity(768);
    for row in 0..K {
        mark(2000 + row as u32 * 3);
        let a = std::array::from_fn(|i| (az[row][i] - ch[i] * th[row][i] % Q).rem_euclid(Q));
        let w = inv_ntt(&a, &z);
        mark(2001 + row as u32 * 3);
        for i in (0..N).step_by(2) {
            let lo = hint(hints[row][i], w[i]);
            let hi = hint(hints[row][i + 1], w[i + 1]);
            if !(0..16).contains(&lo) || !(0..16).contains(&hi) {
                return Err("w1 range");
            }
            w1.push((lo | (hi << 4)) as u8);
        }
        mark(2002 + row as u32 * 3);
    }
    mark(95);
    let mut pre = mu;
    pre.extend_from_slice(&w1);
    let hash = shake(256, &pre, 48);
    mark(96);
    mark(97);
    if response
        .iter()
        .flatten()
        .any(|v| v.checked_abs().is_none_or(|v| v >= GAMMA1 - 196))
        || hash != sig[..48]
    {
        return Err("invalid signature");
    }
    mark(98);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ntt_exact_cap_and_exhaustion() {
        // 86 rejected triples, then 256 accepted triples: exactly 1026 bytes.
        let mut bytes = vec![255; 86 * 3];
        bytes.extend(vec![0; 256 * 3]);
        let mut s = Stream {
            bytes: &bytes,
            consumed: 0,
            limit: 1026,
        };
        assert!(rej_ntt(&mut s).is_ok());
        assert_eq!(s.consumed, 1026);
        let bytes = vec![255; 1029];
        let mut s = Stream {
            bytes: &bytes,
            consumed: 0,
            limit: 1026,
        };
        assert_eq!(rej_ntt(&mut s), Err("sampler exhausted"));
        assert_eq!(s.consumed, 1026);
    }
    #[test]
    fn ball_exact_cap_and_rejected_bytes() {
        let mut bytes = vec![0; 8];
        bytes.extend(vec![255; 199]);
        bytes.extend(vec![0; 49]);
        assert_eq!(bytes.len(), 256);
        let mut s = Stream {
            bytes: &bytes,
            consumed: 0,
            limit: 256,
        };
        let p = ball(&mut s).unwrap();
        assert_eq!(s.consumed, 256);
        assert_eq!(p.iter().filter(|v| **v != 0).count(), 49);
        let mut bytes = vec![0; 8];
        bytes.extend(vec![255; 249]);
        let mut s = Stream {
            bytes: &bytes,
            consumed: 0,
            limit: 256,
        };
        assert_eq!(ball(&mut s), Err("sampler exhausted"));
        assert_eq!(s.consumed, 256);
    }
    #[test]
    fn ntt_inverse_and_euclidean_semantics() {
        let z = zetas();
        let input = std::array::from_fn(|i| i as i64 - 128);
        assert_eq!(
            inv_ntt(&ntt(&input, &z), &z),
            input.map(|v| v.rem_euclid(Q))
        );
        assert_eq!((-1_i64).rem_euclid(Q), Q - 1);
        assert_eq!((-1_i64).div_euclid(2), -1);
        assert_eq!(i64::MIN.checked_abs(), None);
        for v in [-Q, -1, 0, 1, GAMMA2, GAMMA2 + 1, Q - 1, Q] {
            let (h, l) = decompose(v);
            assert!((0..16).contains(&h));
            assert!(l >= -GAMMA2 && l <= GAMMA2);
        }
    }
}
