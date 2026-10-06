//! Isolated executable ports of enrol and CredValid, not full authentication.
//! All witness bytes are runtime inputs. No native verification oracle is used.
pub mod diagnostic;
pub mod mldsa;
use diagnostic::mark;
use sha3::{Digest, Sha3_384};
pub type Result<T> = std::result::Result<T, &'static str>;
pub const PROFILE: &[u8] = b"PQDID-R0S-DIAG1";
pub const SUITE: &[u8] = b"PQ-DID-MITH-1";
pub const MAX_PUBLIC: usize = 65536;
pub const MAX_PRIVATE: usize = 16384;

pub fn record<'a>(data: &'a [u8], tag: &[u8], count: Option<usize>) -> Result<Vec<&'a [u8]>> {
    if data.len() > MAX_PUBLIC {
        return Err("record too large");
    }
    fn word(d: &[u8], p: &mut usize) -> Result<usize> {
        let end = p.checked_add(4).ok_or("offset overflow")?;
        let b: [u8; 4] = d.get(*p..end).ok_or("truncated word")?.try_into().unwrap();
        *p = end;
        Ok(u32::from_be_bytes(b) as usize)
    }
    fn field<'a>(d: &'a [u8], p: &mut usize) -> Result<&'a [u8]> {
        let n = word(d, p)?;
        let end = p.checked_add(n).ok_or("offset overflow")?;
        let b = d.get(*p..end).ok_or("truncated field")?;
        *p = end;
        Ok(b)
    }
    let mut p = 0;
    if field(data, &mut p)? != tag {
        return Err("tag");
    }
    let n = word(data, &mut p)?;
    if n > 64 || count.is_some_and(|v| v != n) {
        return Err("arity");
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(field(data, &mut p)?);
    }
    if p != data.len() {
        return Err("trailing bytes");
    }
    Ok(out)
}
pub fn encode(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    fn lp(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&u32::try_from(b.len()).expect("bounded field").to_be_bytes());
        v.extend_from_slice(b);
    }
    lp(&mut v, tag);
    v.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for b in fields {
        lp(&mut v, b);
    }
    v
}
fn width(b: &[u8], n: usize) -> Result<()> {
    if b.len() == n {
        Ok(())
    } else {
        Err("width")
    }
}
fn uint(b: &[u8], n: usize) -> Result<u64> {
    width(b, n)?;
    if n > 8 {
        return Err("integer width");
    }
    Ok(b.iter().fold(0, |v, c| (v << 8) | u64::from(*c)))
}
#[derive(Clone)]
struct Field {
    kind: u8,
    capacity: usize,
}
fn schema(data: &[u8]) -> Result<Vec<Field>> {
    let fields = record(data, b"schema", None)?;
    if !(5..=19).contains(&fields.len()) {
        return Err("schema arity");
    }
    let n = uint(fields[0], 1)? as usize;
    if !(2..=16).contains(&n) || fields.len() != n + 3 {
        return Err("field count");
    }
    let did = uint(fields[1], 1)? as usize;
    let version = uint(fields[2], 1)? as usize;
    if did == version || !(1..=n).contains(&did) || !(1..=n).contains(&version) {
        return Err("schema indices");
    }
    let mut names = Vec::new();
    let mut out = Vec::new();
    let mut used = 0;
    for raw in &fields[3..] {
        let f = record(raw, b"field", Some(3))?;
        if f[0].is_empty() || f[0].len() > 64 || !f[0].is_ascii() || names.contains(&f[0]) {
            return Err("field name");
        }
        names.push(f[0]);
        let kind = uint(f[1], 1)? as u8;
        let capacity = uint(f[2], 2)? as usize;
        let min = match kind {
            0 => 0,
            1 => 1,
            2 => 8,
            _ => return Err("field type"),
        };
        used += 2 + capacity;
        if capacity < min || used > 1024 {
            return Err("capacity");
        }
        out.push(Field { kind, capacity });
    }
    if out[did - 1].kind != 0
        || out[did - 1].capacity < 171
        || out[version - 1].kind != 0
        || out[version - 1].capacity < 56
    {
        return Err("designated capacities");
    }
    Ok(out)
}
fn attributes(fs: &[Field], data: &[u8]) -> Result<()> {
    width(data, 1024)?;
    let mut offset = 0;
    for f in fs {
        let end = offset + 2 + f.capacity;
        let cell = &data[offset..end];
        let n = uint(&cell[..2], 2)? as usize;
        if n > f.capacity || cell[2 + n..].iter().any(|b| *b != 0) {
            return Err("attribute padding");
        }
        let payload = &cell[2..2 + n];
        match f.kind {
            1 if payload != [0] && payload != [1] => return Err("boolean"),
            2 if n != 8 => return Err("uint64"),
            _ => {}
        }
        offset = end;
    }
    if data[offset..].iter().any(|b| *b != 0) {
        return Err("tail padding");
    }
    Ok(())
}
struct Parameters<'a> {
    raw: &'a [u8],
    reference: &'a [u8],
    namespace: &'a [u8],
    issuer: &'a [u8],
    schema: Vec<Field>,
    metadata: Vec<u8>,
}
fn parameters(raw: &[u8]) -> Result<Parameters<'_>> {
    let p = record(raw, b"parameters", Some(6))?;
    if p[0] != SUITE {
        return Err("suite");
    }
    width(p[2], 32)?;
    width(p[3], 1952)?;
    width(p[4], 1952)?;
    let r = record(p[1], b"iref", Some(3))?;
    if r[0].is_empty() || r[0].len() > 256 || r[1].is_empty() || r[1].len() > 256 || r[2] != p[5] {
        return Err("issuer/schema");
    }
    let s = schema(p[5])?;
    Ok(Parameters {
        raw,
        reference: p[1],
        namespace: p[2],
        issuer: p[3],
        schema: s,
        metadata: encode(b"meta", &[p[1], p[2]]),
    })
}
fn metadata(p: &Parameters<'_>, data: &[u8]) -> Result<()> {
    let m = record(data, b"meta", Some(2))?;
    if m[0] != p.reference || m[1] != p.namespace {
        return Err("metadata instance");
    }
    Ok(())
}
fn binding<'a>(p: &Parameters<'_>, data: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
    let b = record(data, b"binding", Some(2))?;
    width(b[0], 48)?;
    attributes(&p.schema, b[1])?;
    Ok((b[0], b[1]))
}
fn opening(p: &Parameters<'_>, b: (&[u8], &[u8]), secret: &[u8], attrs: &[u8]) -> Result<()> {
    width(secret, 32)?;
    attributes(&p.schema, attrs)?;
    mark(36);
    let preimage = encode(b"holder", &[SUITE, &p.metadata, secret]);
    let y = Sha3_384::digest(&preimage);
    mark(37);
    if &y[..] != b.0 || attrs != b.1 {
        return Err("binding opening");
    }
    Ok(())
}
fn rid(data: &[u8]) -> Result<()> {
    if uint(data, 4)? >= (1 << 20) {
        Err("rid domain")
    } else {
        Ok(())
    }
}
fn enrol(p: &Parameters<'_>, statement: &[u8], secret: &[u8]) -> Result<()> {
    let s = record(statement, b"enrol-statement", Some(7))?;
    if s[0] != p.raw {
        return Err("expected instance");
    }
    metadata(p, s[1])?;
    attributes(&p.schema, s[2])?;
    rid(s[3])?;
    let b = binding(p, s[4])?;
    width(s[5], 32)?;
    let state = record(s[6], b"rstate", Some(4))?;
    if state[0] != p.namespace {
        return Err("state namespace");
    }
    width(state[1], 8)?;
    width(state[2], 48)?;
    width(state[3], 3309)?;
    opening(p, b, secret, s[2])
}
fn cred_valid(p: &Parameters<'_>, encoded: &[u8], secret: &[u8]) -> Result<()> {
    mark(33);
    let c = record(encoded, b"credential", Some(5))?;
    let cert = record(c[0], b"certificate", Some(2))?;
    let b = binding(p, cert[0])?;
    width(cert[1], 3309)?;
    attributes(&p.schema, c[1])?;
    rid(c[2])?;
    if !c[3].is_empty() {
        return Err("nonempty auxiliary");
    }
    metadata(p, c[4])?;
    mark(34);
    mark(35);
    opening(p, b, secret, c[1])?;
    mark(38);
    mark(39);
    let message = encode(b"cred", &[SUITE, &p.metadata, cert[0], c[2]]);
    mark(40);
    mldsa::verify(p.issuer, &message, cert[1], b"PQ-DID/credential/v1")
}
/// Successful result is exactly the authorised public journal. Invalid inputs fail.
pub fn evaluate(operation: &[u8], public: &[u8], private: &[u8]) -> Result<Vec<u8>> {
    mark(30);
    if public.len() > MAX_PUBLIC || private.len() > MAX_PRIVATE {
        return Err("input limit");
    }
    let x = record(public, b"r0-statement", Some(5))?;
    if x[0] != PROFILE || x[1] != operation {
        return Err("profile/operation");
    }
    width(x[3], 32)?;
    mark(31);
    let pp = parameters(x[2])?;
    mark(32);
    match operation {
        b"enrol" => enrol(&pp, x[4], private)?,
        b"cred-valid" => {
            metadata(&pp, x[4])?;
            let w = record(private, b"r0-credential-witness", Some(2))?;
            cred_valid(&pp, w[0], w[1])?;
        }
        _ => return Err("unknown operation"),
    }
    mark(100);
    let journal = encode(b"r0-result", &[PROFILE, operation, public]);
    mark(101);
    Ok(journal)
}
