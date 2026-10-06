//! Unchecked host diagnostics: never a relation input or journal field.
#[cfg(all(feature = "diagnostics", target_os = "zkvm"))]
#[inline(never)]
pub fn mark(id: u32) {
    use std::io::Write;
    let cycle = risc0_zkvm::guest::env::cycle_count();
    let mut record = [0_u8; 16];
    record[..4].copy_from_slice(b"CYC1");
    record[4..8].copy_from_slice(&id.to_le_bytes());
    record[8..].copy_from_slice(&cycle.to_le_bytes());
    risc0_zkvm::guest::env::stderr()
        .write_all(&record)
        .expect("diagnostic output");
}
#[cfg(not(all(feature = "diagnostics", target_os = "zkvm")))]
#[inline(always)]
pub fn mark(_id: u32) {}
