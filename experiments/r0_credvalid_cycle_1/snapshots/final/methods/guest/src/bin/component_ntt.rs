#![no_main]
risc0_zkvm::guest::entry!(main);
fn main() {
    use risc0_zkvm::guest::env;
    for id in 0..3 {
        pqdid_r0_relation::diagnostic::mark(id);
    }
    let mut size = [0_u8; 4];
    env::read_slice(&mut size);
    let size = u32::from_be_bytes(size) as usize;
    assert!(size <= 32768);
    let mut payload = vec![0; size];
    env::read_slice(&mut payload);
    pqdid_r0_relation::mldsa::component_ntt(&payload).expect("component mismatch");
    env::commit_slice(b"R0-CREDVALID-CYCLE-1/component-ok");
}
