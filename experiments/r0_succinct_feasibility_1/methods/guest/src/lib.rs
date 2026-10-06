use risc0_zkvm::guest::env;
fn read_bytes(max: usize) -> Vec<u8> {
    let mut len = [0_u8; 4];
    env::read_slice(&mut len);
    let len = u32::from_be_bytes(len) as usize;
    assert!(len <= max, "input exceeds bound");
    let mut data = vec![0; len];
    env::read_slice(&mut data);
    data
}
pub fn run(operation: &[u8]) {
    let public = read_bytes(pqdid_r0_relation::MAX_PUBLIC);
    let private = read_bytes(pqdid_r0_relation::MAX_PRIVATE);
    let journal = pqdid_r0_relation::evaluate(operation, &public, &private)
        .unwrap_or_else(|_| panic!("relation rejected"));
    env::commit_slice(&journal);
}
