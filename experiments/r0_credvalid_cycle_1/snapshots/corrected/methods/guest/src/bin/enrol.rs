#![no_main]
risc0_zkvm::guest::entry!(main);
fn main() {
    pqdid_r0_guests::run(b"enrol");
}
