"""Add diagnostic-only phase markers to a copied original relation, preserving its work."""

import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
p = root / "relation/Cargo.toml"
p.write_text(
    p.read_text()
    + """\n[features]
diagnostics = ["dep:risc0-zkvm"]
components = []

[dependencies.risc0-zkvm]
version = "=3.0.6"
default-features = false
features = ["std", "disable-dev-mode"]
optional = true
"""
)
p = root / "relation/src/lib.rs"
s = p.read_text().replace(
    "pub mod mldsa;", "pub mod mldsa;\npub mod diagnostic;\nuse diagnostic::mark;"
)
s = s.replace(
    '    let preimage = encode(b"holder",', '    mark(36);\n    let preimage = encode(b"holder",'
).replace("    if &y[..] != b.0", "    mark(37);\n    if &y[..] != b.0")
s = s.replace(
    '    let c = record(encoded, b"credential",',
    '    mark(33);\n    let c = record(encoded, b"credential",',
)
s = s.replace(
    "    opening(p, b, secret, c[1])?;",
    "    mark(34);\n    mark(35);\n    opening(p, b, secret, c[1])?;\n    mark(38);\n    mark(39);",
)
s = s.replace("    mldsa::verify(p.issuer,", "    mark(40);\n    mldsa::verify(p.issuer,")
s = s.replace("    if public.len() > MAX_PUBLIC", "    mark(30);\n    if public.len() > MAX_PUBLIC")
s = s.replace(
    "    let pp = parameters(x[2])?;",
    "    mark(31);\n    let pp = parameters(x[2])?;\n    mark(32);",
)
s = s.replace(
    '    Ok(encode(b"r0-result", &[PROFILE, operation, public]))',
    "    mark(100);\n"
    '    let journal = encode(b"r0-result", &[PROFILE, operation, public]);\n    mark(101);\n'
    "    Ok(journal)",
)
p.write_text(s)
p = root / "relation/src/mldsa.rs"
s = p.read_text().replace("use crate::Result;", "use crate::{Result, diagnostic::mark};")
s = s.replace("    if pk.len() != 1952", "    mark(50);\n    if pk.len() != 1952")
s = s.replace("    let mut t1 = [[0; N]; K];", "    mark(51);\n    let mut t1 = [[0; N]; K];")
s = s.replace(
    "    let mut response = [[0; N]; L];", "    mark(52);\n    let mut response = [[0; N]; L];"
)
s = s.replace("    let bytes = &sig[3248..];", "    mark(53);\n    let bytes = &sig[3248..];")
s = s.replace(
    "    // Match the reference schedule:", "    mark(54);\n    // Match the reference schedule:"
)
s = s.replace("    let mut matrix = vec!", "    mark(60);\n    let mut matrix = vec!")
s = s.replace(
    "            let mut seed = pk[..32].to_vec();",
    "            mark(1000 + (row*5+column) as u32*4);\n"
    "            let mut seed = pk[..32].to_vec();",
)
s = s.replace(
    "            let bytes = shake(128, &seed, 1026);",
    "            let bytes = shake(128, &seed, 1026);\n"
    "            mark(1001 + (row*5+column) as u32*4);",
)
s = s.replace(
    "                limit: 1026,\n            })?;",
    "                limit: 1026,\n"
    "            })?;\n            mark(1002 + (row*5+column) as u32*4);",
)
s = s.replace(
    "    let tr = shake(256, pk, 64);",
    "    mark(61);\n    mark(70);\n    let tr = shake(256, pk, 64);\n    mark(71);",
)
s = s.replace(
    "    let bytes = shake(256, &sig[..48], 256);",
    "    mark(72);\n    mark(73);\n    let bytes = shake(256, &sig[..48], 256);\n    mark(74);",
)
s = s.replace(
    "    let z = zetas();\n    let zh",
    "    mark(75);\n    mark(80);\n    let z = zetas();\n    mark(81);\n    let zh",
)
s = s.replace("    let mut az = [[0; N]; K];", "    mark(82);\n    let mut az = [[0; N]; K];")
s = s.replace(
    "    let ch = ntt(&challenge, &z);",
    "    mark(83);\n    let ch = ntt(&challenge, &z);\n    mark(84);",
)
s = s.replace(
    "    let mut w1 = Vec::with_capacity(768);",
    "    mark(85);\n    let mut w1 = Vec::with_capacity(768);",
)
s = s.replace(
    "    for row in 0..K {\n        let a =",
    "    for row in 0..K {\n        mark(2000+row as u32*3);\n        let a =",
)
s = s.replace(
    "        let w = inv_ntt(&a, &z);",
    "        let w = inv_ntt(&a, &z);\n        mark(2001+row as u32*3);",
)
s = s.replace(
    "            w1.push((lo | (hi << 4)) as u8);\n        }",
    "            w1.push((lo | (hi << 4)) as u8);\n        }\n        mark(2002+row as u32*3);",
)
s = s.replace("    let mut pre = mu;", "    mark(95);\n    let mut pre = mu;")
s = s.replace("    if response\n", "    mark(96);\n    mark(97);\n    if response\n")
s = s.replace("    Ok(())\n}\n#[cfg(test)]", "    mark(98);\n    Ok(())\n}\n#[cfg(test)]")
p.write_text(s)
labels = {
    0: "calibration_0",
    1: "calibration_1",
    2: "calibration_2",
    10: "input_start",
    20: "input_done",
    30: "envelope_start",
    31: "parameters_start",
    32: "parameters_done",
    33: "credential_structure_start",
    34: "credential_structure_done",
    35: "opening_start",
    36: "holder_hash_start",
    37: "holder_hash_done",
    38: "opening_done",
    39: "mcred_start",
    40: "mcred_done",
    50: "signature_format_start",
    51: "public_key_decode_start",
    52: "response_decode_start",
    53: "hints_decode_start",
    54: "hints_decode_done",
    60: "matrix_start",
    61: "matrix_done",
    70: "tr_start",
    71: "mu_prepare_start",
    72: "mu_done",
    73: "ball_xof_start",
    74: "ball_sampler_start",
    75: "ball_done",
    80: "zetas_start",
    81: "response_ntt_start",
    82: "matrix_vector_start",
    83: "challenge_ntt_start",
    84: "public_key_ntt_start",
    85: "inverse_hint_start",
    95: "final_hash_start",
    96: "final_hash_done",
    97: "norm_check_start",
    98: "signature_done",
    100: "journal_prepare_start",
    101: "journal_ready",
    102: "journal_committed",
}
for i in range(30):
    for offset, label in enumerate(["xof_start", "sampler_start", "sampler_done"]):
        labels[1000 + i * 4 + offset] = f"matrix_{i:02d}_{label}"
for i in range(6):
    for offset, label in enumerate(["inverse_start", "hints_start", "hints_done"]):
        labels[2000 + i * 3 + offset] = f"row_{i}_{label}"
(root / "evidence/phase_labels.json").write_text(json.dumps(labels, indent=2) + "\n")
p = root / "methods/guest/Cargo.toml"
p.write_text(
    p.read_text()
    + """\n[features]
diagnostics = ["pqdid-r0-relation/diagnostics"]
components = ["pqdid-r0-relation/components"]
"""
)
p = root / "methods/guest/src/lib.rs"
s = (
    p.read_text()
    .replace(
        "    let public =",
        "    for id in 0..3 { pqdid_r0_relation::diagnostic::mark(id); }\n"
        "    pqdid_r0_relation::diagnostic::mark(10);\n    let public =",
    )
    .replace("    let journal =", "    pqdid_r0_relation::diagnostic::mark(20);\n    let journal =")
    .replace(
        "    env::commit_slice(&journal);",
        "    env::commit_slice(&journal);\n    pqdid_r0_relation::diagnostic::mark(102);",
    )
)
p.write_text(s)
