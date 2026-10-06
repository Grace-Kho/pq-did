use anyhow::{anyhow, bail, ensure, Context, Result};
use bincode::Options;
use pqdid_r0_relation as relation;
use risc0_binfmt::Digestible;
use risc0_zkvm::{
    compute_image_id, Digest, Executor, ExecutorEnv, ExitCode, ExternalProver, InnerReceipt,
    MaybePruned, Prover, ProverOpts, Receipt, VerifierContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as ShaDigest, Sha256};
use std::{fs, path::Path, time::Instant};
const MAX_RECEIPT: u64 = 10 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Registered {
    operation: String,
    image: [u32; 8],
    elf: String,
    elf_sha256: String,
    verifier_parameters: String,
    control_root: String,
}
fn ctx() -> VerifierContext {
    VerifierContext::default().with_dev_mode(false)
}
fn params() -> (String, String) {
    let c = ctx();
    let p = c.succinct_verifier_parameters.as_ref().unwrap();
    (
        p.digest::<risc0_zkvm::sha::Impl>().to_string(),
        p.control_root.to_string(),
    )
}
fn expected(op: &str, public: &[u8]) -> Result<Vec<u8>> {
    let f = relation::record(public, b"r0-statement", Some(5)).map_err(|s| anyhow!(s))?;
    ensure!(
        f[0] == relation::PROFILE && f[1] == op.as_bytes(),
        "public operation/profile mismatch"
    );
    ensure!(f[3].len() == 32, "context length");
    Ok(relation::encode(
        b"r0-result",
        &[relation::PROFILE, op.as_bytes(), public],
    ))
}
fn bytes(path: &str, max: u64) -> Result<Vec<u8>> {
    ensure!(fs::metadata(path)?.len() <= max, "input size ceiling");
    Ok(fs::read(path)?)
}
fn cases() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read("fixtures/cases.json")?)?)
}
fn registered(op: &str) -> Result<Registered> {
    let rs: Vec<Registered> = serde_json::from_slice(&fs::read("fixtures/public/registry.json")?)?;
    rs.into_iter()
        .find(|r| r.operation == op)
        .context("unregistered operation")
}
fn local() -> ExternalProver {
    ExternalProver::new(
        "local-cpu-pinned-3.0.6",
        Path::new("tooling/sdk-3.0.6/r0vm"),
    )
}
fn read_case(c: &Value) -> Result<(String, Vec<u8>, Vec<u8>)> {
    Ok((
        c["operation"].as_str().unwrap().to_owned(),
        bytes(c["public"].as_str().unwrap(), relation::MAX_PUBLIC as u64)?,
        bytes(c["private"].as_str().unwrap(), relation::MAX_PRIVATE as u64)?,
    ))
}
fn input_env<'a>(public: &[u8], private: &[u8]) -> Result<ExecutorEnv<'a>> {
    let mut input = Vec::new();
    input.extend_from_slice(&(public.len() as u32).to_be_bytes());
    input.extend_from_slice(public);
    input.extend_from_slice(&(private.len() as u32).to_be_bytes());
    input.extend_from_slice(private);
    Ok(ExecutorEnv::builder()
        .write_slice(&input)
        .segment_limit_po2(16)
        .session_limit(Some(1 << 22))
        .build()?)
}
fn codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_RECEIPT)
        .reject_trailing_bytes()
}
fn verify_receipt(r: &Receipt, op: &str, public: &[u8], reg: &Registered) -> Result<()> {
    ensure!(reg.operation == op, "registry kind mismatch");
    let (v, c) = params();
    ensure!(
        reg.verifier_parameters == v && reg.control_root == c,
        "untrusted verifier parameters"
    );
    let inner = match &r.inner {
        InnerReceipt::Succinct(s) => s,
        _ => bail!("requires Succinct STARK"),
    };
    ensure!(
        inner.hashfn == "poseidon2" && inner.verifier_parameters.to_string() == v,
        "receipt parameters/hash mismatch"
    );
    ensure!(
        matches!(inner.claim, MaybePruned::Pruned(_)),
        "require pruned claim"
    );
    ensure!(
        inner.control_inclusion_proof.digests.len() == 8
            && inner.control_inclusion_proof.index < 256,
        "control path shape"
    );
    ensure!(
        r.journal.bytes == expected(op, public)?,
        "journal binding mismatch"
    );
    r.verify_with_context(&ctx(), Digest::from(reg.image))?;
    Ok(())
}
fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let command = a.get(1).context("command required")?;
    match command.as_str() {
        "register" => {
            let (v, c) = params();
            let mut rows = Vec::new();
            for (op, file) in [("enrol", "enrol"), ("cred-valid", "cred_valid")] {
                let user_elf = fs::read(format!(
                    "target/guest/riscv32im-risc0-zkvm-elf/release/{file}"
                ))?;
                let b =
                    risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF)
                        .encode();
                let elf = format!("target/{file}.bin");
                fs::write(&elf, &b)?;
                let id = compute_image_id(&b)?;
                rows.push(Registered {
                    operation: op.into(),
                    image: id.as_words().try_into().unwrap(),
                    elf,
                    elf_sha256: format!("{:x}", Sha256::digest(&b)),
                    verifier_parameters: v.clone(),
                    control_root: c.clone(),
                });
            }
            fs::write(
                "fixtures/public/registry.json",
                serde_json::to_vec_pretty(&rows)?,
            )?;
            println!("{}", serde_json::to_string(&rows)?);
        }
        "native-check" => {
            let cs = cases()?;
            let mut result = Vec::new();
            for c in cs["cases"].as_array().unwrap() {
                let (op, p, w) = read_case(c)?;
                let output = relation::evaluate(op.as_bytes(), &p, &w);
                let ok = output.is_ok();
                ensure!(
                    ok == c["reference_expected"].as_bool().unwrap(),
                    "Rust/reference mismatch {}",
                    c["name"]
                );
                if let Ok(j) = output {
                    ensure!(j == expected(&op, &p)?, "native journal");
                }
                result.push(json!({"name":c["name"],"matched":true}));
            }
            for c in cs["mldsa_tests"].as_array().unwrap() {
                let b = bytes(c["path"].as_str().unwrap(), 65536)?;
                let f = relation::record(&b, b"r0-mldsa-test", Some(4)).map_err(|e| anyhow!(e))?;
                let ok = relation::mldsa::verify(f[0], f[1], f[2], f[3]).is_ok();
                ensure!(ok == c["expected"].as_bool().unwrap(), "context mismatch");
                result.push(json!({"name":c["name"],"matched":true}));
            }
            fs::write(
                "evidence/native_comparisons.json",
                serde_json::to_vec_pretty(&result)?,
            )?;
            println!("{} native comparisons passed", result.len());
        }
        "reject-check" => {
            let reg = registered("enrol")?;
            let public = fs::read("fixtures/public/enrol-alpha-42.bin")?;
            let journal = expected("enrol", &public)?;
            let claim = risc0_zkvm::ReceiptClaim::ok(Digest::ZERO, vec![]);
            let composite: risc0_zkvm::CompositeReceipt = serde_json::from_value(
                json!({"segments":[],"assumption_receipts":[],"verifier_parameters":Digest::ZERO}),
            )?;
            let variants = [
                (
                    "Fake",
                    InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(claim)),
                ),
                ("Composite", InnerReceipt::Composite(composite)),
                (
                    "Groth16",
                    InnerReceipt::Groth16(risc0_zkvm::Groth16Receipt::new(
                        vec![],
                        MaybePruned::Pruned(Digest::ZERO),
                        Digest::ZERO,
                    )),
                ),
            ];
            let mut rows = Vec::new();
            for (label, inner) in variants {
                let receipt = Receipt::new(inner, journal.clone());
                let result = verify_receipt(&receipt, "enrol", &public, &reg);
                ensure!(result.is_err());
                ensure!(format!("{:#}", result.unwrap_err()).contains("requires Succinct STARK"));
                rows.push(label);
            }
            for n in [0, 1, 4, 8, 32, 128] {
                ensure!(codec().deserialize::<Receipt>(&vec![255; n]).is_err());
            }
            fs::write(
                "evidence/receipt_policy_rejections.json",
                serde_json::to_vec_pretty(
                    &json!({"rejected_variants":rows,"malformed_containers":6,"actual_proofs_used":0,"note":"synthetic invalid input fixtures, no development proving"}),
                )?,
            )?;
            println!("3 forbidden variants and 6 malformed containers rejected");
        }
        "execute-check" => {
            let cs = cases()?;
            let mut rows = Vec::new();
            let mut failures = 0;
            for c in cs["cases"].as_array().unwrap() {
                let (op, p, w) = read_case(c)?;
                let reg = registered(&op)?;
                let elf = fs::read(&reg.elf)?;
                let start = Instant::now();
                let output = local().execute(input_env(&p, &w)?, &elf);
                let row = match output {
                    Ok(s) => {
                        let valid = s.exit_code == ExitCode::Halted(0);
                        let matched = valid == c["reference_expected"].as_bool().unwrap()
                            && (!valid || s.journal.bytes == expected(&op, &p)?);
                        if !matched {
                            failures += 1;
                        }
                        json!({"name":c["name"],"matched":matched,"accepted":valid,"cycles":s.cycles(),"segments":s.segments.len(),"segment_po2":s.segments.iter().map(|x|x.po2).collect::<Vec<_>>(),"seconds":start.elapsed().as_secs_f64(),"exit_code":format!("{:?}",s.exit_code)})
                    }
                    Err(e) => {
                        let reason = format!("{e:#}");
                        let recognised = reason.contains("relation rejected")
                            || reason.contains("input exceeds bound");
                        let matched = recognised && !c["reference_expected"].as_bool().unwrap();
                        if !matched {
                            failures += 1;
                        }
                        json!({"name":c["name"],"matched":matched,"accepted":false,"error":reason,"seconds":start.elapsed().as_secs_f64()})
                    }
                };
                rows.push(row);
                fs::write(
                    "evidence/guest_comparisons.json",
                    serde_json::to_vec_pretty(&rows)?,
                )?;
                if failures > 0 {
                    bail!("guest/reference or execution failure; see saved comparisons");
                }
            }
            println!("{} guest comparisons passed", rows.len());
        }
        "prove" => {
            let name = a.get(2).context("fixture required")?;
            let out = a.get(3).context("receipt path required")?;
            ensure!(!Path::new(out).exists(), "do not overwrite receipt");
            let evidence: Vec<Value> =
                serde_json::from_slice(&fs::read("evidence/guest_comparisons.json")?)?;
            let cs = cases()?;
            ensure!(
                evidence.len() == cs["cases"].as_array().unwrap().len()
                    && evidence.iter().all(|x| x["matched"] == true),
                "execution gate incomplete"
            );
            let c = cs["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["name"] == name.as_str())
                .context("fixture not found")?;
            ensure!(c["reference_expected"] == true, "positive fixture required");
            let (op, p, w) = read_case(c)?;
            let reg = registered(&op)?;
            let elf = fs::read(&reg.elf)?;
            ensure!(
                format!("{:x}", Sha256::digest(&elf)) == reg.elf_sha256,
                "ELF changed"
            );
            let start = Instant::now();
            let mut info = local().prove_with_ctx(
                input_env(&p, &w)?,
                &ctx(),
                &elf,
                &ProverOpts::succinct().with_dev_mode(false),
            )?;
            let proving_seconds = start.elapsed().as_secs_f64();
            let s = match &mut info.receipt.inner {
                InnerReceipt::Succinct(s) => s,
                _ => bail!("unexpected receipt mode"),
            };
            s.claim = MaybePruned::Pruned(s.claim.digest::<risc0_zkvm::sha::Impl>());
            let seal_bytes = s.seal.len() * 4;
            let control = s.control_id.to_string();
            let control_path = json!({"index":s.control_inclusion_proof.index,"digests":s.control_inclusion_proof.digests.iter().map(|d|d.to_string()).collect::<Vec<_>>()});
            let t = Instant::now();
            verify_receipt(&info.receipt, &op, &p, &reg)?;
            let self_verify_seconds = t.elapsed().as_secs_f64();
            let encoded = codec().serialize(&info.receipt)?;
            ensure!(encoded.len() as u64 <= MAX_RECEIPT, "receipt size");
            fs::write(out, &encoded)?;
            let row = json!({"fixture":name,"operation":op,"receipt":out,"mode":"Succinct","hash_suite":"poseidon2","image":reg.image,"verifier_parameters":reg.verifier_parameters,"stats":info.stats,"pipeline_including_recursion_seconds":proving_seconds,"self_verify_seconds":self_verify_seconds,"journal_bytes":info.receipt.journal.bytes.len(),"seal_bytes":seal_bytes,"serialized_receipt_bytes":encoded.len(),"control_id":control,"control_path":control_path,"separate_proving_recursion_times":"not exposed by this local IPC call"});
            fs::write(format!("{out}.json"), serde_json::to_vec_pretty(&row)?)?;
            println!("{row}");
        }
        "verify" | "adversarial" => {
            ensure!(
                fs::read_dir("fixtures/private").is_err()
                    && fs::read_dir("../../tests/fixtures").is_err(),
                "private fixtures must be inaccessible"
            );
            let op = a.get(2).context("operation")?;
            let public = bytes(a.get(3).context("public path")?, 65536)?;
            let encoded = bytes(a.get(4).context("receipt")?, MAX_RECEIPT)?;
            let r: Receipt = codec().deserialize(&encoded)?;
            ensure!(codec().serialize(&r)? == encoded, "noncanonical encoding");
            let reg = registered(op)?;
            let t = Instant::now();
            verify_receipt(&r, op, &public, &reg)?;
            let mut tests = Vec::new();
            if command == "adversarial" {
                let mut changed = r.clone();
                changed.journal.bytes[0] ^= 1;
                ensure!(verify_receipt(&changed, op, &public, &reg).is_err());
                tests.push("journal");
                let mut p = public.clone();
                *p.last_mut().unwrap() ^= 1;
                ensure!(verify_receipt(&r, op, &p, &reg).is_err());
                tests.push("public statement");
                let fields =
                    relation::record(&public, b"r0-statement", Some(5)).map_err(|e| anyhow!(e))?;
                let mut context = fields[3].to_vec();
                context[0] ^= 1;
                let p = relation::encode(
                    b"r0-statement",
                    &[fields[0], fields[1], fields[2], &context, fields[4]],
                );
                ensure!(verify_receipt(&r, op, &p, &reg).is_err());
                tests.push("public context");
                let mut badreg = Registered {
                    image: reg.image,
                    operation: reg.operation.clone(),
                    elf: reg.elf.clone(),
                    elf_sha256: reg.elf_sha256.clone(),
                    verifier_parameters: reg.verifier_parameters.clone(),
                    control_root: reg.control_root.clone(),
                };
                badreg.image[0] ^= 1;
                ensure!(verify_receipt(&r, op, &public, &badreg).is_err());
                tests.push("expected image");
                ensure!(verify_receipt(
                    &r,
                    if op == "enrol" { "cred-valid" } else { "enrol" },
                    &public,
                    &reg
                )
                .is_err());
                tests.push("operation");
                let mut changed = r.clone();
                if let InnerReceipt::Succinct(s) = &mut changed.inner {
                    s.seal[0] ^= 1;
                }
                ensure!(verify_receipt(&changed, op, &public, &reg).is_err());
                tests.push("seal");
                let mut changed = r.clone();
                if let InnerReceipt::Succinct(s) = &mut changed.inner {
                    s.hashfn = "sha-256".into();
                }
                ensure!(verify_receipt(&changed, op, &public, &reg).is_err());
                tests.push("hash suite");
                let mut trailing = encoded.clone();
                trailing.push(0);
                ensure!(codec().deserialize::<Receipt>(&trailing).is_err());
                tests.push("trailing bytes");
            }
            println!(
                "{}",
                json!({"verified":true,"operation":op,"seconds":t.elapsed().as_secs_f64(),"rejection_tests":tests,"private_input_available":false})
            );
        }
        _ => bail!("unknown command"),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
