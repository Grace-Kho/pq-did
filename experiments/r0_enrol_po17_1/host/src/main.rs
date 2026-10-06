use anyhow::{anyhow, bail, ensure, Context, Result};
use bincode::Options;
use pqdid_r0_relation as relation;
use risc0_binfmt::Digestible;
use risc0_zkvm::{
    compute_image_id, ApiClient, Asset, AssetRequest, Digest, ExecutorEnv, ExitCode,
    ExternalProver, InnerReceipt, MaybePruned, Prover, ProverOpts, Receipt, VerifierContext,
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
        Path::new("../r0_succinct_feasibility_1/tooling/sdk-3.0.6/r0vm"),
    )
}
fn read_case(c: &Value) -> Result<(String, Vec<u8>, Vec<u8>)> {
    Ok((
        c["operation"].as_str().unwrap().to_owned(),
        bytes(c["public"].as_str().unwrap(), relation::MAX_PUBLIC as u64)?,
        bytes(c["private"].as_str().unwrap(), relation::MAX_PRIVATE as u64)?,
    ))
}
fn input_env<'a>(op: &str, public: &[u8], private: &[u8]) -> Result<ExecutorEnv<'a>> {
    ensure!(op == "enrol", "enrolment only");
    let mut input = Vec::new();
    input.extend_from_slice(&(public.len() as u32).to_be_bytes());
    input.extend_from_slice(public);
    input.extend_from_slice(&(private.len() as u32).to_be_bytes());
    input.extend_from_slice(private);
    Ok(ExecutorEnv::builder()
        .write_slice(&input)
        .segment_limit_po2(17)
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
        "inspect" => {
            let (v, c) = params();
            for op in ["enrol"] {
                let reg = registered(op)?;
                let b = fs::read(&reg.elf)?;
                ensure!(format!("{:x}", Sha256::digest(&b)) == reg.elf_sha256);
                ensure!(compute_image_id(&b)? == Digest::from(reg.image));
                ensure!(reg.verifier_parameters == v && reg.control_root == c);
            }
            for case in cases()?["cases"].as_array().unwrap() {
                let p = fs::read(case["public"].as_str().unwrap())?;
                ensure!(
                    expected(case["operation"].as_str().unwrap(), &p)?
                        == fs::read(case["expected_journal"].as_str().unwrap())?
                );
            }
            println!(
                "{}",
                json!({"identities_and_expected_journals":true,"verifier_parameters":v,"control_root":c,"proofs":0,"host_debug_assertions":cfg!(debug_assertions),"prover_options":ProverOpts::succinct().with_dev_mode(false),"executor_segment_limit_po2":17,"session_limit_user_cycles":4194304})
            );
        }
        "execute" => {
            let ledger: Value = serde_json::from_slice(&fs::read("evidence/run_ledger.json")?)?;
            ensure!(
                ledger["execution_runs"] == 1 && ledger["proof_attempts"] == 0,
                "execution slot"
            );
            ensure!(std::env::var("R0_EXECUTION_SLOT")? == "1", "execution slot");
            let cs = cases()?;
            let c = &cs["cases"][0];
            let (op, p, w) = read_case(c)?;
            ensure!(op == "enrol" && c["name"] == "enrol-alpha-42");
            let reg = registered(&op)?;
            let elf = fs::read(&reg.elf)?;
            ensure!(format!("{:x}", Sha256::digest(&elf)) == reg.elf_sha256);
            ensure!(compute_image_id(&elf)? == Digest::from(reg.image));
            ensure!(format!("{:x}", Sha256::digest(&p)) == c["public_sha256"].as_str().unwrap());
            ensure!(format!("{:x}", Sha256::digest(&w)) == c["private_sha256"].as_str().unwrap());
            let want = fs::read(c["expected_journal"].as_str().unwrap())?;
            ensure!(want == expected(&op, &p)?);
            let client = ApiClient::new_sub_process(Path::new(
                "../r0_succinct_feasibility_1/tooling/sdk-3.0.6/r0vm",
            ))?;
            let mut segments = Vec::new();
            let start = Instant::now();
            let outcome = client.execute(&input_env(&op, &p, &w)?, Asset::Inline(elf.into()), AssetRequest::Inline, |s, _private| {
                ensure!(segments.len() < 256, "segment diagnostic bound");
                segments.push(json!({"index":segments.len(), "user_cycles":s.cycles,"po2":s.po2,"padded_capacity":1_u64 << s.po2}));
                fs::write("evidence/execution.progress.json", serde_json::to_vec_pretty(&segments)?)?;
                Ok(())
            });
            let elapsed = start.elapsed().as_secs_f64();
            let row = match outcome {
                Ok(session) => {
                    let matched = session.journal.bytes == want;
                    let accepted = session.exit_code == ExitCode::Halted(0) && matched;
                    fs::write(
                        "evidence/execution.public-journal.bin",
                        &session.journal.bytes,
                    )?;
                    let padded: u64 = segments
                        .iter()
                        .map(|s| s["padded_capacity"].as_u64().unwrap())
                        .sum();
                    json!({"status":if accepted {"completed"} else {"unexpected_output"},"accepted":accepted,"journal_matches_expected":matched,"user_cycles":session.cycles(),"segments":segments.len(),"segment_records":segments,"padded_capacity":padded,"other_capacity":padded-session.cycles(),"exit_code":format!("{:?}",session.exit_code),"journal_bytes":session.journal.bytes.len(),"journal_sha256":format!("{:x}",Sha256::digest(&session.journal.bytes)),"execution_seconds":elapsed,"system_paging_reserved":"not separately exposed by execute IPC"})
                }
                Err(e) => {
                    json!({"status":"execution_failed","accepted":false,"journal_matches_expected":false,"segments":segments.len(),"segment_records":segments,"error":format!("{e:#}"),"execution_seconds":elapsed})
                }
            };
            fs::write(
                "evidence/execution.result.json",
                serde_json::to_vec_pretty(&row)?,
            )?;
            println!("{row}");
            ensure!(row["accepted"] == true, "execution or journal check failed");
        }
        "prove" => {
            let name = a.get(2).context("fixture required")?;
            let out = a.get(3).context("receipt path required")?;
            ensure!(!Path::new(out).exists(), "do not overwrite receipt");
            let slot: usize = std::env::var("R0_PROOF_SLOT")?.parse()?;
            ensure!(
                slot == 2 && name == "enrol-alpha-42",
                "one enrolment attempt only"
            );
            let ledger: Value = serde_json::from_slice(&fs::read("evidence/run_ledger.json")?)?;
            ensure!(ledger["proof_attempts"] == 1, "count before launch");
            let admission: Value =
                serde_json::from_slice(&fs::read("evidence/admission.result.json")?)?;
            ensure!(
                admission["proof_admitted"] == true,
                "execution admission gate"
            );
            let cs = cases()?;
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
            ensure!(
                compute_image_id(&elf)? == Digest::from(reg.image),
                "image changed"
            );
            ensure!(
                format!("{:x}", Sha256::digest(&p)) == c["public_sha256"].as_str().unwrap(),
                "public changed"
            );
            ensure!(
                format!("{:x}", Sha256::digest(&w)) == c["private_sha256"].as_str().unwrap(),
                "private changed"
            );
            ensure!(
                expected(&op, &p)? == fs::read(c["expected_journal"].as_str().unwrap())?,
                "independent journal mismatch"
            );
            fs::write(
                format!("evidence/attempt{slot}.phase.json"),
                b"{\"phase\":\"execution_segment_proving_recursion_combined\"}\n",
            )?;
            let start = Instant::now();
            let mut info = local().prove_with_ctx(
                input_env(&op, &p, &w)?,
                &ctx(),
                &elf,
                &ProverOpts::succinct().with_dev_mode(false),
            )?;
            fs::write(
                format!("evidence/attempt{slot}.phase.json"),
                b"{\"phase\":\"succinct_returned_self_verification\"}\n",
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
            fs::write(
                format!("evidence/attempt{slot}.phase.json"),
                b"{\"phase\":\"saved_succinct_self_verified\"}\n",
            )?;
            println!("{row}");
        }
        "verify" | "adversarial" => {
            ensure!(
                fs::read_dir("fixtures/private").is_err()
                    && fs::read_dir("../../tests/fixtures").is_err()
                    && fs::read_dir("tmp").is_err()
                    && fs::read_dir("../r0_succinct_proof_1").is_err(),
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
            let row = json!({"verified":true,"operation":op,"seconds":t.elapsed().as_secs_f64(),"rejection_tests":tests,"private_input_available":false});
            fs::write(
                format!("evidence/{command}.result.json"),
                serde_json::to_vec_pretty(&row)?,
            )?;
            println!("{row}");
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
