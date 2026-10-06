//! Local execution of one immutable guest; no proving or guest-build command.
use anyhow::{ensure, Context, Result};
use pqdid_r0_relation as relation;
use risc0_zkvm::{compute_image_id, ApiClient, Asset, AssetRequest, ExecutorEnv, ExitCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::Path,
    time::Instant,
};

fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn read(path: &str, max: u64) -> Result<Vec<u8>> {
    ensure!(fs::metadata(path)?.len() <= max, "input ceiling");
    Ok(fs::read(path)?)
}
fn json_file(path: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&read(path, 4 << 20)?)?)
}
fn save(path: &str, value: &Value) -> Result<()> {
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}
struct BoundedFile {
    file: fs::File,
    size: usize,
}
impl BoundedFile {
    fn create(path: &str) -> Result<Self> {
        Ok(Self {
            file: fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
            size: 0,
        })
    }
}
impl Write for BoundedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.size + bytes.len() > 65536 {
            return Err(io::Error::other("diagnostic stream cap"));
        }
        let n = self.file.write(bytes)?;
        self.size += n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 3 && args[1] == "run",
        "execution-only command required"
    );
    let name = args[2].as_str();
    let slot: u32 = std::env::var("R0_EXECUTION_SLOT")?.parse()?;
    ensure!(
        (slot == 1 && name == "valid") || (slot == 2 && name == "negative"),
        "run sequence"
    );
    if slot == 2 {
        let first = json_file("evidence/valid.result.json")?;
        ensure!(
            first["status"] == "completed"
                && first["accepted"] == true
                && first["journal_matches_expected"] == true,
            "valid execution gate"
        );
        let reference = json_file("evidence/negative-reference.json")?;
        ensure!(
            reference["expected_acceptance"] == false
                && reference["cryptographic_verifier_called"] == true,
            "negative reference gate"
        );
    }
    let config = json_file("config.json")?;
    ensure!(
        config["session_limit_user_cycles"] == 16777216 && config["segment_limit_po2"] == 16,
        "fixed configuration"
    );
    let reg = json_file("artifacts/corrected-plain.json")?;
    ensure!(reg["features"] == "none", "uninstrumented guest required");
    let program = read(reg["program"].as_str().context("programme path")?, 8 << 20)?;
    ensure!(
        sha(&program) == reg["program_sha256"]
            && compute_image_id(&program)?.to_string() == reg["image"],
        "immutable image changed"
    );
    let fixture = if slot == 1 {
        "cred-alpha-42"
    } else {
        "cred-rid-changed"
    };
    let cases = json_file("fixtures/cases.json")?;
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == fixture)
        .context("fixture")?;
    let public = read(case["public"].as_str().unwrap(), 65536)?;
    let private = read(case["private"].as_str().unwrap(), 16384)?;
    ensure!(
        sha(&public) == case["public_SHA256"] && sha(&private) == case["private_fixture_SHA256"],
        "fixture changed"
    );
    let expected = read("fixtures/expected-public-journal.bin", 65536)?;
    ensure!(
        expected == relation::encode(b"r0-result", &[relation::PROFILE, b"cred-valid", &public]),
        "independent journal framing"
    );
    let mut input = Vec::new();
    for value in [&public, &private] {
        input.extend_from_slice(&(value.len() as u32).to_be_bytes());
        input.extend_from_slice(value);
    }
    let env = ExecutorEnv::builder()
        .write_slice(&input)
        .stderr(BoundedFile::create(&format!("evidence/{name}.stderr"))?)
        .stdout(BoundedFile::create(&format!("evidence/{name}.stdout"))?)
        .segment_limit_po2(16)
        .session_limit(Some(1 << 24))
        .build()?;
    let mut records = BoundedFile::create(&format!("evidence/{name}.segments.jsonl"))?;
    let mut count = 0_u64;
    let mut user = 0_u64;
    let mut capacity = 0_u64;
    let mut histogram = std::collections::BTreeMap::<u32, u64>::new();
    let client = ApiClient::new_sub_process(Path::new(
        "../r0_succinct_feasibility_1/tooling/sdk-3.0.6/r0vm",
    ))?;
    let start = Instant::now();
    let outcome = client.execute(&env, Asset::Inline(program.into()), AssetRequest::Inline, |s, _private_asset| {
        count += 1; user += s.cycles as u64; capacity += 1_u64 << s.po2;
        *histogram.entry(s.po2).or_default() += 1;
        // Preserve the existing individual-record bound; remaining segments use
        // constant-size aggregate counters, not a larger diagnostic allocation.
        if count <= 256 { writeln!(records, "{}", json!({"index":count-1,"user_cycles":s.cycles,"po2":s.po2}))?; }
        save(&format!("evidence/{name}.progress.json"), &json!({
            "completed_segments":count,"completed_user_cycles":user,"padded_capacity":capacity,
            "other_capacity":capacity-user,"retained_segment_records":count.min(256),
            "segment_po2_histogram":histogram,"last_phase":"unknown: unchanged uninstrumented guest"
        }))?;
        Ok(())
    });
    let mut result = json!({"package":"R0-CREDVALID-EXEC24-1","slot":slot,"fixture":fixture,
        "image":reg["image"],"elf_sha256":reg["elf_sha256"],"program_sha256":reg["program_sha256"],
        "config":config,"execution_seconds":start.elapsed().as_secs_f64(),
        "completed_segments":count,"completed_segment_user_cycles":user,"padded_segment_capacity":capacity,
        "other_segment_capacity":capacity-user,"segment_po2_histogram":histogram,
        "counter_note":"SDK user cycles; separate paging/system/reserved counts unavailable through Execute IPC",
        "expected_acceptance":slot==1,"expected_public_journal_sha256":sha(&expected),
        "expected_public_journal_bytes":expected.len(),"actual_public_journal_sha256":null,
        "actual_public_journal_bytes":null,"returned_session":false,"accepted":false,
        "journal_matches_expected":false,"user_cycles":null,"proof_attempts":0,"receipt_generated":false});
    match outcome {
        Ok(session) => {
            result["returned_session"] = json!(true);
            result["exit_code"] = json!(format!("{:?}", session.exit_code));
            result["user_cycles"] = json!(session.cycles());
            result["margin_below_cap"] = json!(16777216_u64.saturating_sub(session.cycles()));
            result["actual_public_journal_sha256"] = json!(sha(&session.journal.bytes));
            result["actual_public_journal_bytes"] = json!(session.journal.bytes.len());
            result["journal_matches_expected"] = json!(session.journal.bytes == expected);
            result["accepted"] = json!(
                session.exit_code == ExitCode::Halted(0) && session.journal.bytes == expected
            );
            result["status"] = json!(if result["accepted"] == true {
                "completed"
            } else {
                "unexpected_guest_output"
            });
            fs::write(
                format!("evidence/{name}.public-journal.bin"),
                &session.journal.bytes,
            )?;
        }
        Err(error) => {
            let reason = format!("{error:#}");
            result["status"] = json!(if reason.starts_with("Session limit exceeded:") {
                "cycle_capped"
            } else if reason.contains("Guest panicked:") && reason.contains("relation rejected") {
                "credential_rejected"
            } else {
                "execution_error"
            });
            result["error"] = json!(reason);
            result["last_phase"] = json!("unknown: unchanged uninstrumented guest");
        }
    }
    save(&format!("evidence/{name}.result.json"), &result)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
