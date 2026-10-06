//! Execution-only diagnostic host. No proving trait/API or receipt operations.
use anyhow::{anyhow, bail, ensure, Context, Result};
use pqdid_r0_relation as relation;
use risc0_zkvm::{compute_image_id, ApiClient, Asset, AssetRequest, ExecutorEnv, ExitCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::Path,
    time::Instant,
};

const BASE: &str = "../r0_succinct_feasibility_1";
#[derive(Serialize, Deserialize)]
struct Registered {
    label: String,
    image: String,
    program: String,
    program_sha256: String,
    elf: String,
    elf_sha256: String,
    features: String,
    source_sha256: Value,
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn bytes(path: &str, max: u64) -> Result<Vec<u8>> {
    ensure!(fs::metadata(path)?.len() <= max, "input ceiling");
    Ok(fs::read(path)?)
}
fn expected(op: &str, public: &[u8]) -> Result<Vec<u8>> {
    let f = relation::record(public, b"r0-statement", Some(5)).map_err(|s| anyhow!(s))?;
    ensure!(
        f[0] == relation::PROFILE && f[1] == op.as_bytes() && f[3].len() == 32,
        "public envelope"
    );
    Ok(relation::encode(
        b"r0-result",
        &[relation::PROFILE, op.as_bytes(), public],
    ))
}
fn cases() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read("fixtures/cases.json")?)?)
}
fn read_case(c: &Value) -> Result<(String, Vec<u8>, Vec<u8>)> {
    Ok((
        c["operation"].as_str().unwrap().into(),
        bytes(c["public"].as_str().unwrap(), 65536)?,
        bytes(c["private"].as_str().unwrap(), 16384)?,
    ))
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
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.size + b.len() > 65536 {
            return Err(io::Error::other("diagnostic stream cap"));
        }
        let n = self.file.write(b)?;
        self.size += n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).context("command")?.as_str() {
        "register" => {
            ensure!(args.len() == 5, "register label elf features");
            let label = &args[2];
            ensure!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "label"
            );
            let user = bytes(&args[3], 8 * 1024 * 1024)?;
            let program =
                risc0_binfmt::ProgramBinary::new(&user, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
            let path = format!("artifacts/{label}.bin");
            ensure!(!Path::new(&path).exists(), "preserve registered artefact");
            fs::write(&path, &program)?;
            let elf = format!("artifacts/{label}.elf");
            fs::write(&elf, &user)?;
            let names = [
                "relation/src/lib.rs",
                "relation/src/mldsa.rs",
                "relation/src/diagnostic.rs",
                "methods/guest/src/lib.rs",
                "relation/Cargo.toml",
                "methods/guest/Cargo.toml",
                "Cargo.lock",
                "methods/guest/Cargo.lock",
            ];
            let mut hashes = serde_json::Map::new();
            for name in names {
                hashes.insert(name.into(), json!(sha(&fs::read(name)?)));
            }
            let reg = Registered {
                label: label.clone(),
                image: compute_image_id(&program)?.to_string(),
                program: path,
                program_sha256: sha(&program),
                elf,
                elf_sha256: sha(&user),
                features: args[4].clone(),
                source_sha256: Value::Object(hashes),
            };
            fs::write(
                format!("artifacts/{label}.json"),
                serde_json::to_vec_pretty(&reg)?,
            )?;
            println!("{}", serde_json::to_string(&reg)?);
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

        "run" => {
            ensure!(args.len() == 5, "run label fixture result-name");
            let label = &args[2];
            let fixture = &args[3];
            let name = &args[4];
            ensure!(
                name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "result name"
            );
            let slot: u32 = std::env::var("R0_EXECUTION_SLOT")
                .context("guarded execution slot required")?
                .parse()?;
            ensure!((1..=6).contains(&slot), "slot");
            if slot == 1 {
                ensure!(
                    label == "baseline-diag" && fixture == "cred-alpha-42",
                    "first diagnostic fixture"
                );
            }
            if slot == 6 {
                ensure!(
                    label == "corrected-plain" && fixture == "cred-alpha-42",
                    "reserved correction fixture"
                );
            }
            if (2..=5).contains(&slot) {
                ensure!(label.starts_with("component-"), "component slots only");
            }
            let reg: Registered =
                serde_json::from_slice(&fs::read(format!("artifacts/{label}.json"))?)?;
            let program = bytes(&reg.program, 8 * 1024 * 1024)?;
            ensure!(
                sha(&program) == reg.program_sha256
                    && compute_image_id(&program)?.to_string() == reg.image,
                "registered identity changed"
            );
            let (input, journal) = if label.starts_with("component-") {
                let payload = bytes(&format!("fixtures/components/{fixture}.bin"), 32768)?;
                let mut input = Vec::new();
                input.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                input.extend(payload);
                (input, b"R0-CREDVALID-CYCLE-1/component-ok".to_vec())
            } else {
                let all = cases()?;
                let c = all["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|c| c["name"] == fixture.as_str())
                    .context("fixture")?;
                let (op, p, w) = read_case(c)?;
                ensure!(c["reference_expected"] == true, "valid fixture only");
                let mut input = Vec::new();
                for v in [&p, &w] {
                    input.extend_from_slice(&(v.len() as u32).to_be_bytes());
                    input.extend_from_slice(v);
                }
                (input, expected(&op, &p)?)
            };
            let stderr = BoundedFile::create(&format!("evidence/{name}.markers"))?;
            let stdout = BoundedFile::create(&format!("evidence/{name}.stdout"))?;
            let env = ExecutorEnv::builder()
                .write_slice(&input)
                .stderr(stderr)
                .stdout(stdout)
                .segment_limit_po2(16)
                .session_limit(Some(1 << 22))
                .build()?;
            let mut segments = Vec::new();
            let mut prefix = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(format!("evidence/{name}.segments.jsonl"))?;
            let start = Instant::now();
            let client =
                ApiClient::new_sub_process(Path::new(BASE).join("tooling/sdk-3.0.6/r0vm"))?;
            let outcome = client.execute(
                &env,
                Asset::Inline(program.into()),
                AssetRequest::Inline,
                |s, _private_segment_asset| {
                    ensure!(segments.len() < 256, "segment metadata bound");
                    let row = json!({"index":segments.len(),"user_cycles":s.cycles,"po2":s.po2});
                    writeln!(prefix, "{row}")?;
                    segments.push(row);
                    Ok(())
                },
            );
            let mut result = json!({"slot":slot,"label":label,"fixture":fixture,"image":reg.image,"seconds":start.elapsed().as_secs_f64(),"session_limit_user_cycles":4194304,"segment_limit_po2":16,"completed_segment_metadata":segments,"paging_cycles":"not separately exposed by Execute IPC","proof_attempts":0});
            match outcome {
                Ok(s) => {
                    ensure!(s.exit_code == ExitCode::Halted(0), "guest unsuccessful");
                    ensure!(s.journal.bytes == journal, "unexpected journal");
                    result["status"] = json!("completed");
                    result["user_cycles"] = json!(s.cycles());
                    result["padded_cycles"] =
                        json!(s.segments.iter().map(|s| 1_u64 << s.po2).sum::<u64>());
                    result["journal_matches_expected"] = json!(true);
                    result["segments"] = json!(s.segments.len());
                }
                Err(e) => {
                    let reason = format!("{e:#}");
                    result["error"] = json!(reason);
                    result["status"] = json!(if reason.starts_with("Session limit exceeded:") {
                        "cycle_limit"
                    } else {
                        "execution_error"
                    });
                }
            }
            fs::write(
                format!("evidence/{name}.result.json"),
                serde_json::to_vec_pretty(&result)?,
            )?;
            println!("{result}");
            ensure!(
                result["status"] != "execution_error",
                "execution integration error"
            );
        }
        _ => bail!("execution-only package: unsupported command"),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
