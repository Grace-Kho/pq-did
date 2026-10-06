# Versioned KYC delivery exports and four smoke measurements

Use the guarded commands and admission requirements in
[the delivery report](../../docs/kyc_testbed_delivery.md). `runner.py` imports the
sealed issuer-v2/manager-v2 application and actual bounded ML-DSA core. `export.py`
imports the existing bounded writer; it emits a derivative catalogue with exact
source locators, not a rewritten historical dataset.

Historical counts are 276, 19, 3 and 4 in separate datasets. Four new smoke rows
validate this runner only. CSV/JSONL chunks are bounded at 256 KiB; manifests and
readback cover both formats. Component results are separate, unavailable private
metrics remain null with reasons, and historical failures remain indexed.

No command is an implicit allowance for another benchmark run. A closed ledger or
existing output directory refuses reuse. No full-statistics campaign, private proof,
installation, build, network service or isolation activation is included.
