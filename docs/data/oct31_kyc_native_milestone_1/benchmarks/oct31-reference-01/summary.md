# Measured isolated ML-DSA reference workload

All 276 trials retained: 12 cold-process, 24 warm-up and 240 warm measurements.
Setup/key generation are excluded from operation latency and included in resource accounting.

| Scenario | Warm n | Median (ms) | Nearest-rank p95 (ms) |
| --- | ---: | ---: | ---: |
| ISSUE | 60 | 189.175 | 268.009 |
| PRESENT-A | 60 | 465.898 | 565.499 |
| PRESENT-B | 60 | 468.337 | 572.229 |
| REVOKE-UPDATE | 60 | 534.213 | 620.661 |

These are descriptive local observations, not population percentiles or throughput.
Private authentication/proof timings and sizes are unavailable, never zero.
