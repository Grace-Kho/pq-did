# ML-DSA reference benchmark

Research workload on this host. Complete attributes, DID/version, persistent holder key, rid and path are disclosed and linkable. No private-authentication proof backend is available. No full-scheme overhead ratio is computed.

Warm-ups remain in the ledger and exports. Latency statistics use successful, uncensored observations only; failed and missing attempts remain visible. Cold samples are descriptive. Sample p95 is not a population p95 or SLA.

| Scenario | Session | Phase | Attempts/planned | Successful | Failed | Censored | Min ms | Median ms | p95 ms | Max ms |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ISSUE | session-1 | cold | 0/1 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| ISSUE | session-1 | warmup | 0/2 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| ISSUE | session-1 | warm | 1/20 | 1 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
| ISSUE | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| ISSUE | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| ISSUE | pooled | warm | 1/60 | 1 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
| PRESENT-A | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-A | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-A | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-B | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-B | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-B | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| REVOKE-UPDATE | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| REVOKE-UPDATE | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| REVOKE-UPDATE | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
