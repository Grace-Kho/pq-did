# ML-DSA reference benchmark

Research workload on this host. Complete attributes, DID/version, persistent holder key, rid and path are disclosed and linkable. No private-authentication proof backend is available. No full-scheme overhead ratio is computed.

Warm-ups remain in the ledger and exports. Latency statistics use successful, uncensored observations only; failed and missing attempts remain visible. Cold samples are descriptive. Sample p95 is not a population p95 or SLA.

| Scenario | Session | Phase | Attempts/planned | Successful | Failed | Censored | Min ms | Median ms | p95 ms | Max ms |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ISSUE | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| ISSUE | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| ISSUE | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-A | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-A | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-A | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-B | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-B | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| PRESENT-B | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| REVOKE-UPDATE | session-1 | cold | 1/1 | 1 | 0 | 0 | 523.762 | 523.762 | 523.762 | 523.762 |
| REVOKE-UPDATE | session-1 | warmup | 2/2 | 2 | 0 | 0 | 520.827 | 541.986 | 563.145 | 563.145 |
| REVOKE-UPDATE | session-1 | warm | 20/20 | 20 | 0 | 0 | 471.428 | 551.889 | 626.428 | 720.969 |
| REVOKE-UPDATE | pooled | cold | 1/3 | 1 | 0 | 0 | 523.762 | 523.762 | 523.762 | 523.762 |
| REVOKE-UPDATE | pooled | warmup | 2/6 | 2 | 0 | 0 | 520.827 | 541.986 | 563.145 | 563.145 |
| REVOKE-UPDATE | pooled | warm | 20/60 | 20 | 0 | 0 | 471.428 | 551.889 | 626.428 | 720.969 |
