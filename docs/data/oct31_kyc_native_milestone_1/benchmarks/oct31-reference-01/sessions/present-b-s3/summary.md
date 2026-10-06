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
| PRESENT-B | session-3 | cold | 1/1 | 1 | 0 | 0 | 472.168 | 472.168 | 472.168 | 472.168 |
| PRESENT-B | session-3 | warmup | 2/2 | 2 | 0 | 0 | 501.971 | 504.354 | 506.737 | 506.737 |
| PRESENT-B | session-3 | warm | 20/20 | 20 | 0 | 0 | 430.245 | 498.342 | 577.609 | 595.850 |
| PRESENT-B | pooled | cold | 1/3 | 1 | 0 | 0 | 472.168 | 472.168 | 472.168 | 472.168 |
| PRESENT-B | pooled | warmup | 2/6 | 2 | 0 | 0 | 501.971 | 504.354 | 506.737 | 506.737 |
| PRESENT-B | pooled | warm | 20/60 | 20 | 0 | 0 | 430.245 | 498.342 | 577.609 | 595.850 |
| REVOKE-UPDATE | pooled | cold | 0/3 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| REVOKE-UPDATE | pooled | warmup | 0/6 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
| REVOKE-UPDATE | pooled | warm | 0/60 | 0 | 0 | 0 | unavailable | unavailable | unavailable | unavailable |
