# Headless process comparison

Synthetic single-host measurements; two limited metadata heuristics, not an anonymity proof.

| Backend | Case | Completed / planned | p50 / p95 ms | Client MiB/hour | Passive match | Followup match |
| --- | --- | --- | --- | --- | --- | --- |
| direct | clean | 64 / 64 | 0 / 1 | 5.46 | 63/64 (98.4%; chance 6.2%) | 28/48 (58.3%; chance 6.2%) |
| prototype | clean | 63 / 64 | 1476 / 4475 | 64.18 | 3/64 (4.7%; chance 6.2%) | 3/48 (6.2%; chance 6.2%) |
| direct | watermark | 64 / 64 | 378 / 755 | 5.46 | 59/64 (92.2%; chance 6.2%) | 34/48 (70.8%; chance 6.2%) |
| prototype | watermark | 64 / 64 | 1979 / 5977 | 64.18 | 3/64 (4.7%; chance 6.2%) | 3/48 (6.2%; chance 6.2%) |
| direct | loss | 56 / 64 | 1 / 3 | 4.86 | 56/56 (100.0%; chance 6.2%) | 21/42 (50.0%; chance 6.2%) |
| prototype | loss | 57 / 64 | 1758 / 5975 | 64.18 | 2/58 (3.4%; chance 6.2%) | 5/44 (11.4%; chance 6.2%) |
| direct | disconnect | 64 / 64 | 0 / 1 | 5.46 | 62/64 (96.9%; chance 6.2%) | 28/48 (58.3%; chance 6.2%) |
| prototype | disconnect | 63 / 64 | 1655 / 5978 | 58.72 | 4/64 (6.2%; chance 6.4%) | 1/48 (2.1%; chance 6.3%) |

Complete Katzenpost reference: **not_run_credential_file_policy** (v0.0.107). The stock Docker generator and server write identity.private.pem and link.private.pem. The user's rule keeps credentials out of files. No keys or testnet were generated; no reference measurements are fabricated.

The direct control uses the same Sphinx cell geometry with one-hop request/reply paths, without cover or mixing. TCP stream bytes include HTTP but exclude TCP/IP headers and retransmission. Percentiles describe completed jobs only. Loss can stop a client's remaining sequential jobs.

Privacy values summarize fixed nearest-event rules, not a trained or comprehensive attacker. Missing measurements invalidate attack scores. Raw observations and ephemeral keys remain in memory only.
