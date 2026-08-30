<!-- EMITTED by mp_metric.py, as of 2026-08-29. Do not edit. -->
<!-- ledger-fingerprint: 410bceed291e5ee7d28482dc90b0b708e0d027b5accdb1458fb1653ab92470e3 -->
| release | 2 | 1 | 0 | N/A | as-coded | N/A→0 | N/A→2 | ceiling |
|---|---|---|---|---|---|---|---|---|
| olmo-2-13b | 7 | 6 | 6 | 3 | 0.526 | 0.455 | 0.591 | 0.868 |
| pythia-12b | 5 | 6 | 8 | 3 | 0.421 | 0.364 | 0.500 | 0.868 |
| bloom-176b | 3 | 8 | 8 | 3 | 0.368 | 0.318 | 0.455 | 0.868 |
| bert-base-uncased | 3 | 3 | 13 | 3 | 0.237 | 0.205 | 0.341 | 0.868 |
| mistral-7b-v0.3 | 2 | 0 | 17 | 3 | 0.105 | 0.091 | 0.227 | 0.868 |
| qwen2.5-7b | 2 | 0 | 17 | 3 | 0.105 | 0.091 | 0.227 | 0.868 |
| gpt-2-1.5b | 1 | 2 | 16 | 3 | 0.105 | 0.091 | 0.227 | 0.868 |
| gpt-4o | 0 | 2 | 20 | 0 | 0.045 | 0.045 | 0.045 | 0.773 |
| claude-3.5-sonnet | 0 | 2 | 20 | 0 | 0.045 | 0.045 | 0.045 | 0.773 |
| llama-3.1-8b | 0 | 1 | 18 | 3 | 0.026 | 0.023 | 0.159 | 0.868 |
| gemma-2-9b | 0 | 1 | 18 | 3 | 0.026 | 0.023 | 0.159 | 0.868 |
| gemini-1.5-pro | 0 | 1 | 21 | 0 | 0.023 | 0.023 | 0.023 | 0.773 |

The three columns are the same census under three readings of N/A. The spread between
`N/A→0` and `N/A→2` is the weight the escape hatch is carrying; where it is wide, the
as-coded figure is not reportable on its own.

`ceiling` is the highest as-coded score this release COULD reach: completeness and search
axes cap at 1 for everyone, and an api-only release cannot publish weights at all.
Scores are not comparable across releases whose ceilings differ.
