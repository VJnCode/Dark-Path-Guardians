## Detection metrics

Model: `qwen3:4b` (local, via Ollama) · split: `test` · generated 2026-11-26

#### Text set (Mathur et al. 2019 + dark.csv negatives)

570 strings (320 negatives). Macro average covers types with n ≥ 10; * marks types with too few examples to trust. 80 out-of-scope dark strings (e.g. activity notifications) are excluded; share of them flagged as some pattern: rules 10%, llm 48%, hybrid 29%.

| Pattern | n | Rules P | R | F1 | Llm P | R | F1 | Hybrid P | R | F1 |
|---|---|---|---|---|---|---|---|---|---|---|
| fake_urgency | 80 | 1.00 | 0.90 | 0.95 | 0.92 | 0.82 | 0.87 | 0.99 | 0.89 | 0.93 |
| fake_scarcity | 80 | 0.99 | 0.95 | 0.97 | 1.00 | 0.90 | 0.95 | 0.99 | 0.95 | 0.97 |
| preselected_option* | 3 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 1.00 | 0.33 | 0.50 |
| hidden_fees* | 3 | 0.00 | 0.00 | 0.00 | 0.40 | 0.67 | 0.50 | 0.33 | 0.33 | 0.33 |
| confirmshaming | 80 | 1.00 | 0.82 | 0.90 | 1.00 | 0.80 | 0.89 | 1.00 | 0.91 | 0.95 |
| forced_consent* | 4 | 0.00 | 0.00 | 0.00 | 0.50 | 1.00 | 0.67 | 0.38 | 0.75 | 0.50 |
| disguised_ad | 0 | (0 FP) | – | – | (8 FP) | – | – | (4 FP) | – | – |
| **Macro avg** | | 1.00 | 0.89 | 0.94 | 0.97 | 0.84 | 0.90 | 0.99 | 0.92 | 0.95 |
| **Any dark pattern** | | 1.00 | 0.86 | 0.92 | 0.93 | 0.86 | 0.90 | 0.95 | 0.91 | 0.93 |

Run time: rules: 0.1s · llm: 2102.5s · hybrid: 379.6s.

#### Manual page set (per page)

Pending review: 0 of 51 pages verified. See `eval/manual/README.md`.

