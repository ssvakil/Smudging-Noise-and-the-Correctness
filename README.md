# Smudging Noise and the Correctness–Security Trade-off in Threshold Homomorphic Encryption for Bounded-Domain Rating Aggregation

Code, data, and validation scripts accompanying the paper:

> S. S. Vakil, Y. Farjami, "Smudging Noise and the Correctness–Security Trade-off in Threshold Homomorphic Encryption for Bounded-Domain Rating Aggregation," under review, 2026.

[![Paper (PDF)](https://img.shields.io/badge/paper-PDF-blue)](./paper/paper.pdf)
[![Cover Page (PDF)](https://img.shields.io/badge/artifact-cover%20page-lightgrey)](./cover_page.pdf)

**Authors:** Seyed Saeid Vakil, Yaghoub Farjami — Department of Computer Engineering, Faculty of Engineering, University of Qom, Qom, Iran
**Contact:** `S.vakil@stu.qom.ac.ir`, `farjami@qom.ac.ir`

---

## Summary

This repository provides two independent, complementary validations for the paper's two central findings:

1. **Correctness–security incompatibility** (Theorem 1): under the standard Smudging Lemma, correct threshold decryption and asymptotically negligible single-query statistical security cannot both hold for threshold cardinality $n>1$ at realistic single-modulus BFV-style parameters.
2. **Multi-query noise-averaging attack** (Theorem 2): an adversary with repeated access to a partial-decryption oracle for the *same* ciphertext can recover a bounded, adjacent-valued rating (e.g., $\{1,\ldots,5\}$) within a small, closed-form number of queries, even at noise levels calibrated to preserve correctness.

See the [paper](./paper/paper.pdf) for full derivations, proofs, threat model, and discussion of scope and limitations.

## Repository structure

```
.
├── paper/
│   ├── paper.tex                       # Full LaTeX source of the paper
│   └── paper.pdf                       # Compiled PDF
├── cover_page.tex / cover_page.pdf     # One-page artifact cover page (claims, requirements, scope)
├── figures/
│   ├── fig_nmax.pdf / .png             # Fig. 1: n_max breakdown region vs. security level
│   └── fig_attack_curves.pdf / .png    # Fig. 2: closed-form attack success curves
├── src/
│   ├── analysis.py                     # Closed-form Smudging Lemma bounds (Sec. 4/5, Theorem 1 & 2)
│   ├── lwe_threshold.py                # Toy-scale LWE/BFV threshold decryption + multi-query attack simulation
│   ├── validate_real_params.py         # Re-derivation at real 128-bit standards-track parameters (HomomorphicEncryption.org)
│   └── validate_openfhe_multiparty.py  # Real multiparty (threshold) BFV correctness check using OpenFHE
├── output/
│   ├── openfhe_validation_output.txt       # Recorded output of validate_openfhe_multiparty.py
│   └── validate_real_params_output.txt     # Recorded output of validate_real_params.py
├── requirements.txt
└── README.md
```

## Requirements

Two tiers of dependencies, matching the two validation modes described in the paper (Sec. 5.4):

**Tier 1 — no internet required, runs anywhere:**
```
python >= 3.9
numpy
scipy
matplotlib   # only needed to regenerate figures
```
Install with:
```bash
pip install -r requirements.txt
```

**Tier 2 — requires internet access to install:**
```
openfhe   # OpenFHE Python bindings, for real multiparty BFV correctness validation
```
Install with:
```bash
pip install openfhe
```
> **Note:** `validate_openfhe_multiparty.py` was developed and its expected output recorded in an environment *with* internet access. It has not been executable in fully offline/sandboxed environments during development of this repository; if `pip install openfhe` fails in your environment, see [Troubleshooting](#troubleshooting) below.

## Usage

Run the closed-form and toy-simulation validations (Tier 1, no internet needed):
```bash
python3 src/analysis.py
python3 src/lwe_threshold.py
python3 src/validate_real_params.py
```

Run the real-library correctness validation (Tier 2, requires internet to install `openfhe` first):
```bash
pip install openfhe
python3 src/validate_openfhe_multiparty.py
```

Regenerate the paper's figures:
```bash
pip install matplotlib
python3 src/make_figures.py
```

Recorded output from both validation tiers (as reported in the paper's Sec. 5.4) is included under `output/` for reference without needing to re-run anything.

## What each script validates

| Script | Validates | Needs internet? |
|---|---|---|
| `analysis.py` | Closed-form Smudging Lemma bounds ($n_{\max}$, Eq. 4) at toy-scale parameters | No |
| `lwe_threshold.py` | Toy-scale LWE/BFV threshold decryption; multi-query attack success rate vs. plaintext-slot spacing | No |
| `validate_real_params.py` | Re-derives $n_{\max}$ and $k^{*}$ at real 128-bit standards-track BFV parameters ($N{=}4096$) | No |
| `validate_openfhe_multiparty.py` | Real multiparty BFV threshold decryption **correctness** at $n\in\{4,9,20\}$, 128-bit security | **Yes** (to install `openfhe`) |

## Scope and limitations

This artifact validates **correctness** and the **closed-form parameter analysis** against a real production HE library (OpenFHE). It does **not** validate the multi-query attack itself against a production library's internals: OpenFHE's public multiparty API returns only the final combined (correct) plaintext and does not expose each party's raw noisy partial-decryption share, which the attack's toy-scale implementation relies on. See the paper's *Threats to Validity* (Sec. 5.3–5.4) and *Formal Limitations of the Attack Model* (Sec. 7.1) for the complete, explicit scope under which the paper's claims hold.

## Troubleshooting

- **`pip install openfhe` fails:** ensure Python 3.8–3.11 (OpenFHE's Python bindings may not yet support the newest Python releases); consider a fresh virtual environment (`python3 -m venv venv && source venv/bin/activate`); on Windows, native builds are limited — WSL or Docker is recommended.
- **`AttributeError` on `Multiparty*` calls:** OpenFHE's Python API has changed method names across versions; check `pip show openfhe` and consult the version-matched [OpenFHE documentation](https://openfhe-development.readthedocs.io/).
- **No internet access in your environment:** run only the Tier 1 scripts; the recorded output in `output/openfhe_validation_output.txt` reflects a successful run and can be cited/inspected without re-running it yourself.

## Citation

If you use this code, please cite the paper:
```bibtex
@unpublished{vakil2026smudging,
  author = {Vakil, Seyed Saeid and Farjami, Yaghoub},
  title  = {Smudging Noise and the Correctness--Security Trade-off in Threshold Homomorphic Encryption for Bounded-Domain Rating Aggregation},
  note   = {Under review},
  year   = {2026}
}
```

## License

Add your preferred license here (e.g., MIT for code, CC-BY for paper text) before making the repository public.

## Acknowledgments

The authors declare that they have no known competing financial interests or personal relationships that could have appeared to influence the work reported in this paper.
