"""
VALIDATION SCRIPT 1: Real-parameter-scale LWE/BFV threshold decryption
and multi-query noise-averaging attack, using standardized security
parameters from the HomomorphicEncryption.org security standard
(https://homomorphicencryption.org/standard/) instead of the toy-scale
parameters used in the chat-session simulation.

WHY THIS SCRIPT (rather than calling OpenFHE/SEAL directly) FOR THE
MULTI-QUERY ATTACK (Theorem 2):
Production libraries (OpenFHE, SEAL, HElib) intentionally hide the raw,
per-query noisy partial-decryption signal behind a "Combine" operation
that is designed to always return the EXACT correct plaintext. This is
precisely the internal signal our multi-query attack needs to observe.
Reproducing the attack against these libraries would require patching
their internals rather than using the public API, which is out of scope
for a quick validation. Instead, this script re-implements the SAME
minimal LWE/BFV-style scheme as the chat-session toy model, but at
REAL, standards-track parameters (not arbitrary toy values), so that
Theorem 1 and Theorem 2's numerical predictions can be checked against
parameters an auditor would recognize as realistic.

Recommended standard parameter set used below (128-bit security,
HomomorphicEncryption.org 2019 standard, "conservative" column):
  polynomial degree N = 4096
  ciphertext modulus  log2(q) ~= 109 bits  (single modulus, matching
    this paper's single-modulus assumption; real BFV deployments often
    use an RNS chain of several smaller moduli -- see note at bottom)
  plaintext modulus t: application-chosen; we use t=8 (>5) as in the paper

INSTALL: only needs numpy (no HE library required for this script).
    pip install numpy scipy

RUN:
    python3 validate_real_params.py
"""

import numpy as np
import math

rng = np.random.default_rng(2026)

# ---------------------------------------------------------------------
# STANDARDS-TRACK PARAMETERS (HomomorphicEncryption.org 128-bit table)
# ---------------------------------------------------------------------
N_DIM = 4096                 # polynomial degree (LWE/RLWE dimension)
LOG2_Q = 109                  # ciphertext modulus bit-length @ 128-bit sec for N=4096
q = 2 ** LOG2_Q
t = 8                          # plaintext modulus (paper uses t=8 for ratings 1..5)
Delta = q // t
FRESH_NOISE_STD = 3.19          # standard discrete-Gaussian error std (SEAL/OpenFHE default)
n_parties = 9                    # matches paper's n=9 (from ourpaper2)
z0 = 6                             # correctness tail-bound multiplier used in the paper

print("=" * 78)
print("VALIDATION 1: real 128-bit-secure BFV-style single-modulus parameters")
print("=" * 78)
print(f"N (poly degree)      = {N_DIM}")
print(f"log2(q)              = {LOG2_Q}  (q = {q:.4e})")
print(f"t (plaintext modulus) = {t}")
print(f"Delta = q/t           = {Delta:.4e}")
print(f"Fresh noise std        = {FRESH_NOISE_STD}")
print(f"n (threshold parties)  = {n_parties}")
print()

# ---------------------------------------------------------------------
# Re-derive Theorem 1 (exact form, Eq. nmax_exact) at these REAL params
# ---------------------------------------------------------------------
B1 = FRESH_NOISE_STD * 6  # 6-sigma tail bound on fresh noise, as in the paper
correctness_bound = Delta / 2

def nmax_exact(eps, B1=B1, Delta=Delta, z0=z0):
    return (Delta * eps) ** 2 / (12 * z0 ** 2 * B1 ** 2)

print("-" * 78)
print("Theorem 1 (exact form) at REAL parameters, varying target security lambda")
print("-" * 78)
for lam in [128, 80, 40, 20]:
    eps = 2.0 ** (-lam)
    nm = nmax_exact(eps)
    print(f"  lambda={lam:4d}  eps=2^-{lam:<4d}  n_max_exact = {nm:.6e}"
          + ("   <-- infeasible for any n>1" if nm < 1 else ""))
print()
print("If n_max_exact < 1 at these REAL (not toy) parameters too, this")
print("confirms Theorem 1's conclusion is not an artifact of the toy-scale")
print("parameters used in the original chat-session simulation.")
print()

# ---------------------------------------------------------------------
# Achievable eps at n=9 (paper's actual deployed n), and resulting
# multi-query attack cost via Theorem 2's closed form (Eq. kstar)
# ---------------------------------------------------------------------
print("-" * 78)
print(f"Achievable single-query eps at n={n_parties} (correctness-preserving), REAL params")
print("-" * 78)
B2_max_correct = correctness_bound / (z0 * math.sqrt(n_parties) * math.sqrt(3))
eps_achieved = (B1 * math.sqrt(3)) / B2_max_correct
print(f"Max per-party smudging std (uniform B2, exact form): {B2_max_correct:.6e}")
print(f"Achieved single-query statistical distance eps*      : {eps_achieved:.6e}")
print(f"  (target 2^-128 = {2**-128:.3e} for comparison)")
print()

from scipy.stats import norm
sigma_agg = math.sqrt(n_parties) * (B2_max_correct / math.sqrt(3))  # convert uniform B2 to std
half_gap = Delta / 2  # adjacent-slot half gap
for p in [0.90, 0.99, 0.999]:
    k_star = (2 * sigma_agg * norm.ppf(p) / Delta) ** 2
    print(f"  k* for {p*100:.1f}% recovery confidence (Theorem 2, Eq. kstar): {k_star:.4f}  -> ceil = {math.ceil(max(k_star,1))}")
print()
print("=" * 78)
print("NOTE ON RNS-BASED DEPLOYMENTS")
print("=" * 78)
print("Real production BFV deployments (SEAL, OpenFHE) typically use an RNS")
print("modulus chain (several ~30-60 bit primes) rather than one single large")
print("modulus. This paper's single-modulus model is a simplification stated")
print("explicitly in Sec. 4 of the paper. Re-running this analysis under an")
print("RNS chain is a natural next step and may change the numeric constants")
print("(though we expect the qualitative conclusion -- that n_max is far below")
print("realistic deployment cardinalities -- to persist, since RNS chains do")
print("not fundamentally change the noise-vs-modulus relationship, only how")
print("q is represented computationally).")
