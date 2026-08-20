"""
VALIDATION SCRIPT 2: Real multiparty (threshold) BFV correctness check
using OpenFHE's native Multiparty FHE support.

*** THIS SCRIPT REQUIRES INTERNET ACCESS TO INSTALL AND HAS NOT BEEN
*** EXECUTED IN THE CHAT SANDBOX (no network access there). Please run
*** it in your own environment and report back the output.

INSTALL:
    pip install openfhe

WHAT THIS VALIDATES:
OpenFHE implements real, production-grade multiparty (threshold) BFV
key generation and decryption (not a toy re-implementation). This
script encrypts each candidate rating value {1,...,5} under a jointly
generated n-party public key, has all n parties contribute partial
decryptions, and combines them -- directly testing whether CORRECTNESS
holds at real, cryptographically secure parameters for n=9 parties
(matching ourpaper2's threshold configuration), analogous to the
"Sanity check" step in the chat-session toy model but on a real library.

WHAT THIS SCRIPT DOES *NOT* VALIDATE:
OpenFHE's multiparty API returns only the FINAL combined (correct)
plaintext -- it does not expose each party's raw noisy partial share at
the message level, by design (this is what makes it usable in
production). It therefore CANNOT be used, via this public API alone, to
directly reproduce the multi-query noise-averaging attack of Theorem 2;
that requires the custom low-level implementation used in the chat
session (see validate_real_params.py, which uses real standardized
parameters instead of OpenFHE's abstraction).

If this script runs successfully and reports correct decryption for all
five rating values at n=9, it corroborates that a production library
achieves per-message correctness for our target scenario -- useful
context for interpreting Theorem 1's correctness-ceiling analysis
against a real implementation, even though the noise internals differ
in representation (RNS chain vs. single modulus) from this paper's
simplified model.
"""

from openfhe import *

def run_multiparty_bfv_test(n_parties=9, plaintext_modulus=8, ratings=(1, 2, 3, 4, 5)):
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(plaintext_modulus)
    parameters.SetMultiplicativeDepth(0)         # we only need encrypt/decrypt, no mult
    parameters.SetSecurityLevel(HEStd_128_classic)  # real 128-bit security, matches paper's target lambda
    parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)  # explicit noise-flooding threshold mode

    cc = GenCryptoContext(parameters)
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(MULTIPARTY)

    print(f"Ring dimension used by OpenFHE at 128-bit security: {cc.GetRingDimension()}")

    # --- Distributed key generation across n_parties ---
    # OpenFHE's MultipartyKeyGen chains each party's contribution onto the
    # previous party's public key, matching the additive-sharing structure
    # described in Sec. 3 of the paper.
    kp_list = []
    kp1 = cc.KeyGen()
    kp_list.append(kp1)
    running_pub_key = kp1.publicKey
    for i in range(1, n_parties):
        kp_i = cc.MultipartyKeyGen(running_pub_key)
        kp_list.append(kp_i)
        running_pub_key = kp_i.publicKey

    joint_public_key = running_pub_key

    print(f"Generated joint public key across n={n_parties} parties.")
    print()

    all_correct = True
    for rating in ratings:
        pt = cc.MakePackedPlaintext([rating])
        ct = cc.Encrypt(joint_public_key, pt)

        # --- Threshold (multiparty) partial decryption + combination ---
        # First party does the "lead" partial decryption; remaining parties
        # do "main" partial decryptions against it. This mirrors the
        # combine step described abstractly in Sec. 3 of the paper.
        partials = []
        lead = cc.MultipartyDecryptLead([ct], kp_list[0].secretKey)
        partials.extend(lead)
        for i in range(1, n_parties):
            main = cc.MultipartyDecryptMain([ct], kp_list[i].secretKey)
            partials.extend(main)

        result_pt = cc.MultipartyDecryptFusion(partials)
        result_pt.SetLength(1)
        decoded = result_pt.GetPackedValue()[0]

        correct = (decoded == rating)
        all_correct &= correct
        print(f"true rating={rating}  decoded={decoded}  {'OK' if correct else 'MISMATCH <-- report this!'}")

    print()
    if all_correct:
        print(f"RESULT: all {len(ratings)} ratings decoded correctly at n={n_parties} "
              f"parties, 128-bit security, plaintext modulus={plaintext_modulus}.")
        print("This corroborates the paper's correctness assumption at real parameters.")
    else:
        print("RESULT: at least one MISMATCH occurred -- this would be an important")
        print("and unexpected finding; please double-check the OpenFHE version and")
        print("report the exact mismatch pattern.")

if __name__ == "__main__":
    # Matches ourpaper2's n=9; try also n=4, n=20 for a broader picture
    for n in [4, 9, 20]:
        print("#" * 78)
        print(f"# n_parties = {n}")
        print("#" * 78)
        try:
            run_multiparty_bfv_test(n_parties=n)
        except Exception as e:
            print(f"FAILED at n={n}: {e}")
        print()
