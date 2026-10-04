# Okra Tamarin model

Run from this directory with Tamarin 1.12.0 and Maude 3.5.1:

```sh
tamarin-prover +RTS -N2 -RTS --quit-on-warning --derivcheck-timeout=30 --prove --bound=60 --output=okra.proof.spthy okra.spthy
```

`--bound` limits proof-search depth, not the number of sessions. The completed baseline proofs are unbounded-session results for this abstract rule system. Read the model header and restrictions before interpreting them.

The model includes registration, separate credential/token keys, protected request generation, native-evidence binding, blind response finalization, service retry state, and public nonce-only presentations. Authenticated provisioning, fixed accepted measurements/policy, private authenticated channels, and atomic service reservation are assumptions. Channel handles allow adversarial scheduling and replay. The channel fact represents an ideal confidential authenticated channel; it does not prove a TLS or session-key establishment protocol.

The blind-signature equation is a terminating symbolic correctness abstraction. It does not encode RSA's arithmetic, computational one-more security, or blindness. Threshold shares, compromised TCBs, real-time deadlines, revocation and policy changes are not modeled. Expiry is an explicit cancellation transition.

L1 is registered-attester agreement from the service's perspective. L2 is token-origin correspondence, not full Lowe peer-identity agreement: the issuer does not authenticate an RP identity. L3 links acceptance to evidence generated after the fresh challenge. L4/L5 are secrecy predicates; L6 checks unique acceptance using linear challenge state. The S5 equivalence model is separate, under `../deepsec/`.

The baseline represents protected endpoint code and a network adversary. Focused hostile-wrapper controls also test nonce/report substitution; unrestricted malicious requester behavior is not covered by the completed baseline proof.

Baseline model SHA-256: `a3866842ae915413ff941826cabe7ec9357626ef6fa4cb940a1da27c17dbc407`.
