# DeepSec check of post-registration attester unlinkability

The paper listing in `body/deepsec.tex` and `attester_unlinkability.dps`
contain the same model. DeepSec 2.0.2 reports that `Left` and `Right` are
trace equivalent. This is a bounded check of the relying party's presentation
view, not a verification of the complete ORA implementation.

## Installation used for this run

- Official source: https://github.com/DeepSec-prover/deepsec
- Version: 2.0.2
- Commit: `8ddc45ec79de5ec49810302ea7da32d3dc9f46e4`
- Local executable: `/Users/zengpeng/Documents/ChatGPT/New project/tools/deepsec/deepsec`
- Compiler: OCaml 5.2.1 in the existing `proverif-cli` opam switch.
- Added build dependencies: `ocamlfind` 1.9.8 and `ocamlbuild` 0.16.1.
- Platform: macOS, Apple Silicon. Build completed without source modifications.
- The three executables `deepsec`, `deepsec_worker`, and `deepsec_api` remain
  together in the official source checkout. No global shell configuration was changed.
- DeepSec also stores native results under
  `/Users/zengpeng/Library/Application Support/DeepSec/result_files`.

The installation follows the official instructions:
https://deepsec-prover.github.io/manual/html/install.html

From the paper project directory, rerun the checks with:

```sh
python3 formal/deepsec/check_models.py --check-listing
```

On another machine, pass `--deepsec /absolute/path/to/deepsec`.
The runner generates control models, enforces a 60-second limit per case,
and saves the exact command, model SHA-256, wall time, and prover output in a
new timestamped `results/` directory. DeepSec may return exit status zero for
invalid input, so the runner checks the diagnostic text as well as recording
the exit status. The `--check-listing` option requires byte-for-byte agreement
between the paper listing and the principal `.dps` file.

## Scope and assumptions

`Left` has one eligible attester complete both sessions. `Right` has two
eligible attesters complete one session each. Both use the same issuer token
key within their respective world; fresh keys across the two worlds are
compared up to renaming. The relying party learns only the issuer public keys
and the two `(nonce, signature)` presentations. It supplies the second nonce
after observing the first presentation. A repeated nonce is rejected.

The registration and token signing keys are distinct private names. Attester
identity and the abstract eligibility credential are confined to private
issuance channels. The issuer is honest and does not collude with the relying
party. The credential stands for successful registration, not a model of the
registration exchange or its one-time/reusable-credential state.

The model assumes successful evidence appraisal and directly produces the
canonical RSA-FDH signature `sign(hash(nonce), sk_tok)` after eligibility
checking. This **abstracts completed issuance**, rather than replacing the
real blind-signature protocol with an ordinary-signature implementation. The
cryptographic argument in the paper separately justifies that unblinding
produces the canonical value. A correspondence proof from the complete ORA
implementation to this abstraction is not supplied by DeepSec.

Only fixed, matched public configuration is covered. The model does not
establish native-evidence soundness, blind-signature security, registration
correctness, credential redemption, general replay/expiry state, issuer
unlinkability, privacy under collusion, or privacy against identifying network,
timing, application, or failure information. No claim about eight sessions or
large-session performance is made.

## Verified results

The final run is saved in `results/20261003T115434422297Z/`.
All eight expectations passed; each completed equivalence query was reported
by DeepSec as taking less than one second. These tiny abstract cases are not a
performance benchmark of the protocol or an eight-session experiment.

| Case | Expected and observed result | Purpose |
| --- | --- | --- |
| `rp_unlinkability` | Trace equivalent | Same versus different attesters |
| `identity_leak` | Not trace equivalent | Exposing `ak` in both tokens enables an equality test |
| `issuance_leak` | Not trace equivalent | Exposing issuance identity/credential/nonce breaks privacy |
| `canonical_outputs` | Trace equivalent | Issuance model matches two actual canonical token outputs |
| `not_stuck` | Not trace equivalent | Successful model differs from a process that emits no tokens |
| `original_submitted` | Syntax error | Preserved user code: malformed `Init`, line 33 |
| `prior_listing` | Duplicate identifier error | Preserved local listing declares `unblind` twice |
| `unsupported_unblinding` | Non-subterm rewrite error | Isolates the unsupported RSA unblinding equation |

`generated/` contains mechanically derived controls. Their outputs and attack
traces appear in the corresponding result logs. The control mutations change
only the observation surface or reference process; they are not alternate
protocol proposals.

## Problems in the original code

The user-supplied original is preserved as `original_submitted.dps`.

1. `Init` has unbalanced grouping and does not construct the intended pair of
   attester-state triples. DeepSec rejects it before equivalence checking.
2. `free sk` makes the signing key public. Public `att` also exposes stable
   identity-related fields. This is not the stipulated non-colluding RP view.
3. Finalized tokens are written only to the private state channel `pid`, not
   presented to a public relying-party channel.
4. State changes from `(AK, AK_hash, uct)` to `(AK, nonce_report, utk)`, although
   the next session interprets the latter fields as the former. This changes
   the registration state semantics across sessions.
5. Two parallel `!^8` processes instantiate up to 16 attestation actions per
   world, not two presentations and not simply eight authentications.
6. `unblind` is an opaque constructor in that version. A checksign rule
   returning `true` does not make signatures with different blinding factors
   equal as RSA-FDH final signatures should be.

The pre-existing local listing is preserved as `prior_listing.dps`. Besides
declaring `unblind` as both a constructor and a destructor, it groups different
destructor roots in one `reduc` declaration. Even after fixing those issues,

```text
unblind(sign(blind(m,r),k),r) = sign(m,k)
```

is rejected because its right-hand side is not a subterm of the left-hand side.
The corrected model therefore explicitly abstracts canonical successful
issuance rather than claiming that DeepSec checks this algebraic identity.

## LaTeX check

The built-in editor compiler was invoked on both edited TeX files. It cannot
compile these project fragments by themselves: `body/Analysis.tex` fails at
the existing `\subsection` at line 5, and `body/deepsec.tex` reports that
`lstlisting` is undefined, because the project preamble is not loaded.
The source is preserved in place; no replacement document
or separately compiled PDF was created. DeepSec verification is complete, but
the full manuscript PDF compilation has not been verified in this run.
