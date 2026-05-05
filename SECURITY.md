# Security Audit Report — lightsparkdev/frost

**Date:** 2026-04-12
**Auditor:** Automated security audit (Claude Code)
**Scope:** Lightspark fork-specific changes to ZcashFoundation/frost
**Branches reviewed:**
  - `origin/nested-signing` @ `9aaf1b6` (5 Lightspark commits on top of upstream `b56839d`)
  - `origin/spark-frost` @ `115983a`
  - `main` @ `b56839d` (= upstream v2.1.0, NCC-audited)

---

## Executive Summary

The Lightspark fork introduces two new fields into `SigningPackage` —
`signing_participants_groups` and `adaptor` — that **alter the signature share
a participant produces** but are **not bound by the binding factor ρ**.

This violates the core security invariant of FROST and enables a malicious
coordinator to extract any participant's secret share by sending two
`SigningPackage`s that differ only in one of these fields. The attack requires
no cryptographic break, runs in constant time, and is undetectable by the
victim.

We rate two findings **CRITICAL** (full key-share extraction), four **HIGH**,
and four **MEDIUM**.

---

## Background: Why ρ Matters

FROST's security against ROS-style attacks rests on a single property:

> Every input that affects the signature share `zᵢ` MUST be bound by the
> binding factor `ρᵢ = H1(transcript)`.

The signature share is:

    zᵢ = dᵢ + eᵢ · ρᵢ + λᵢ · sᵢ · c

If an adversary can change `λᵢ` or `c` while holding `ρᵢ` fixed, the nonce
contribution `dᵢ + eᵢ · ρᵢ` cancels across two signing sessions, leaving a
linear equation in `sᵢ`.

RFC 9591 §5.2 binds `ρ` to `(group_pk, msg, commitment_list, identifier)`
because in the standard protocol those are the *only* inputs to `λᵢ` and `c`.
Lightspark added inputs but forgot to bind them.

---

## CRITICAL Findings

### C-1: `signing_participants_groups` not bound by binding factor

| | |
|---|---|
| **Severity** | Critical |
| **Branch** | `origin/nested-signing` |
| **Introduced** | `ba7fd18`, generalized in `5459e1b` |
| **Location** | `frost-core/src/lib.rs:372` (field), `:455-487` (binding factor), `frost-core/src/round2.rs:161-177` (consumption) |
| **Impact** | Secret share extraction by malicious coordinator |

#### Description

`SigningPackage` was extended with:

```rust
// frost-core/src/lib.rs:372
signing_participants_groups: Option<Vec<BTreeSet<Identifier<C>>>>,
```

In `round2::sign`, this field overrides the Lagrange coefficient:

```rust
// frost-core/src/round2.rs:161-177
let lambda_i = match signing_package.signing_participants_groups.clone() {
    Some(signing_participants_groups) => {
        let mut result = Err(Error::UnknownIdentifier);
        for signing_participants_group in signing_participants_groups {
            if signing_participants_group.contains(&key_package.identifier()) {
                result = compute_lagrange_coefficient(
                    &signing_participants_group, None, *key_package.identifier(),
                );
                break;
            }
        }
        result?
    }
    None => derive_interpolating_value(key_package.identifier(), &signing_package)?,
};
```

But `binding_factor_preimages` (lib.rs:455-487) hashes only:

    ρ_input = group_pk || H4(msg) || H5(commitments) || prefix || identifier

`signing_participants_groups` is absent.

#### Attack

Coordinator obtains victim `i`'s commitment `(Dᵢ, Eᵢ)` once, then sends two
packages:

| | Pkg A | Pkg B |
|---|---|---|
| `signing_commitments` | `S` | `S` (identical) |
| `message` | `m` | `m` (identical) |
| `signing_participants_groups` | `[{i, j₁, j₂}]` | `[{i, k₁, k₂}]` |

Since `ρ` depends only on `(VK, m, S, i)`:

    ρᵢᴬ = ρᵢᴮ = ρ

Since `R` is computed from `S` and `ρ` only (groups don't affect
`compute_group_commitment`):

    Rᴬ = Rᴮ → cᴬ = cᴮ = c

But `λᵢ` differs because the interpolation set differs:

    zᴬ = dᵢ + eᵢ·ρ + λᴬ · sᵢ · c
    zᴮ = dᵢ + eᵢ·ρ + λᴮ · sᵢ · c

Subtracting:

    sᵢ = (zᴬ − zᴮ) / ((λᴬ − λᴮ) · c)

All values on the right are known to the coordinator. **One subtraction, one
field inversion, one multiplication. Done.**

#### Why the existing nonce-check doesn't help

`round2::sign` checks `signer_nonces.commitments == commitment` (line 141).
This passes for both packages — `S` is identical. The signer has no way to
know it should refuse the second request: the message is the same, the
commitments are the same, the package looks like a benign retry.

---

### C-2: `adaptor` not bound by binding factor

| | |
|---|---|
| **Severity** | Critical |
| **Branch** | `origin/nested-signing` |
| **Introduced** | `78d37da` |
| **Location** | `frost-core/src/lib.rs:388` (field), `:455-487` (binding factor), `:579-581` (consumption) |
| **Impact** | Secret share extraction by malicious coordinator |

#### Description

```rust
// frost-core/src/lib.rs:388
adaptor: Option<VerifyingKey<C>>,
```

The adaptor point `T` is added to the group commitment:

```rust
// frost-core/src/lib.rs:579-581
if let Some(adaptor) = signing_package.adaptor {
    group_commitment = group_commitment + adaptor.to_element();
}
```

Again, `binding_factor_preimages` does not include it.

#### Attack

Same setup as C-1, but vary `adaptor` instead:

| | Pkg A | Pkg B |
|---|---|---|
| `signing_commitments` | `S` | `S` |
| `message` | `m` | `m` |
| `adaptor` | `T₁` | `T₂` |

`ρᵢᴬ = ρᵢᴮ = ρ` (adaptor not in transcript).

Now `R` differs: `Rᴬ = R₀ + T₁`, `Rᴮ = R₀ + T₂`. The challenge is
`c = H2(R || VK || m)`, so:

    cᴬ ≠ cᴮ

With identical `λᵢ` (using `signing_participants_groups = None`):

    zᴬ = dᵢ + eᵢ·ρ + λᵢ · sᵢ · cᴬ
    zᴮ = dᵢ + eᵢ·ρ + λᵢ · sᵢ · cᴮ

    sᵢ = (zᴬ − zᴮ) / (λᵢ · (cᴬ − cᴮ))

#### Note on adaptor signatures

This is not a flaw inherent to adaptor signatures. Correct adaptor-FROST
constructions (e.g., the schemes in the BIP-FROST discussion) include `T` in
the transcript that derives `ρ`, precisely to prevent this.

---

## HIGH Findings

### H-1: Aggregate verification bypass when adaptor present

| | |
|---|---|
| **Severity** | High |
| **Branch** | `origin/nested-signing` |
| **Introduced** | `78d37da` |
| **Location** | `frost-core/src/lib.rs:658-661` |

```rust
if signing_package.adaptor.is_some() {
    // If there is an adaptor, we skip the verification step.
    return Ok(signature);
}
```

The pre-signature `(R + T, z)` is *expected* to fail standard verification —
that's the point of adaptor signatures. But returning it with **no validation
at all** means:

1. Cheater detection is silently disabled
2. A malicious co-signer can submit `zᵢ = 0` (or any garbage) — the
   coordinator returns a "successful" but unredeemable pre-signature
3. The caller has no in-band signal that verification was skipped

The correct check is `z·G == R + T + c·VK` (verifying the pre-signature
against the adapted commitment).

---

### H-2: `Identifier::Sub` bypasses zero invariant

| | |
|---|---|
| **Severity** | High |
| **Branch** | `origin/spark-frost` |
| **Location** | `frost-core/src/identifier.rs:161-169` |

```rust
impl<C> std::ops::Sub for Identifier<C> where C: Ciphersuite {
    type Output = Self;
    fn sub(self, rhs: Identifier<C>) -> Self::Output {
        Self(self.0 - rhs.0)   // ← NO ZERO CHECK
    }
}
```

`Identifier`'s safety invariant is **never zero** — evaluating the secret
polynomial at 0 yields the group secret directly. Every other constructor
(`new`, `deserialize`, `TryFrom<u16>`, serde) enforces this. `Sub` does not.

`id - id` produces `Identifier(0)`. If this value reaches
`evaluate_polynomial` or `compute_lagrange_coefficient` with `x = Some(zero)`,
the protocol leaks the constant term.

Note: upstream removed this `Sub` impl in `647da35`. The `spark-frost` branch
is based on an older commit and still has it.

---

### H-3: Coordinator-controlled λ enables false accusation

| | |
|---|---|
| **Severity** | High |
| **Branch** | `origin/nested-signing` |
| **Location** | `frost-core/src/round2.rs:161-177`, `frost-core/src/lib.rs:801-817` |

There is no validation that:
- groups in `signing_participants_groups` are pairwise disjoint
- `⋃ groups == signing_commitments.keys()`
- each group has `≥ min_signers` members

Both `sign()` and `verify_signature_share_precomputed()` pick the *first*
group containing the target identifier. A malicious coordinator can construct
overlapping groups so the signer computes `λᵢ` from group A while cheater
detection re-derives it from group B, flagging an honest signer as malicious.

A coordinator can also send `groups = [{i}]` → `λᵢ = 1`, voiding the
threshold property for that signer.

---

### H-4: `aggregate_spark` accepts shares from unknown identifiers

| | |
|---|---|
| **Severity** | High |
| **Branch** | `origin/spark-frost` |
| **Introduced** | `6845a63` |
| **Location** | `frost-core/src/lib.rs` (~line 714) |

The check `pubkeys.verifying_shares().contains_key(id)` is commented out.
Signature shares from identifiers with no registered verifying share are
summed into `z` without rejection. Combined with the absence of cheater
detection in the spark path, an attacker can inject arbitrary additive offsets
into the final signature.

---

## MEDIUM Findings (upstream-inherited)

| ID | Location | Issue |
|---|---|---|
| **M-1** | `frost-core/src/keys/dkg.rs:200-209,355-362` | `round1::SecretPackage`/`round2::SecretPackage` derive `Zeroize` but not `ZeroizeOnDrop`. `dkg::part2()` consumes by value but never calls `.zeroize()` — coefficients leak on every code path including early-return errors. |
| **M-2** | `frost-core/src/keys/dkg.rs:505-513` | `part2`/`part3` check `len() == max_signers - 1` but never `!packages.contains_key(&self_id)`. App-layer mis-key passes silently. |
| **M-3** | `frost-core/src/keys.rs:421-444,672-683` | `SecretShare::verify()` accepts length-1 VSS commitments. `KeyPackage::try_from` then sets `min_signers = commitment.len() = 1`. DKG path is protected; trusted-dealer/deserialize path is not. |
| **M-4** | `frost-core/src/lib.rs:537-539` (upstream) | No explicit identity check on the *summed* group commitment. Per-element checks exist (line 518), but adversarial commitments can sum to 0. Fails later in `serialize(R)` for most ciphersuites — fragile, not enforced here. |

---

## Recommendations

### Immediate (before any production use of `nested-signing`)

1. **Bind `signing_participants_groups` and `adaptor` in
   `binding_factor_preimages`.** See PoC fix below. This single change closes
   both C-1 and C-2.

2. **Replace the H-1 early-return with proper pre-signature verification:**
   `(z·G − c·VK == R)` where `R` already includes `T`.

3. **Remove or guard `Identifier::Sub` on `spark-frost`**, or rebase onto a
   commit after upstream `647da35`.

### Short-term

4. Add structural validation for `signing_participants_groups` in
   `SigningPackage::new_with_participants_groups`:
   - groups are pairwise disjoint
   - `⋃ groups ⊆ signing_commitments.keys()`
   - `|group| ≥ min_signers` for each group (checked at sign time)

5. Restore the `verifying_shares().contains_key(id)` check in
   `aggregate_spark`.

### General

6. Add a regression test: two `sign()` calls with the same nonce but different
   `SigningPackage` field values must produce identical shares **OR** the
   second call must fail. Any other outcome indicates a binding-factor gap.

---

## Appendix: PoC Fixes

### Fix for C-1 / C-2 — `binding_factor_preimages`

**File:** `frost-core/src/lib.rs` (on `origin/nested-signing`)

```rust
pub fn binding_factor_preimages(
    &self,
    verifying_key: &VerifyingKey<C>,
    additional_prefix: &[u8],
) -> Result<Vec<(Identifier<C>, Vec<u8>)>, Error<C>> {
    let mut binding_factor_input_prefix = Vec::new();

    binding_factor_input_prefix.extend_from_slice(verifying_key.serialize()?.as_ref());
    binding_factor_input_prefix.extend_from_slice(C::H4(self.message.as_slice()).as_ref());
    binding_factor_input_prefix.extend_from_slice(
        C::H5(&round1::encode_group_commitments(self.signing_commitments())?[..]).as_ref(),
    );

    // SECURITY: bind every SigningPackage field that influences the
    // signature share. signing_participants_groups changes λᵢ; adaptor
    // changes R (and hence c). Omitting either lets a malicious
    // coordinator hold ρ fixed while varying zᵢ → secret-share extraction.

    // -- signing_participants_groups --
    let mut groups_enc = Vec::new();
    match &self.signing_participants_groups {
        None => groups_enc.push(0u8),
        Some(groups) => {
            groups_enc.push(1u8);
            let n: u16 = groups
                .len()
                .try_into()
                .map_err(|_| Error::IncorrectNumberOfIdentifiers)?;
            groups_enc.extend_from_slice(&n.to_be_bytes());
            for group in groups {
                let m: u16 = group
                    .len()
                    .try_into()
                    .map_err(|_| Error::IncorrectNumberOfIdentifiers)?;
                groups_enc.extend_from_slice(&m.to_be_bytes());
                for id in group {
                    groups_enc.extend_from_slice(id.serialize().as_ref());
                }
            }
        }
    }
    binding_factor_input_prefix.extend_from_slice(C::H5(&groups_enc).as_ref());

    // -- adaptor --
    match &self.adaptor {
        None => binding_factor_input_prefix.push(0u8),
        Some(adaptor) => {
            binding_factor_input_prefix.push(1u8);
            binding_factor_input_prefix.extend_from_slice(adaptor.serialize()?.as_ref());
        }
    }

    binding_factor_input_prefix.extend_from_slice(additional_prefix);

    Ok(self
        .signing_commitments()
        .keys()
        .map(|identifier| {
            let mut binding_factor_input = Vec::new();
            binding_factor_input.extend_from_slice(&binding_factor_input_prefix);
            binding_factor_input.extend_from_slice(identifier.serialize().as_ref());
            (*identifier, binding_factor_input)
        })
        .collect())
}
```

### Fix for H-1 — adaptor pre-signature verification

**File:** `frost-core/src/lib.rs` (on `origin/nested-signing`, replaces lines 658-661)

```rust
let verification_result = if let Some(adaptor) = signing_package.adaptor() {
    let challenge = <C>::challenge(
        &group_commitment.0,
        &pubkeys.verifying_key,
        signing_package.message(),
    )?;
    let zG = <C::Group>::generator() * z;
    let cVK = pubkeys.verifying_key.to_element() * challenge.to_scalar();
    let expected = (group_commitment.0 - adaptor.to_element()) + cVK;
    if (zG - expected) * <C::Group>::cofactor() == <C::Group>::identity() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
} else {
    pubkeys
        .verifying_key
        .verify(signing_package.message(), &signature)
};
```

### Fix for H-2 — `Identifier::Sub`

**File:** `frost-core/src/identifier.rs` (on `origin/spark-frost`)

Delete the `Sub` impl entirely (matching upstream `647da35`). If subtraction
is genuinely needed for nested Lagrange:

```rust
impl<C> Identifier<C>
where
    C: Ciphersuite,
{
    pub fn checked_sub(self, rhs: Identifier<C>) -> Result<Self, Error<C>> {
        Self::new(self.0 - rhs.0)
    }
}
```
