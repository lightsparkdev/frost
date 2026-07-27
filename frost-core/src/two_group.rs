//! Two-group FROST signing with group-tagged binding factors.
//!
//! Generalizes the nested-signing scheme (one flat commitment set with
//! per-group Lagrange interpolation, [`SigningPackage::new_with_participants_groups`])
//! to the case where the second participant group is itself a t-of-n FROST
//! group with its own identifier space. The two identifier spaces are
//! independent and may collide numerically, so every collection in this
//! module is keyed by `(group, identifier)` and the binding-factor preimage
//! is domain-separated by a one-byte group tag:
//!
//! ```text
//! rho_i = H1(tag(group(i)) || vk || H4(msg) || H5(commitment_list) || id(i))
//! commitment_list = concatenation, over all signers of both groups sorted
//!                   by (tag, identifier), of
//!                   tag || identifier || hiding || binding
//! ```
//!
//! The tag appears both in each signer's own preimage and in every
//! commitment-list entry, so signers whose identifiers collide across groups
//! alias in neither the per-signer factor nor the commitment-set hash.
//! Everything else — the group commitment `R`, the challenge, per-signer
//! share computation and verification — reuses the [`Ciphersuite`] hooks
//! unchanged, so ciphersuite-specific behavior (e.g. BIP-340 even-Y nonce
//! negation, which is decided by the parity of the single `R` computed over
//! both groups' commitments) is identical to single-group signing. Existing
//! single-group entry points are untouched: callers select this scheme
//! explicitly by calling into this module.
//!
//! Like the participant-groups scheme, each signer's Lagrange coefficient is
//! computed within its own group over that group's participating identifiers,
//! and is folded into the signer's share; [`aggregate`] only ever sums shares.
//!
//! Limitations, by design: no adaptor points, and no ciphersuites whose
//! pre-processing hooks depend on the commitment set or transform signature
//! shares (the hooks are invoked with a synthetic single-group
//! [`SigningPackage`] carrying only the relevant group's commitments; every
//! ciphersuite in this workspace satisfies this, including
//! secp256k1-tr, whose hooks only normalize key material to even-Y).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{
    compute_lagrange_coefficient, keys, round1, round2, BindingFactor, Ciphersuite, Error, Field,
    Group, GroupCommitment, Identifier, Signature, SigningPackage, VerifyingKey,
};

/// Which of the two signing groups a signer belongs to.
///
/// The variant order defines the domain-separation tag byte and the
/// commitment-list ordering; it is part of the wire-level scheme and MUST NOT
/// change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignerGroup {
    /// The first group (tag byte `0x00`).
    Primary,
    /// The second group (tag byte `0x01`).
    Secondary,
}

impl SignerGroup {
    /// The domain-separation tag byte for this group.
    pub fn tag(self) -> u8 {
        match self {
            SignerGroup::Primary => 0x00,
            SignerGroup::Secondary => 0x01,
        }
    }
}

/// The group-tagged H1 preimages of every signer's binding factor, in
/// `(tag, identifier)` order.
pub type BindingFactorPreimages<C> = Vec<((SignerGroup, Identifier<C>), Vec<u8>)>;

type BindingFactors<C> = BTreeMap<(SignerGroup, Identifier<C>), BindingFactor<C>>;

/// The message and both groups' round-one commitments for one two-group
/// signing run.
///
/// The commitments of the two groups are kept in separate maps because their
/// identifier spaces are independent: the same identifier scalar may appear
/// in both groups and refers to two different signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoGroupSigningPackage<C: Ciphersuite> {
    primary_commitments: BTreeMap<Identifier<C>, round1::SigningCommitments<C>>,
    secondary_commitments: BTreeMap<Identifier<C>, round1::SigningCommitments<C>>,
    message: Vec<u8>,
}

impl<C: Ciphersuite> TwoGroupSigningPackage<C> {
    /// Creates a package from both groups' commitments and the message.
    /// Both groups must have at least one participating signer.
    pub fn new(
        primary_commitments: BTreeMap<Identifier<C>, round1::SigningCommitments<C>>,
        secondary_commitments: BTreeMap<Identifier<C>, round1::SigningCommitments<C>>,
        message: &[u8],
    ) -> Result<Self, Error<C>> {
        if primary_commitments.is_empty() || secondary_commitments.is_empty() {
            return Err(Error::IncorrectNumberOfCommitments);
        }
        Ok(Self {
            primary_commitments,
            secondary_commitments,
            message: message.to_vec(),
        })
    }

    /// The message to be signed.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The given group's commitments.
    pub fn signing_commitments(
        &self,
        group: SignerGroup,
    ) -> &BTreeMap<Identifier<C>, round1::SigningCommitments<C>> {
        match group {
            SignerGroup::Primary => &self.primary_commitments,
            SignerGroup::Secondary => &self.secondary_commitments,
        }
    }

    /// Iterates over all signers of both groups in `(tag, identifier)` order —
    /// the canonical order of the commitment-list encoding.
    fn iter_all(
        &self,
    ) -> impl Iterator<Item = (SignerGroup, &Identifier<C>, &round1::SigningCommitments<C>)> {
        self.primary_commitments
            .iter()
            .map(|(id, c)| (SignerGroup::Primary, id, c))
            .chain(
                self.secondary_commitments
                    .iter()
                    .map(|(id, c)| (SignerGroup::Secondary, id, c)),
            )
    }

    /// Encodes both groups' commitments in `(tag, identifier)` order, each
    /// entry as `tag || identifier || hiding || binding`.
    fn encode_tagged_commitments(&self) -> Result<Vec<u8>, Error<C>> {
        let mut bytes = Vec::new();
        for (group, identifier, commitment) in self.iter_all() {
            bytes.push(group.tag());
            bytes.extend_from_slice(identifier.serialize().as_ref());
            bytes.extend_from_slice(<C::Group>::serialize(&commitment.hiding.value())?.as_ref());
            bytes.extend_from_slice(<C::Group>::serialize(&commitment.binding.value())?.as_ref());
        }
        Ok(bytes)
    }

    /// Computes the group-tagged H1 preimages of every signer's binding
    /// factor, in `(tag, identifier)` order.
    pub fn binding_factor_preimages(
        &self,
        verifying_key: &VerifyingKey<C>,
    ) -> Result<BindingFactorPreimages<C>, Error<C>> {
        let mut common_suffix = Vec::new();
        common_suffix.extend_from_slice(verifying_key.serialize()?.as_ref());
        common_suffix.extend_from_slice(C::H4(&self.message).as_ref());
        common_suffix.extend_from_slice(C::H5(&self.encode_tagged_commitments()?).as_ref());

        Ok(self
            .iter_all()
            .map(|(group, identifier, _)| {
                let mut preimage = Vec::new();
                preimage.push(group.tag());
                preimage.extend_from_slice(&common_suffix);
                preimage.extend_from_slice(identifier.serialize().as_ref());
                ((group, *identifier), preimage)
            })
            .collect())
    }

    fn compute_binding_factors(
        &self,
        verifying_key: &VerifyingKey<C>,
    ) -> Result<BindingFactors<C>, Error<C>> {
        Ok(self
            .binding_factor_preimages(verifying_key)?
            .into_iter()
            .map(|(key, preimage)| (key, BindingFactor(C::H1(&preimage))))
            .collect())
    }

    /// Computes the single group commitment `R` over both groups'
    /// commitments. Mirrors [`crate::compute_group_commitment`], with the
    /// binding factors keyed by `(group, identifier)`.
    fn compute_group_commitment(
        &self,
        binding_factors: &BindingFactors<C>,
    ) -> Result<GroupCommitment<C>, Error<C>> {
        let identity = <C::Group as Group>::identity();
        let mut group_commitment = identity;

        let mut binding_scalars = Vec::new();
        let mut binding_elements = Vec::new();

        for (group, identifier, commitment) in self.iter_all() {
            // The following check prevents a party from accidentally revealing their share.
            if identity == commitment.binding.value() || identity == commitment.hiding.value() {
                return Err(Error::IdentityCommitment);
            }

            let binding_factor = binding_factors
                .get(&(group, *identifier))
                .ok_or(Error::UnknownIdentifier)?;

            binding_elements.push(commitment.binding.value());
            binding_scalars.push(binding_factor.0);

            group_commitment = group_commitment + commitment.hiding.value();
        }

        let accumulated_binding_commitment =
            crate::scalar_mul::VartimeMultiscalarMul::<C>::vartime_multiscalar_mul(
                binding_scalars,
                binding_elements,
            );

        Ok(GroupCommitment(
            group_commitment + accumulated_binding_commitment,
        ))
    }
}

/// Produces one signer's signature share in a two-group signing run.
///
/// `group` states which group the signer belongs to; it is an explicit input
/// because the two identifier spaces may collide, so membership cannot be
/// inferred from `key_package.identifier`. The signer's Lagrange coefficient
/// is computed within its own group's participating set and folded into the
/// returned share.
pub fn sign<C: Ciphersuite>(
    signing_package: &TwoGroupSigningPackage<C>,
    signer_nonces: &round1::SigningNonces<C>,
    key_package: &keys::KeyPackage<C>,
    group: SignerGroup,
) -> Result<round2::SignatureShare<C>, Error<C>> {
    let own_commitments = signing_package.signing_commitments(group);

    if own_commitments.len() < key_package.min_signers as usize {
        return Err(Error::IncorrectNumberOfCommitments);
    }

    let commitment = own_commitments
        .get(&key_package.identifier)
        .ok_or(Error::MissingCommitment)?;
    if &signer_nonces.commitments != commitment {
        return Err(Error::IncorrectCommitment);
    }

    // Run the ciphersuite sign pre-processing (e.g. secp256k1-tr even-Y key
    // normalization) with a synthetic single-group package; see the module
    // docs for why this is sound.
    let synthetic = SigningPackage::new(own_commitments.clone(), signing_package.message());
    let (_, signer_nonces, key_package) = <C>::pre_sign(&synthetic, signer_nonces, key_package)?;

    let binding_factors = signing_package.compute_binding_factors(&key_package.verifying_key)?;
    let binding_factor = binding_factors
        .get(&(group, key_package.identifier))
        .ok_or(Error::UnknownIdentifier)?
        .clone();

    let group_commitment = signing_package.compute_group_commitment(&binding_factors)?;

    let own_participants: BTreeSet<Identifier<C>> = own_commitments.keys().copied().collect();
    let lambda_i = compute_lagrange_coefficient(&own_participants, None, key_package.identifier)?;

    let challenge = <C>::challenge(
        &group_commitment.0,
        &key_package.verifying_key,
        signing_package.message(),
    )?;

    Ok(<C>::compute_signature_share(
        &group_commitment,
        &signer_nonces,
        binding_factor,
        lambda_i,
        &key_package,
        challenge,
    ))
}

/// Aggregates both groups' signature shares into the final signature and
/// verifies it against `pubkeys.verifying_key` (the combined key both groups
/// signed under).
///
/// `pubkeys` carries verifying shares for the **primary** group only. If the
/// aggregate does not verify, every primary share is checked individually and
/// the culprits reported via [`Error::InvalidSignatureShare`]; if all primary
/// shares verify, the failure lies with the secondary group (or with
/// inconsistent inputs), for which no per-signer verification material
/// exists, and [`Error::InvalidSignature`] is returned without blame.
pub fn aggregate<C: Ciphersuite>(
    signing_package: &TwoGroupSigningPackage<C>,
    primary_shares: &BTreeMap<Identifier<C>, round2::SignatureShare<C>>,
    secondary_shares: &BTreeMap<Identifier<C>, round2::SignatureShare<C>>,
    pubkeys: &keys::PublicKeyPackage<C>,
) -> Result<Signature<C>, Error<C>> {
    for (group, shares) in [
        (SignerGroup::Primary, primary_shares),
        (SignerGroup::Secondary, secondary_shares),
    ] {
        let commitments = signing_package.signing_commitments(group);
        if commitments.len() != shares.len()
            || !commitments.keys().all(|id| shares.contains_key(id))
        {
            return Err(Error::UnknownIdentifier);
        }
    }
    if !signing_package
        .signing_commitments(SignerGroup::Primary)
        .keys()
        .all(|id| pubkeys.verifying_shares.contains_key(id))
    {
        return Err(Error::UnknownIdentifier);
    }

    if let Some(min) = pubkeys.min_signers() {
        if primary_shares.len() < min as usize {
            return Err(Error::IncorrectNumberOfShares);
        }
    }

    // Run the ciphersuite aggregate pre-processing (e.g. secp256k1-tr even-Y
    // public-key normalization) with a synthetic single-group package; see
    // the module docs for why this is sound.
    let synthetic = SigningPackage::new(
        signing_package
            .signing_commitments(SignerGroup::Primary)
            .clone(),
        signing_package.message(),
    );
    let (_, primary_shares, pubkeys) = <C>::pre_aggregate(&synthetic, primary_shares, pubkeys)?;

    let binding_factors = signing_package.compute_binding_factors(&pubkeys.verifying_key)?;
    let group_commitment = signing_package.compute_group_commitment(&binding_factors)?;

    let mut z = <<C::Group as Group>::Field as Field>::zero();
    for share in primary_shares.values().chain(secondary_shares.values()) {
        z = z + share.to_scalar();
    }

    let signature = Signature {
        R: group_commitment.0,
        z,
    };

    if pubkeys
        .verifying_key
        .verify(signing_package.message(), &signature)
        .is_ok()
    {
        return Ok(signature);
    }

    // The aggregate did not verify: check each primary share to assign blame.
    let challenge = <C>::challenge(
        &group_commitment.0,
        &pubkeys.verifying_key,
        signing_package.message(),
    )?;
    let primary_participants: BTreeSet<Identifier<C>> = signing_package
        .signing_commitments(SignerGroup::Primary)
        .keys()
        .copied()
        .collect();

    let mut culprits = Vec::new();
    for (identifier, share) in primary_shares.iter() {
        let commitment = signing_package
            .signing_commitments(SignerGroup::Primary)
            .get(identifier)
            .ok_or(Error::UnknownIdentifier)?;
        let binding_factor = binding_factors
            .get(&(SignerGroup::Primary, *identifier))
            .ok_or(Error::UnknownIdentifier)?;
        let verifying_share = pubkeys
            .verifying_shares
            .get(identifier)
            .ok_or(Error::UnknownIdentifier)?;
        let lambda_i = compute_lagrange_coefficient(&primary_participants, None, *identifier)?;
        let commitment_share = commitment.to_group_commitment_share(binding_factor);

        if <C>::verify_share(
            &group_commitment,
            share,
            *identifier,
            &commitment_share,
            verifying_share,
            lambda_i,
            &challenge,
        )
        .is_err()
        {
            culprits.push(*identifier);
        }
    }

    if culprits.is_empty() {
        Err(Error::InvalidSignature)
    } else {
        Err(Error::InvalidSignatureShare { culprits })
    }
}
