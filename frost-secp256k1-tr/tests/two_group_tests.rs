//! Tests for two-group signing with group-tagged binding factors
//! (`frost_core::two_group`) over the secp256k1-tr ciphersuite.

use std::collections::BTreeMap;
use std::error::Error;

use frost_core::two_group::{self, SignerGroup, TwoGroupSigningPackage};
use frost_secp256k1_tr as frost;

use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage, Tweak};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, VerifyingKey};

struct Groups {
    primary_kps: BTreeMap<Identifier, KeyPackage>,
    secondary_kps: BTreeMap<Identifier, KeyPackage>,
    /// Primary verifying shares under the combined key, for aggregation.
    pubkeys: PublicKeyPackage,
    combined_vk: VerifyingKey,
}

/// Generates two independent dealer groups whose secrets add up to the key
/// behind `combined_vk`, with every key package rewritten to carry the
/// combined verifying key (the key both groups jointly sign under).
fn make_groups(
    primary: (u16, u16),
    secondary: (u16, u16),
    primary_ids: Option<&[Identifier]>,
    secondary_ids: Option<&[Identifier]>,
) -> Result<Groups, Box<dyn Error>> {
    let rng = rand::rngs::OsRng;
    let id_list = |ids: Option<&[Identifier]>| match ids {
        Some(ids) => IdentifierList::Custom(ids.to_vec().leak()),
        None => IdentifierList::Default,
    };
    let (p_shares, p_pub) =
        frost::keys::generate_with_dealer(primary.0, primary.1, id_list(primary_ids), rng)?;
    let (s_shares, s_pub) =
        frost::keys::generate_with_dealer(secondary.0, secondary.1, id_list(secondary_ids), rng)?;

    let combined_vk =
        VerifyingKey::new(p_pub.verifying_key().to_element() + s_pub.verifying_key().to_element());

    let rebuild = |shares: BTreeMap<Identifier, frost::keys::SecretShare>,
                   min: u16|
     -> Result<BTreeMap<Identifier, KeyPackage>, Box<dyn Error>> {
        shares
            .into_iter()
            .map(|(id, share)| {
                let kp = KeyPackage::try_from(share)?;
                Ok((
                    id,
                    KeyPackage::new(
                        id,
                        *kp.signing_share(),
                        *kp.verifying_share(),
                        combined_vk,
                        min,
                    ),
                ))
            })
            .collect()
    };

    Ok(Groups {
        primary_kps: rebuild(p_shares, primary.1)?,
        secondary_kps: rebuild(s_shares, secondary.1)?,
        pubkeys: PublicKeyPackage::new(
            p_pub.verifying_shares().clone(),
            combined_vk,
            Some(primary.1),
        ),
        combined_vk,
    })
}

type Round1 = (
    BTreeMap<Identifier, SigningNonces>,
    BTreeMap<Identifier, SigningCommitments>,
);

fn commit_round(kps: &BTreeMap<Identifier, KeyPackage>, signers: &[Identifier]) -> Round1 {
    let mut rng = rand::rngs::OsRng;
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for id in signers {
        let (nonces, commitments) = frost::round1::commit(kps[id].signing_share(), &mut rng);
        nonces_map.insert(*id, nonces);
        commitments_map.insert(*id, commitments);
    }
    (nonces_map, commitments_map)
}

fn sign_group(
    package: &TwoGroupSigningPackage<frost::Secp256K1Sha256TR>,
    kps: &BTreeMap<Identifier, KeyPackage>,
    nonces: &BTreeMap<Identifier, SigningNonces>,
    group: SignerGroup,
) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>> {
    nonces
        .iter()
        .map(|(id, n)| Ok((*id, two_group::sign(package, n, &kps[id], group)?)))
        .collect()
}

fn ids(range: std::ops::RangeInclusive<u16>) -> Vec<Identifier> {
    range
        .map(|i| i.try_into().expect("nonzero identifier"))
        .collect()
}

#[test]
fn sign_and_aggregate_verifies() -> Result<(), Box<dyn Error>> {
    // Default identifier lists give BOTH groups identifiers 1..=n, so every
    // run of this test also exercises cross-group identifier collisions.
    // Iterate so both parities of the aggregate nonce R occur.
    for _ in 0..8 {
        let groups = make_groups((5, 3), (3, 2), None, None)?;
        let message = b"two-group message";

        let (p_nonces, p_commitments) = commit_round(&groups.primary_kps, &ids(1..=3));
        let (s_nonces, s_commitments) = commit_round(&groups.secondary_kps, &ids(1..=2));
        let package = TwoGroupSigningPackage::new(p_commitments, s_commitments, message)?;

        let p_shares = sign_group(
            &package,
            &groups.primary_kps,
            &p_nonces,
            SignerGroup::Primary,
        )?;
        let s_shares = sign_group(
            &package,
            &groups.secondary_kps,
            &s_nonces,
            SignerGroup::Secondary,
        )?;

        let signature = two_group::aggregate(&package, &p_shares, &s_shares, &groups.pubkeys)?;
        groups.combined_vk.verify(message, &signature)?;
    }
    Ok(())
}

#[test]
fn colliding_identifiers_get_distinct_tagged_binding_factors() -> Result<(), Box<dyn Error>> {
    let groups = make_groups((3, 2), (3, 2), None, None)?;
    let message = b"collision message";

    let (_, p_commitments) = commit_round(&groups.primary_kps, &ids(1..=2));
    let (_, s_commitments) = commit_round(&groups.secondary_kps, &ids(1..=2));
    let package = TwoGroupSigningPackage::new(p_commitments, s_commitments, message)?;

    let preimages: BTreeMap<_, _> = package
        .binding_factor_preimages(&groups.combined_vk)?
        .into_iter()
        .collect();
    let id1: Identifier = 1u16.try_into()?;
    let primary = &preimages[&(SignerGroup::Primary, id1)];
    let secondary = &preimages[&(SignerGroup::Secondary, id1)];

    assert_eq!(primary.first(), Some(&0x00));
    assert_eq!(secondary.first(), Some(&0x01));
    // Same identifier, same commitment set — only the tag distinguishes them.
    assert_eq!(primary[1..], secondary[1..]);
    assert_ne!(primary, secondary);
    Ok(())
}

#[test]
fn tampered_primary_shares_are_blamed() -> Result<(), Box<dyn Error>> {
    let groups = make_groups((5, 3), (3, 2), None, None)?;
    let message = b"blame message";

    let (p_nonces, p_commitments) = commit_round(&groups.primary_kps, &ids(1..=3));
    let (s_nonces, s_commitments) = commit_round(&groups.secondary_kps, &ids(1..=2));
    let package = TwoGroupSigningPackage::new(p_commitments, s_commitments, message)?;

    let mut p_shares = sign_group(
        &package,
        &groups.primary_kps,
        &p_nonces,
        SignerGroup::Primary,
    )?;
    let s_shares = sign_group(
        &package,
        &groups.secondary_kps,
        &s_nonces,
        SignerGroup::Secondary,
    )?;

    let id1: Identifier = 1u16.try_into()?;
    p_shares.insert(id1, corrupt(&p_shares[&id1])?);

    let err = two_group::aggregate(&package, &p_shares, &s_shares, &groups.pubkeys)
        .expect_err("tampered primary share must not aggregate");
    match err {
        frost::Error::InvalidSignatureShare { culprits } => {
            assert_eq!(culprits, vec![id1]);
        }
        other => panic!("expected InvalidSignatureShare, got {other:?}"),
    }
    Ok(())
}

/// Returns a share whose scalar differs from the input's (flips the low byte).
fn corrupt(share: &SignatureShare) -> Result<SignatureShare, Box<dyn Error>> {
    let mut bytes = share.serialize();
    let last = bytes.last_mut().expect("share serialization is nonempty");
    *last = last.wrapping_add(1);
    Ok(SignatureShare::deserialize(&bytes)?)
}

#[test]
fn bad_secondary_share_fails_without_blame() -> Result<(), Box<dyn Error>> {
    let groups = make_groups((5, 3), (3, 2), None, None)?;
    let message = b"secondary failure message";

    let (p_nonces, p_commitments) = commit_round(&groups.primary_kps, &ids(1..=3));
    let (s_nonces, s_commitments) = commit_round(&groups.secondary_kps, &ids(1..=2));
    let package = TwoGroupSigningPackage::new(p_commitments, s_commitments, message)?;

    let p_shares = sign_group(
        &package,
        &groups.primary_kps,
        &p_nonces,
        SignerGroup::Primary,
    )?;
    let mut s_shares = sign_group(
        &package,
        &groups.secondary_kps,
        &s_nonces,
        SignerGroup::Secondary,
    )?;

    let id1: Identifier = 1u16.try_into()?;
    s_shares.insert(id1, corrupt(&s_shares[&id1])?);

    // No per-signer verification material exists for the secondary group, so
    // the failure is reported without blame.
    let err = two_group::aggregate(&package, &p_shares, &s_shares, &groups.pubkeys)
        .expect_err("tampered secondary shares must not aggregate");
    assert!(matches!(err, frost::Error::InvalidSignature));
    Ok(())
}

#[test]
fn divergent_primary_commitment_view_fails_loudly() -> Result<(), Box<dyn Error>> {
    let groups = make_groups((5, 3), (3, 2), None, None)?;
    let message = b"divergent view message";

    let (p_nonces, p_commitments) = commit_round(&groups.primary_kps, &ids(1..=3));
    let (s_nonces, s_commitments) = commit_round(&groups.secondary_kps, &ids(1..=2));
    let package =
        TwoGroupSigningPackage::new(p_commitments.clone(), s_commitments.clone(), message)?;

    let p_shares = sign_group(
        &package,
        &groups.primary_kps,
        &p_nonces,
        SignerGroup::Primary,
    )?;

    // One secondary signer binds a different primary commitment set (its own
    // freshly resampled commitment for primary signer 1).
    let id1: Identifier = 1u16.try_into()?;
    let id2: Identifier = 2u16.try_into()?;
    let mut divergent_p_commitments = p_commitments;
    let (_, resampled) = frost::round1::commit(
        groups.primary_kps[&id1].signing_share(),
        &mut rand::rngs::OsRng,
    );
    divergent_p_commitments.insert(id1, resampled);
    let divergent_package =
        TwoGroupSigningPackage::new(divergent_p_commitments, s_commitments, message)?;

    let mut s_shares = BTreeMap::new();
    s_shares.insert(
        id1,
        two_group::sign(
            &divergent_package,
            &s_nonces[&id1],
            &groups.secondary_kps[&id1],
            SignerGroup::Secondary,
        )?,
    );
    s_shares.insert(
        id2,
        two_group::sign(
            &package,
            &s_nonces[&id2],
            &groups.secondary_kps[&id2],
            SignerGroup::Secondary,
        )?,
    );

    // All primary shares verify against the true package, so the divergence
    // is detected by the aggregate check and reported without blame.
    let err = two_group::aggregate(&package, &p_shares, &s_shares, &groups.pubkeys)
        .expect_err("divergent commitment views must not aggregate");
    assert!(matches!(err, frost::Error::InvalidSignature));
    Ok(())
}

#[test]
fn tweaked_two_group_sign_and_aggregate_verifies() -> Result<(), Box<dyn Error>> {
    // Mirrors the deployed taproot convention: the taptweak scalar enters the
    // key sum exactly once, on the secondary (user) side, which calls
    // `tweak()` at signing time on a key package carrying the untweaked
    // combined key. Primary (operator) key packages are pre-normalized to the
    // untweaked combined key's parity and carry the tweaked combined key, and
    // sign without further tweaking. The aggregation public-key package holds
    // the tweaked combined key and the primary verifying shares exactly as
    // the primary signers signed (pre-normalized, no tweak).
    use frost::keys::{EvenY, VerifyingShare};

    let merkle_root: Vec<u8> = vec![];
    for _ in 0..4 {
        let groups = make_groups((5, 3), (3, 2), None, None)?;
        let message = b"tweaked two-group message";

        let untweaked_vk = groups.combined_vk;
        let tweaked_vk = *PublicKeyPackage::new(BTreeMap::new(), untweaked_vk, None)
            .tweak(Some(&merkle_root))
            .verifying_key();

        let mut primary_kps = BTreeMap::new();
        let mut primary_verifying_shares: BTreeMap<Identifier, VerifyingShare> = BTreeMap::new();
        for (id, kp) in &groups.primary_kps {
            let normalized = kp.clone().into_even_y(Some(untweaked_vk.has_even_y()));
            primary_verifying_shares.insert(*id, *normalized.verifying_share());
            primary_kps.insert(
                *id,
                KeyPackage::new(
                    *id,
                    *normalized.signing_share(),
                    *normalized.verifying_share(),
                    tweaked_vk,
                    *kp.min_signers(),
                ),
            );
        }

        let (p_nonces, p_commitments) = commit_round(&primary_kps, &ids(1..=3));
        let (s_nonces, s_commitments) = commit_round(&groups.secondary_kps, &ids(1..=2));
        let package = TwoGroupSigningPackage::new(p_commitments, s_commitments, message)?;

        let p_shares = sign_group(&package, &primary_kps, &p_nonces, SignerGroup::Primary)?;
        let tweaked_secondary_kps = groups
            .secondary_kps
            .iter()
            .map(|(id, kp)| (*id, kp.clone().tweak(Some(&merkle_root))))
            .collect::<BTreeMap<_, _>>();
        let s_shares = sign_group(
            &package,
            &tweaked_secondary_kps,
            &s_nonces,
            SignerGroup::Secondary,
        )?;

        let pubkeys = PublicKeyPackage::new(primary_verifying_shares, tweaked_vk, Some(3));
        let signature = two_group::aggregate(&package, &p_shares, &s_shares, &pubkeys)?;
        tweaked_vk.verify(message, &signature)?;

        untweaked_vk
            .verify(message, &signature)
            .expect_err("signature must not verify under the untweaked key");
    }
    Ok(())
}

#[test]
fn tagged_scheme_differs_from_flat_participant_groups() -> Result<(), Box<dyn Error>> {
    // With collision-free identifiers the flat participant-groups scheme (the
    // deployed nested-signing path) can sign the same message with the same
    // nonces; the group tag must still change the binding factors, so the two
    // schemes must produce different signatures (both valid).
    let secondary_ids = ids(101..=103);
    let groups = make_groups((3, 2), (3, 2), None, Some(&secondary_ids))?;
    let message = b"scheme divergence message";

    let p_signers = ids(1..=2);
    let s_signers = ids(101..=102);
    let (p_nonces, p_commitments) = commit_round(&groups.primary_kps, &p_signers);
    let (s_nonces, s_commitments) = commit_round(&groups.secondary_kps, &s_signers);

    // Tagged two-group signature.
    let package =
        TwoGroupSigningPackage::new(p_commitments.clone(), s_commitments.clone(), message)?;
    let p_shares = sign_group(
        &package,
        &groups.primary_kps,
        &p_nonces,
        SignerGroup::Primary,
    )?;
    let s_shares = sign_group(
        &package,
        &groups.secondary_kps,
        &s_nonces,
        SignerGroup::Secondary,
    )?;
    let tagged_signature = two_group::aggregate(&package, &p_shares, &s_shares, &groups.pubkeys)?;

    // Flat participant-groups signature over the same commitments and nonces.
    let mut flat_commitments = p_commitments;
    flat_commitments.extend(s_commitments);
    let flat_package = frost::SigningPackage::new_with_participants_groups(
        flat_commitments,
        Some(vec![
            p_signers.iter().copied().collect(),
            s_signers.iter().copied().collect(),
        ]),
        message,
    );
    let mut flat_shares = BTreeMap::new();
    for (id, nonces) in p_nonces.iter().chain(s_nonces.iter()) {
        let kps = if p_nonces.contains_key(id) {
            &groups.primary_kps
        } else {
            &groups.secondary_kps
        };
        flat_shares.insert(*id, frost::round2::sign(&flat_package, nonces, &kps[id])?);
    }
    let mut all_verifying_shares = groups.pubkeys.verifying_shares().clone();
    for (id, kp) in &groups.secondary_kps {
        all_verifying_shares.insert(*id, *kp.verifying_share());
    }
    let flat_pubkeys = PublicKeyPackage::new(all_verifying_shares, groups.combined_vk, None);
    let flat_signature = frost::aggregate(&flat_package, &flat_shares, &flat_pubkeys)?;

    assert_ne!(
        tagged_signature.serialize()?,
        flat_signature.serialize()?,
        "the group tag must change the binding factors and hence the signature"
    );
    groups.combined_vk.verify(message, &tagged_signature)?;
    groups.combined_vk.verify(message, &flat_signature)?;
    Ok(())
}
