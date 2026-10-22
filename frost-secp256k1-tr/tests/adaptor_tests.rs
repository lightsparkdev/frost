use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::Tweak;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;

// Spark signs and aggregates adaptor signatures with an empty merkle root.
const MERKLE_ROOT: &[u8] = &[];
const MESSAGE: &[u8] = b"message to sign";

struct Session {
    key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkey_package: frost::keys::PublicKeyPackage,
    nonces: BTreeMap<frost::Identifier, frost::round1::SigningNonces>,
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
}

fn session() -> Session {
    let mut rng = rand::rngs::OsRng;
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng).unwrap();
    let key_packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key_package) in &key_packages {
        let (n, c) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    Session {
        key_packages,
        pubkey_package,
        nonces,
        commitments,
    }
}

fn adaptor() -> (Scalar, frost::VerifyingKey) {
    let signing_key = frost::SigningKey::new(&mut rand::rngs::OsRng);
    let secret: [u8; 32] = signing_key.serialize().try_into().unwrap();
    let secret = Scalar::from_repr(secret.into()).unwrap();
    (secret, frost::VerifyingKey::from(&signing_key))
}

fn package(s: &Session, adaptor: frost::VerifyingKey, v2: bool) -> frost::SigningPackage {
    if v2 {
        frost::SigningPackage::new_with_adaptor_v2(
            s.commitments.clone(),
            None,
            MESSAGE,
            Some(adaptor),
        )
    } else {
        frost::SigningPackage::new_with_adaptor(s.commitments.clone(), None, MESSAGE, Some(adaptor))
    }
}

fn sign(
    s: &Session,
    package: &frost::SigningPackage,
) -> BTreeMap<frost::Identifier, frost::round2::SignatureShare> {
    s.key_packages
        .iter()
        .map(|(id, key_package)| {
            let share = frost::round2::sign_with_tweak(
                package,
                &s.nonces[id],
                key_package,
                Some(MERKLE_ROOT),
            )
            .unwrap();
            (*id, share)
        })
        .collect()
}

fn aggregate(
    s: &Session,
    package: &frost::SigningPackage,
    shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
) -> Result<frost::Signature, frost::Error> {
    frost::aggregate_with_tweak(package, shares, &s.pubkey_package, Some(MERKLE_ROOT))
}

/// Adds or subtracts the adaptor secret, as the nonce parity requires, and
/// returns how many of the two completions verify.
fn completions_that_verify(s: &Session, pre_signature: &frost::Signature, secret: Scalar) -> usize {
    let bytes = pre_signature.serialize().unwrap();
    let z: [u8; 32] = bytes[32..].try_into().unwrap();
    let z = Scalar::from_repr(z.into()).unwrap();
    let verifying_key = s
        .pubkey_package
        .clone()
        .tweak(Some(MERKLE_ROOT))
        .verifying_key()
        .to_owned();
    [z + secret, z - secret]
        .into_iter()
        .filter(|completed| {
            let mut completed_bytes = bytes.clone();
            completed_bytes[32..].copy_from_slice(&completed.to_bytes());
            let signature = frost::Signature::deserialize(&completed_bytes).unwrap();
            verifying_key.verify(MESSAGE, &signature).is_ok()
        })
        .count()
}

#[test]
fn check_adaptor_signature_completes() {
    // Enough fresh sessions that both nonce parities occur.
    for _ in 0..16 {
        for v2 in [false, true] {
            let s = session();
            let (secret, adaptor) = adaptor();
            let package = package(&s, adaptor, v2);
            let pre_signature = aggregate(&s, &package, &sign(&s, &package)).unwrap();
            assert_eq!(completions_that_verify(&s, &pre_signature, secret), 1);
        }
    }
}

#[test]
fn check_adaptor_v2_shares_depend_on_adaptor() {
    let s = session();
    let (secret, adaptor_1) = adaptor();
    let (_, adaptor_2) = adaptor();
    let id = *s.key_packages.keys().next().unwrap();

    let v1 = sign(&s, &package(&s, adaptor_1, false));
    let v2 = sign(&s, &package(&s, adaptor_1, true));
    let v2_other = sign(&s, &package(&s, adaptor_2, true));
    assert_ne!(v1[&id], v2[&id]);
    assert_ne!(v2[&id], v2_other[&id]);

    // Shares from one version don't complete under the other.
    let mismatched = aggregate(&s, &package(&s, adaptor_1, false), &v2).unwrap();
    assert_eq!(completions_that_verify(&s, &mismatched, secret), 0);
}
