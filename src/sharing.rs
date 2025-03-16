use generic_array::GenericArray;
use itertools::{Itertools, izip};
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{FiniteField, IsSubFieldOf},
    serialization::CanonicalSerialize,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    ops::Add,
};

use crate::error::GcError;

#[derive(Clone, PartialEq, Eq)]
pub struct AuthShare<ShareFF, MacFF>
where
    ShareFF: FiniteField,
    MacFF: FiniteField,
{
    /// The party ID that holds this share.
    /// We use a small type to minimize message size.
    pub party_id: u16,
    /// The secret share x^i.
    pub share: ShareFF,
    /// The MACs M_j[x^i], where value M_j[x^i] is under key j.
    /// The btree is keyed on j (the other party's index).
    pub mac_values: BTreeMap<u16, MacFF>,
    /// The MAC keys K_i[x^j], where value K_i[x^j] is under key i.
    /// The btree is keyed on j (the other party's index).
    pub mac_keys: BTreeMap<u16, MacFF>,
}

impl<ShareFF, MacFF> AuthShare<ShareFF, MacFF>
where
    ShareFF: FiniteField,
    MacFF: FiniteField + CanonicalSerialize,
{
    pub fn serialize_mac_values<W: Write>(&self, writer: &mut W) {
        // iterating is sorted by key
        for v in self.mac_values.values() {
            writer.write_all(&v.to_bytes()).unwrap();
        }
    }

    pub fn deserialize_mac_values<R: Read>(&mut self, party_count: u16, reader: &mut R) {
        if !self.mac_values.is_empty() {
            panic!("reading mac values into AuthShare that's not empty")
        }
        let mut buf = GenericArray::<u8, MacFF::ByteReprLen>::default();
        for i in 0..party_count {
            if i != self.party_id {
                reader
                    .read_exact(&mut buf)
                    .unwrap_or_else(|_| panic!("reading failed for i={i}"));
                self.mac_values.insert(i, MacFF::from_bytes(&buf).unwrap());
            }
        }
    }

    pub fn sum_mac_keys(&self) -> MacFF {
        // Sum trait is not implemented, so we use fold
        self.mac_keys.values().fold(MacFF::ZERO, |acc, x| acc + *x)
    }

    pub fn sum_mac_values(&self) -> MacFF {
        // Sum trait is not implemented, so we use fold
        self.mac_values
            .values()
            .fold(MacFF::ZERO, |acc, x| acc + *x)
    }

    pub fn check_against_incoming_macs(
        &self,
        mac_values: &[MacFF],
        delta: &MacFF,
    ) -> Result<(), GcError>
    where
        ShareFF: IsSubFieldOf<MacFF>,
    {
        // if MACs are given as a vector
        // we assume they're indexed from 0 to n-2 (length of n-1)
        let final_index = mac_values.len() as u16;
        assert!(!self.mac_keys.keys().contains(&final_index));
        assert_eq!(self.party_id, final_index);
        for (key, mac) in self.mac_keys.values().zip(mac_values) {
            if *mac != (self.share * *delta) + *key {
                return Err(GcError::MacCheckFailure);
            }
        }
        Ok(())
    }
}

macro_rules! impl_add {
    ($for_type:ty) => {
        impl<ShareFF, MacFF> Add<&AuthShare<ShareFF, MacFF>> for $for_type
        where
            ShareFF: FiniteField,
            MacFF: FiniteField,
        {
            type Output = AuthShare<ShareFF, MacFF>;

            fn add(self, rhs: &AuthShare<ShareFF, MacFF>) -> Self::Output {
                assert_eq!(self.party_id, rhs.party_id);
                let new_share = self.share + rhs.share;
                let new_mac_values = self
                    .mac_values
                    .keys()
                    .map(|j| (*j, self.mac_values[j] + rhs.mac_values[j]))
                    .collect::<BTreeMap<_, _>>();
                let new_mac_keys = self
                    .mac_keys
                    .keys()
                    .map(|j| (*j, self.mac_keys[j] + rhs.mac_keys[j]))
                    .collect::<BTreeMap<_, _>>();
                Self::Output {
                    party_id: self.party_id,
                    share: new_share,
                    mac_values: new_mac_values,
                    mac_keys: new_mac_keys,
                }
            }
        }
    };
}

impl_add!(AuthShare<ShareFF, MacFF>);
impl_add!(&AuthShare<ShareFF, MacFF>);

pub fn secret_share_with_delta<ShareFF, MacFF, R>(
    secret: ShareFF,
    deltas: &[MacFF],
    rng: &mut R,
) -> Vec<AuthShare<ShareFF, MacFF>>
where
    ShareFF: FiniteField,
    MacFF: FiniteField,
    ShareFF: IsSubFieldOf<MacFF>,
    R: Rng + CryptoRng,
{
    let n = deltas.len() as u16;
    assert!(n > 0);
    let mut shares = (0..n).map(|_| ShareFF::random(rng)).collect_vec();

    // Sum trait is not implemented, so we use fold
    let sum_shares = shares.iter().fold(ShareFF::ZERO, |acc, x| acc + *x);
    // Correct the first share so that the sum of shares is the secret
    shares[0] = shares[0] + secret - sum_shares;

    // all the mac keys, ordered by party
    let mut mac_keys = Vec::with_capacity((n * n) as usize);
    for i in 0..n {
        let mut party_i_keys = BTreeMap::new();
        for j in 0..n {
            if i != j {
                party_i_keys.insert(j, MacFF::random(rng));
            }
        }
        mac_keys.push(party_i_keys);
    }

    // all the macs, ordered by party
    let mut mac_values = Vec::with_capacity((n * n) as usize);
    for i in 0..n {
        let mut party_i_macs = BTreeMap::new();
        for j in 0..n {
            if i != j {
                // MAC_j[x^i] = x^i * Delta_j + K_j[x^i]
                let m_j_i = shares[i as usize] * deltas[j as usize] + mac_keys[j as usize][&i];
                party_i_macs.insert(j, m_j_i);
            }
        }
        mac_values.push(party_i_macs);
    }

    // assemble everything together
    izip!(0..n, shares, mac_values, mac_keys)
        .map(|(i, share, mac, key)| AuthShare {
            party_id: i,
            share,
            mac_values: mac,
            mac_keys: key,
        })
        .collect()
}

pub fn secret_share<ShareFF, MacFF, R>(
    secret: ShareFF,
    n: u16,
    rng: &mut R,
) -> (Vec<AuthShare<ShareFF, MacFF>>, Vec<MacFF>)
where
    ShareFF: FiniteField,
    MacFF: FiniteField,
    ShareFF: IsSubFieldOf<MacFF>,
    R: Rng + CryptoRng,
{
    // Generate the global Deltas
    let deltas = (0..n).map(|_| MacFF::random(rng)).collect_vec();
    (secret_share_with_delta(secret, &deltas, rng), deltas)
}

pub fn verify_and_reconstruct<ShareFF, MacFF>(
    n: u16,
    shares: Vec<AuthShare<ShareFF, MacFF>>,
    deltas: Vec<MacFF>,
) -> Result<ShareFF, GcError>
where
    ShareFF: FiniteField,
    MacFF: FiniteField,
    ShareFF: IsSubFieldOf<MacFF>,
{
    // we need to check, for every shares x^i such that
    // M_j[x^i] = x^i \Delta_j + K_j[x^i], for j in [n] \ i
    // held by i                 held by j
    for i in 0..n {
        for j in 0..n {
            if i != j {
                let m_j_i = shares[i as usize].mac_values[&j];
                let delta_j = deltas[j as usize];
                let k_j_i = shares[j as usize].mac_keys[&i];
                let share_i = shares[i as usize].share;

                if m_j_i != share_i * delta_j + k_j_i {
                    return Err(GcError::MacCheckFailure);
                }
            }
        }
    }

    let result = shares.iter().fold(ShareFF::ZERO, |acc, x| acc + x.share);

    Ok(result)
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;
    use scuttlebutt::{AesRng, ring::FiniteRing};
    use swanky_field_binary::{F2, F128b};

    #[test]
    fn test_sharing_sunshine() {
        let mut rng = AesRng::new();
        let n = 10u16;
        let secret = F2::random(&mut rng);
        let (shares, deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);
        assert_eq!(secret, verify_and_reconstruct(n, shares, deltas).unwrap());
    }

    #[test]
    fn test_sharing_failure() {
        let mut rng = AesRng::new();
        let n = 10u16;
        let secret = F2::random(&mut rng);
        {
            // modify a share
            let (mut shares, deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);
            shares[0].share += F2::ONE;
            verify_and_reconstruct(n, shares, deltas).unwrap_err();
        }
        {
            // modify a delta
            let (shares, mut deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);
            deltas[0] += F128b::ONE;
            verify_and_reconstruct(n, shares, deltas).unwrap_err();
        }
    }

    #[test]
    fn test_reading_mac_values() {
        let mut rng = AesRng::new();
        let n = 10u16;
        let secret = F2::random(&mut rng);
        let (shares, _deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);

        let mut writer = Cursor::new(vec![]);
        let share_orig = shares[0].clone();
        let mut share_new = share_orig.clone();
        share_new.mac_values = BTreeMap::new();

        share_orig.serialize_mac_values(&mut writer);
        assert_eq!(writer.get_ref().len(), (n as usize - 1) * (128 / 8));

        let mut buf = Cursor::new(writer.into_inner());
        share_new.deserialize_mac_values(n, &mut buf);
    }
}
