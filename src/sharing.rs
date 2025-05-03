use generic_array::GenericArray;
use itertools::{Itertools, izip};
use rand::{CryptoRng, Rng};
use scuttlebutt::{
    field::{FiniteField, IsSubFieldOf},
    serialization::CanonicalSerialize,
};
use smallvec::smallvec;
use std::{
    io::{Read, Write},
    ops::{Add, Mul},
};

use crate::error::GcError;

type GcSmallVec<MacFF> = smallvec::SmallVec<[MacFF; 16]>;

#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The it is index by j (the other party's index).
    /// Value on index i is 0.
    pub mac_values: GcSmallVec<MacFF>,
    /// The MAC keys K_i[x^j], where value K_i[x^j] is under key i.
    /// The it is indexed on j (the other party's index).
    /// Value on index i is 0.
    pub mac_keys: GcSmallVec<MacFF>,
}

impl<ShareFF, MacFF> AuthShare<ShareFF, MacFF>
where
    ShareFF: FiniteField,
    MacFF: FiniteField + CanonicalSerialize,
{
    pub fn make_empty() -> Self {
        Self {
            party_id: 0,
            share: ShareFF::ZERO,
            mac_values: smallvec![],
            mac_keys: smallvec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.mac_keys.is_empty() && self.mac_keys.is_empty()
    }

    pub fn serialize_mac_values<W: Write>(&self, writer: &mut W) {
        // iterating is sorted by key
        for (j, v) in self.mac_values.iter().enumerate() {
            if j == self.party_id as usize {
                continue;
            }
            writer.write_all(&v.to_bytes()).unwrap();
        }
    }

    /// NOTE: this will overwrite the mac values!
    pub fn deserialize_mac_values<R: Read>(&mut self, party_count: u16, reader: &mut R) {
        let mut buf = GenericArray::<u8, MacFF::ByteReprLen>::default();
        self.mac_values = smallvec![MacFF::ZERO; party_count as usize];
        for i in 0..party_count {
            if i != self.party_id {
                reader
                    .read_exact(&mut buf)
                    .unwrap_or_else(|_| panic!("reading failed for i={i}"));
                self.mac_values[i as usize] = MacFF::from_bytes(&buf).unwrap();
            }
        }
    }

    pub fn sum_mac_keys(&self) -> MacFF {
        // Sum trait is not implemented, so we use fold
        self.mac_keys.iter().fold(MacFF::ZERO, |acc, x| acc + *x)
    }

    pub fn sum_mac_values(&self) -> MacFF {
        // Sum trait is not implemented, so we use fold
        self.mac_values.iter().fold(MacFF::ZERO, |acc, x| acc + *x)
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
        debug_assert_eq!(self.party_id, final_index);
        for (key, mac) in self.mac_keys.iter().zip(mac_values) {
            if *mac != (self.share * *delta) + *key {
                return Err(GcError::MacCheckFailure);
            }
        }
        Ok(())
    }

    /// Compute the additive share of <x \Delta_j> from the authenticate share.
    ///
    /// Note: calling this function only makes sense when:
    /// 1. using j that is not the caller's party ID or
    /// 2. using j that is the party's ID (j == i) and using the party's delta_i.
    pub fn to_x_delta_i_share(&self, j: u16, delta_i: &MacFF) -> MacFF
    where
        ShareFF: IsSubFieldOf<MacFF>,
    {
        let i = self.party_id;
        if i == j {
            // <x \Delta_i>_i = x^i \Delta_i + \sum_{j \ne i} K_j[x^i]
            self.share * *delta_i + self.sum_mac_keys()
        } else {
            // <x \Delta_i>_j = M_j[x^i]
            self.mac_values[j as usize]
        }
    }

    pub fn to_x_delta_shares(&self, delta: &MacFF) -> Vec<MacFF>
    where
        ShareFF: IsSubFieldOf<MacFF>,
    {
        let n = self.mac_keys.len() as u16;
        (0..n).map(|i| self.to_x_delta_i_share(i, delta)).collect()
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
                debug_assert_eq!(self.party_id, rhs.party_id);
                let new_share = self.share + rhs.share;
                let new_mac_values = self
                    .mac_values
                    .iter()
                    .zip(&rhs.mac_values)
                    .map(|(left, right)| *left + *right)
                    .collect();
                let new_mac_keys = self
                    .mac_keys
                    .iter()
                    .zip(&rhs.mac_keys)
                    .map(|(left, right)| *left + *right)
                    .collect();
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

macro_rules! impl_const_mul {
    ($for_type:ty) => {
        impl<ShareFF, MacFF> Mul<ShareFF> for $for_type
        where
            ShareFF: FiniteField + IsSubFieldOf<MacFF>,
            MacFF: FiniteField,
        {
            type Output = AuthShare<ShareFF, MacFF>;

            fn mul(self, rhs: ShareFF) -> Self::Output {
                let new_share = self.share * rhs;
                let new_mac_values = self.mac_values.iter().map(|left| rhs * *left).collect();
                let new_mac_keys = self.mac_keys.iter().map(|left| rhs * *left).collect();
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
impl_const_mul!(AuthShare<ShareFF, MacFF>);
impl_const_mul!(&AuthShare<ShareFF, MacFF>);

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
    debug_assert!(n > 0);
    let mut shares = (0..n).map(|_| ShareFF::random(rng)).collect_vec();

    // Sum trait is not implemented, so we use fold
    let sum_shares = shares.iter().fold(ShareFF::ZERO, |acc, x| acc + *x);
    // Correct the first share so that the sum of shares is the secret
    shares[0] = shares[0] + secret - sum_shares;

    // all the mac keys, ordered by party
    let mut mac_keys = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut party_i_keys: GcSmallVec<MacFF> = smallvec![MacFF::ZERO; n as usize];
        for j in 0..n {
            if i != j {
                party_i_keys[j as usize] = MacFF::random(rng);
            }
        }
        mac_keys.push(party_i_keys);
    }

    // all the macs, ordered by party
    let mut mac_values = Vec::with_capacity((n * n) as usize);
    for i in 0..n {
        let mut party_i_macs: GcSmallVec<MacFF> = smallvec![MacFF::ZERO; n as usize];
        for j in 0..n {
            if i != j {
                // MAC_j[x^i] = x^i * Delta_j + K_j[x^i]
                let m_j_i =
                    shares[i as usize] * deltas[j as usize] + mac_keys[j as usize][i as usize];
                party_i_macs[j as usize] = m_j_i;
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

/// Secret share some `secret` for `n` parties.
/// Returns shares and deltas
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
    deltas: &[MacFF],
) -> Result<ShareFF, GcError>
where
    ShareFF: FiniteField,
    MacFF: FiniteField,
    ShareFF: IsSubFieldOf<MacFF>,
{
    // assume there are as many shares as [n]
    debug_assert_eq!(n as usize, shares.len());

    // we need to check, for every shares x^i such that
    // M_j[x^i] = x^i \Delta_j + K_j[x^i], for j in [n] \ i
    // held by i                 held by j
    for i in 0..n {
        for j in 0..n {
            if i != j {
                let m_j_i = shares[i as usize].mac_values[j as usize];
                let delta_j = deltas[j as usize];
                let k_j_i = shares[j as usize].mac_keys[i as usize];
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
        assert_eq!(secret, verify_and_reconstruct(n, shares, &deltas).unwrap());
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
            verify_and_reconstruct(n, shares, &deltas).unwrap_err();
        }
        {
            // modify a delta
            let (shares, mut deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);
            deltas[0] += F128b::ONE;
            verify_and_reconstruct(n, shares, &deltas).unwrap_err();
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
        share_new.mac_values = smallvec![F128b::ZERO; n as usize];

        share_orig.serialize_mac_values(&mut writer);
        assert_eq!(writer.get_ref().len(), (n as usize - 1) * (128 / 8));

        let mut buf = Cursor::new(writer.into_inner());
        share_new.deserialize_mac_values(n, &mut buf);
    }

    #[test]
    fn test_into_x_delta_i_share() {
        let mut rng = AesRng::new();
        let n = 10u16;
        let secret = F2::random(&mut rng);
        let (shares, deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);

        for i in 0..n {
            let actual = (0..n)
                .map(|party_id| {
                    shares[party_id as usize].to_x_delta_i_share(i, &deltas[party_id as usize])
                })
                .fold(F128b::ZERO, |acc, x| acc + x);
            let expected = secret * deltas[i as usize];

            assert_eq!(actual, expected)
        }
    }

    #[test]
    fn test_mul_by_const() {
        let mut rng = AesRng::new();
        let n = 10u16;
        let constant = F2::random(&mut rng);
        let secret = F2::random(&mut rng);
        let (shares, deltas) = secret_share::<_, F128b, _>(secret, n, &mut rng);
        let shares = shares.into_iter().map(|share| share * constant).collect();
        assert_eq!(
            secret * constant,
            verify_and_reconstruct(n, shares, &deltas).unwrap()
        );
    }
}
