use itertools::Itertools;
use ocelot::ot::{
    FixedKeyInitializer, KosDeltaReceiver, KosDeltaSender, RandomReceiver, RandomSender,
    Receiver as OtReceiver,
};
use rand::{Rng, SeedableRng};
use scuttlebutt::{AesRng, Block, SymChannel, ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};

use super::{
    Cheat, F128B_LEN, SecurePreprocessor, block_to_f128b, bytes_to_f128b, f128b_to_bytes, mul_bit,
    seed_to_block,
};
use crate::prep::network::{COMMITMENT_LEN, NONCE_LEN, commit, verify_commitment};
use crate::{error::GcError, sharing::AuthShare};

impl SecurePreprocessor {
    /// Generate `count` random authenticated shares, i.e., Π_aShare from WRK17.
    pub(super) fn random_auth_shares(
        &mut self,
        count: usize,
    ) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        let rho = self.rho;
        let me = self.party_id as usize;
        let n = self.party_count as usize;

        // The last 3ρ bits are sacrificed: ρ bits are opened to check the consistency
        // of the global keys and 2ρ bits hide the linear combinations opened when checking
        // the consistency of the bits.
        let len = count + 3 * rho;
        let bits = (0..len).map(|_| self.rng.r#gen::<bool>()).collect_vec();
        let (macs, keys) = self.cot_with_all(&bits)?;
        self.check_bit_consistency(&bits, &macs, &keys)?;

        let mut shares = bits
            .iter()
            .enumerate()
            .map(|(m, bit)| AuthShare {
                party_id: self.party_id,
                share: F2::from(*bit),
                mac_values: (0..n)
                    .map(|k| if k == me { F128b::ZERO } else { macs[k][m] })
                    .collect(),
                mac_keys: (0..n)
                    .map(|k| if k == me { F128b::ZERO } else { keys[k][m] })
                    .collect(),
            })
            .collect_vec();
        self.check_delta_consistency(&shares[count..count + rho])?;
        shares.truncate(count);
        Ok(shares)
    }

    /// Run correlated OT with every other party in both directions.
    /// As the sender we use our global key as the correlation, as the receiver we use `bits`
    /// as the choice bits. This gives two-party authenticated bits.
    ///
    /// Returns `(macs, keys)` where `macs[k][m] = M_k[x_m]` and `keys[k][m] = K_i[x^k_m]`.
    #[allow(clippy::type_complexity)]
    fn cot_with_all(
        &mut self,
        bits: &[bool],
    ) -> Result<(Vec<Vec<F128b>>, Vec<Vec<F128b>>), GcError> {
        let me = self.party_id;
        let n = self.party_count as usize;
        let victim = self.victim();
        let flip_bit = self.cheating(Cheat::AbitInconsistentBits);
        let bad_delta = self.cheating(Cheat::InconsistentDelta);
        let delta_bytes: [u8; 16] = self.delta.to_bytes().into();
        let seeds = self
            .net
            .peers()
            .map(|_| Block::from(self.rng.r#gen::<u128>()))
            .collect_vec();

        // Run the OTs with every peer in its own thread so that no party waits on another
        let results = std::thread::scope(|s| {
            let handles = self
                .net
                .links_mut()
                .zip(seeds)
                .map(|((peer, link), seed)| {
                    s.spawn(move || -> Result<_, GcError> {
                        let mut rng = AesRng::from_seed(seed);
                        let mut channel = SymChannel::new(link);
                        let mut bits = bits.to_vec();
                        if flip_bit && peer == victim {
                            bits[0] = !bits[0];
                        }
                        let mut delta = delta_bytes;
                        if bad_delta && peer == victim {
                            delta[1] ^= 1;
                        }

                        // the party with the smaller ID acts as the sender first
                        let (keys, macs) = if me < peer {
                            let mut sender =
                                KosDeltaSender::init_fixed_key(&mut channel, delta, &mut rng)?;
                            let mut receiver = KosDeltaReceiver::init(&mut channel, &mut rng)?;
                            let keys = sender.send_random(&mut channel, bits.len(), &mut rng)?;
                            let macs = receiver.receive_random(&mut channel, &bits, &mut rng)?;
                            (keys, macs)
                        } else {
                            let mut receiver = KosDeltaReceiver::init(&mut channel, &mut rng)?;
                            let mut sender =
                                KosDeltaSender::init_fixed_key(&mut channel, delta, &mut rng)?;
                            let macs = receiver.receive_random(&mut channel, &bits, &mut rng)?;
                            let keys = sender.send_random(&mut channel, bits.len(), &mut rng)?;
                            (keys, macs)
                        };
                        let keys = keys.into_iter().map(|(k, _)| block_to_f128b(k)).collect();
                        let macs = macs.into_iter().map(block_to_f128b).collect();
                        Ok((peer, keys, macs))
                    })
                })
                .collect_vec();
            handles
                .into_iter()
                .map(|h| h.join().expect("OT thread panicked"))
                .collect_vec()
        });

        let mut all_macs = vec![vec![]; n];
        let mut all_keys = vec![vec![]; n];
        for result in results {
            let (peer, keys, macs) = result?;
            all_keys[peer as usize] = keys;
            all_macs[peer as usize] = macs;
        }
        Ok((all_macs, all_keys))
    }

    /// The check of Π_aBit^n (WRK17 Figure 14, `check1` in emp-agmpc).
    ///
    /// For ρ public random linear combinations, every party broadcasts the combination
    /// of its bits and sends the combined MAC to every other party which checks it.
    /// A party that used different bits with different parties is caught with
    /// probability 1/2 per combination.
    fn check_bit_consistency(
        &mut self,
        bits: &[bool],
        macs: &[Vec<F128b>],
        keys: &[Vec<F128b>],
    ) -> Result<(), GcError> {
        let rho = self.rho;
        let n = self.party_count as usize;
        let peers = self.net.peers().map(|p| p as usize).collect_vec();
        let mask = if rho == 128 {
            u128::MAX
        } else {
            (1u128 << rho) - 1
        };

        // bit j of coefs[m] is the coefficient of the m-th bit in the j-th combination
        let seed = self.coin_toss()?;
        let mut coef_rng = AesRng::from_seed(seed_to_block(&seed));
        let mut combined_bits = 0u128;
        let mut combined_macs = vec![vec![F128b::ZERO; rho]; n];
        let mut combined_keys = vec![vec![F128b::ZERO; rho]; n];
        for (m, bit) in bits.iter().enumerate() {
            let coef = coef_rng.r#gen::<u128>() & mask;
            if *bit {
                combined_bits ^= coef;
            }
            let mut c = coef;
            while c != 0 {
                let j = c.trailing_zeros() as usize;
                c &= c - 1;
                for &k in &peers {
                    combined_macs[k][j] += macs[k][m];
                    combined_keys[k][j] += keys[k][m];
                }
            }
        }

        let all_bits = self.net.broadcast(&combined_bits.to_le_bytes(), 16)?;
        let msgs = combined_macs
            .iter()
            .map(|m| f128b_to_bytes(m))
            .collect_vec();
        let received = self.net.exchange(&msgs, rho * F128B_LEN)?;
        for &i in &peers {
            let their_bits = u128::from_le_bytes(all_bits[i].as_slice().try_into().unwrap());
            let their_macs = bytes_to_f128b(&received[i]);
            for (j, mac) in their_macs.into_iter().enumerate() {
                let bit = (their_bits >> j) & 1 == 1;
                if mac != combined_keys[i][j] + mul_bit(bit, self.delta) {
                    self.detected(GcError::CheatDetected(format!(
                        "authenticated bit consistency check failed for party {i}"
                    )))?;
                }
            }
        }
        Ok(())
    }

    /// The check of Π_aShare (WRK17 Figure 15, `check2` in emp-agmpc), it opens `shares`.
    ///
    /// For every share, every party `i` commits to `K = sum_k K_i[x^k]` and `K + Δ_i`
    /// and to its bit with all its MACs. After the bits and MACs are opened, party `i`
    /// opens the commitment matching `b = sum_{k != i} x^k` which must equal
    /// `sum_{k != i} M_i[x^k]`. A party that used different global keys with different
    /// parties is caught with probability 1/2 per share.
    fn check_delta_consistency(&mut self, shares: &[AuthShare<F2, F128b>]) -> Result<(), GcError> {
        let n = self.party_count as usize;
        let me = self.party_id as usize;
        let peers = self.net.peers().map(|p| p as usize).collect_vec();
        // a bit and n MACs (including the empty one for ourselves)
        let mac_msg_len = 1 + n * F128B_LEN;
        let mac_opening_len = mac_msg_len + NONCE_LEN;
        let key_opening_len = F128B_LEN + NONCE_LEN;

        let mut my_coms = vec![];
        let mut my_mac_openings = vec![];
        let mut key_openings = vec![];
        for share in shares {
            let key0 = share.sum_mac_keys();
            let key1 = key0 + self.delta;
            let (com0, nonce0) = commit(&mut self.rng, &key0.to_bytes());
            let (com1, nonce1) = commit(&mut self.rng, &key1.to_bytes());
            let mac_msg = std::iter::once(bool::from(share.share) as u8)
                .chain(f128b_to_bytes(&share.mac_values))
                .collect_vec();
            let (com_mac, nonce_mac) = commit(&mut self.rng, &mac_msg);
            my_coms.extend(com0.into_iter().chain(com1).chain(com_mac));
            my_mac_openings.extend(mac_msg.into_iter().chain(nonce_mac));
            key_openings.push([(key0, nonce0), (key1, nonce1)]);
        }
        let coms = self
            .net
            .broadcast(&my_coms, shares.len() * 3 * COMMITMENT_LEN)?;
        let mac_openings = self
            .net
            .broadcast(&my_mac_openings, shares.len() * mac_opening_len)?;

        // bits[i][r] and macs[i][r][k] = M_k[x^i_r]
        let mut bits = vec![vec![false; shares.len()]; n];
        let mut macs = vec![vec![vec![]; shares.len()]; n];
        for i in 0..n {
            for r in 0..shares.len() {
                let opening = &mac_openings[i][r * mac_opening_len..(r + 1) * mac_opening_len];
                let (msg, nonce) = opening.split_at(mac_msg_len);
                let com = &coms[i][(r * 3 + 2) * COMMITMENT_LEN..(r * 3 + 3) * COMMITMENT_LEN];
                if !verify_commitment(com, msg, nonce) || msg[0] > 1 {
                    self.detected(GcError::CheatDetected(format!(
                        "party {i} opened a MAC commitment incorrectly"
                    )))?;
                }
                bits[i][r] = msg[0] == 1;
                macs[i][r] = bytes_to_f128b(&msg[1..]);
            }
        }
        let parity = |i: usize, r: usize| {
            (0..n)
                .filter(|k| *k != i)
                .fold(false, |acc, k| acc ^ bits[k][r])
        };

        let my_key_openings = key_openings
            .iter()
            .enumerate()
            .flat_map(|(r, openings)| {
                let (key, nonce) = openings[parity(me, r) as usize];
                key.to_bytes().into_iter().chain(nonce)
            })
            .collect_vec();
        let all_key_openings = self
            .net
            .broadcast(&my_key_openings, shares.len() * key_opening_len)?;

        for &i in &peers {
            for r in 0..shares.len() {
                let b = parity(i, r) as usize;
                let opening = &all_key_openings[i][r * key_opening_len..(r + 1) * key_opening_len];
                let (key, nonce) = opening.split_at(F128B_LEN);
                let com = &coms[i][(r * 3 + b) * COMMITMENT_LEN..(r * 3 + b + 1) * COMMITMENT_LEN];
                let expected = (0..n)
                    .filter(|k| *k != i)
                    .fold(F128b::ZERO, |acc, k| acc + macs[k][r][i]);
                if !verify_commitment(com, key, nonce) || bytes_to_f128b(key)[0] != expected {
                    self.detected(GcError::CheatDetected(format!(
                        "global key consistency check failed for party {i}"
                    )))?;
                }
            }
        }
        Ok(())
    }
}
