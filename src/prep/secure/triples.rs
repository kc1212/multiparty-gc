use itertools::{Itertools, izip};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use scuttlebutt::{AesRng, ring::FiniteRing};
use swanky_field_binary::{F2, F128b};

use super::{Cheat, HashDomain, SecurePreprocessor, hash, lsb, mul_bit, seed_to_block};
use crate::net::{Bits, PartyId, Wire};
use crate::prep::{ReceiverParty, StaticPreprocessor, Triple};
use crate::{error::GcError, sharing::AuthShare, universal_hash};

impl SecurePreprocessor {
    /// Π_LaAND (WRK17 Figure 8) with Π_HaAND (Figure 16) as a subroutine.
    ///
    /// `shares` contains authenticated shares `(x, y, r)` for every triple,
    /// the output are triples `(x, y, z)` with `z = x * y`.
    pub(super) fn leaky_and(
        &mut self,
        shares: Vec<AuthShare<F2, F128b>>,
    ) -> Result<Vec<Triple>, GcError> {
        let me = self.party_id;
        let n = self.party_count as usize;
        let delta = self.delta;
        let victim = self.victim();
        let peers = self.session.peers().collect_vec();
        let tccr = self.tccr();
        let count = shares.len() / 3;
        let (xs, ys, rs): (Vec<_>, Vec<_>, Vec<_>) = shares.into_iter().tuples().multiunzip();
        let x_bit = |t: usize| bool::from(xs[t].share);

        // Π_HaAND: compute shares v of sum_i sum_{j != i} x^j y^i
        let flip_y = self.cheating(Cheat::HalfAndFlipY);
        let mut vs = vec![false; count];
        let mut msgs = vec![Bits(vec![]); n];
        for &j in &peers {
            let mut h0 = Vec::with_capacity(count);
            let mut h1 = Vec::with_capacity(count);
            for (t, (x, y)) in xs.iter().zip(&ys).enumerate() {
                let s = self.rng.r#gen::<bool>();
                vs[t] ^= s;
                let key = x.mac_keys[j as usize];
                let y = bool::from(y.share) ^ (flip_y && j == victim);
                h0.push(lsb(hash(&tccr, key, HashDomain::HalfAnd, t, me, j, false)) ^ s);
                h1.push(
                    lsb(hash(
                        &tccr,
                        key + delta,
                        HashDomain::HalfAnd,
                        t,
                        me,
                        j,
                        true,
                    )) ^ s
                        ^ y,
                );
            }
            msgs[j as usize] = Bits(h0.into_iter().chain(h1).collect());
        }
        let received = self
            .session
            .exchange_msg(|j| std::mem::take(&mut msgs[j as usize]), &(2 * count))?;
        for &i in &peers {
            let h = &received[i as usize].0;
            for (t, v) in vs.iter_mut().enumerate() {
                let x = x_bit(t);
                let mac = xs[t].mac_values[i as usize];
                *v ^= h[t + count * x as usize]
                    ^ lsb(hash(&tccr, mac, HashDomain::HalfAnd, t, i, me, x));
            }
        }

        // z^i = x^i y^i + v^i and e^i = z^i + r^i
        let es = izip!(&xs, &ys, &rs, &vs)
            .map(|(x, y, r, v)| bool::from(x.share * y.share + r.share) ^ v)
            .collect_vec();
        let mut my_e = Bits(es);
        if self.cheating(Cheat::LeakyAndFlipE) {
            my_e.0[0] ^= true;
        }

        // Phi_i is the share of y * (sum_i Delta_i), U does not depend on e so it is
        // sent in the same round as e
        let phis = ys
            .iter()
            .map(|y| mul_bit(bool::from(y.share), delta) + y.sum_mac_keys() + y.sum_mac_values())
            .collect_vec();
        let wrong_u = self.cheating(Cheat::LeakyAndWrongU);
        let mut key_phis = vec![vec![]; n];
        let mut u_msgs = vec![vec![]; n];
        for &j in &peers {
            let (k_phis, us): (Vec<_>, Vec<_>) = xs
                .iter()
                .zip(&phis)
                .enumerate()
                .map(|(t, (x, phi))| {
                    let key = x.mac_keys[j as usize];
                    let k_phi = hash(&tccr, key, HashDomain::LeakyAnd, t, me, j, false);
                    let mut u = hash(&tccr, key + delta, HashDomain::LeakyAnd, t, me, j, true)
                        + k_phi
                        + *phi;
                    if wrong_u && j == victim {
                        u += F128b::ONE;
                    }
                    (k_phi, u)
                })
                .unzip();
            key_phis[j as usize] = k_phis;
            u_msgs[j as usize] = us;
        }

        // broadcast e^i and send U_{i,j} to every P_j
        let u_for = |j: PartyId| std::mem::take(&mut u_msgs[j as usize]);
        let (all_e, received) = if self.cheating(Cheat::EquivocateBroadcast) {
            let mut other_e = my_e.clone();
            other_e.0[0] ^= true;
            self.session.broadcast_all_with_private_msg_with(
                &my_e,
                |j| {
                    if j == victim {
                        other_e.clone()
                    } else {
                        my_e.clone()
                    }
                },
                u_for,
                &count,
                &(count, ()),
            )?
        } else {
            self.session
                .broadcast_all_with_private_msg(&my_e, u_for, &count, &(count, ()))?
        };

        // set [z^i] = [r^i] + e^i
        let mut zs = rs;
        for (i, e) in all_e.iter().enumerate() {
            for (z, e) in zs.iter_mut().zip(&e.0) {
                if *e {
                    if i == me as usize {
                        z.share += F2::ONE;
                    } else {
                        z.mac_keys[i] += delta;
                    }
                }
            }
        }

        let mut hs = izip!(&xs, &zs, &phis)
            .map(|(x, z, phi)| {
                mul_bit(bool::from(x.share), *phi)
                    + mul_bit(bool::from(z.share), delta)
                    + z.sum_mac_keys()
                    + z.sum_mac_values()
            })
            .collect_vec();
        for &k in &peers {
            for (t, (h, u)) in hs.iter_mut().zip(&received[k as usize]).enumerate() {
                let x = x_bit(t);
                let mac = xs[t].mac_values[k as usize];
                let m_phi = mul_bit(x, *u) + hash(&tccr, mac, HashDomain::LeakyAnd, t, k, me, x);
                *h += key_phis[k as usize][t] + m_phi;
            }
        }

        // sum_i H_i must be zero for every triple, we check a random linear combination
        let chi = self.coin_toss()?;
        let mut h = universal_hash(&chi, &hs);
        if self.cheating(Cheat::LeakyAndWrongH) {
            h += F128b::ONE;
        }
        let (com, nonce) = self.session.commit(&mut self.rng, &h.to_wire_bytes());
        let coms = self.session.broadcast_all_msg(&com, &())?;
        // the commitments were broadcast, so the openings need no echo round
        let openings = self.session.send_to_all_msg(&(h, nonce), &((), ()))?;
        let mut sum = F128b::ZERO;
        for (i, (com, (h, nonce))) in coms.iter().zip(&openings).enumerate() {
            if !self
                .session
                .verify_commitment(com, &h.to_wire_bytes(), nonce)
            {
                self.detected(GcError::CheatDetected(format!(
                    "party {i} opened the AND triple check commitment incorrectly"
                )))?;
            }
            sum += *h;
        }
        if sum != F128b::ZERO {
            self.detected(GcError::CheatDetected(
                "AND triple check failed".to_string(),
            ))?;
        }

        Ok(izip!(xs, ys, zs).collect())
    }

    /// Π_aAND (WRK17 Figure 18): randomly partition the leaky triples into buckets of size
    /// `bucket_size` and combine every bucket into one triple.
    pub(super) fn combine_buckets(
        &mut self,
        leaky: Vec<Triple>,
        bucket_size: usize,
    ) -> Result<Vec<Triple>, GcError> {
        let count = leaky.len() / bucket_size;
        let seed = self.coin_toss()?;
        let mut perm = (0..leaky.len()).collect_vec();
        perm.shuffle(&mut AesRng::from_seed(seed_to_block(&seed)));
        let buckets = perm.chunks_exact(bucket_size).collect_vec();

        // d = y_1 + y_k is opened for every other triple k in the bucket
        let leaky_ref = &leaky;
        let d_shares = buckets
            .iter()
            .flat_map(|bucket| {
                let y1 = &leaky_ref[bucket[0]].1;
                bucket[1..].iter().map(move |k| y1 + &leaky_ref[*k].1)
            })
            .collect_vec();
        let ds = self
            .open_values_to(ReceiverParty::All, &d_shares)?
            .expect("opened to all parties");

        // x = x_1 + x_k, y = y_1 and z = z_1 + z_k + d x_k
        let triples = buckets
            .iter()
            .enumerate()
            .map(|(b, bucket)| {
                let ds = &ds[b * (bucket_size - 1)..(b + 1) * (bucket_size - 1)];
                let (mut x, y, mut z) = leaky[bucket[0]].clone();
                for (k, d) in bucket[1..].iter().zip(ds) {
                    let (xk, _, zk) = &leaky[*k];
                    z = z + zk + &(xk * *d);
                    x = x + xk;
                }
                (x, y, z)
            })
            .collect_vec();
        debug_assert_eq!(triples.len(), count);
        Ok(triples)
    }
}
