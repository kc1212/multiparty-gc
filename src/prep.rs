use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::time::Duration;

use itertools::Itertools;
use itertools::izip;
use rand::CryptoRng;
use rand::Rng;
use scuttlebutt::ring::FiniteRing;
use scuttlebutt::serialization::CanonicalSerialize;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::error::GcError;
use crate::sharing::AuthShare;
use crate::sharing::secret_share_with_delta;
use crate::sharing::verify_and_reconstruct;
use crate::transpose;

pub type Triple = (
    AuthShare<F2, F128b>,
    AuthShare<F2, F128b>,
    AuthShare<F2, F128b>,
);

#[derive(Clone, Copy, PartialEq)]
pub enum ReceiverParty {
    All,
    Party(u16),
}

/// Static preprocessor is one that has no networking.
///
/// Authenticated shares are only consistent
/// if this function is called in the same order
/// by all parties.
pub trait StaticPreprocessor {
    fn party_count(&self) -> u16;
    fn my_party_id(&self) -> u16;
    fn init_delta(&mut self) -> Result<F128b, GcError>;
    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError>;

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError>;

    /// Perform a beaver multiplication using beaver triples from [auth_triples].
    fn beaver_mul(
        &mut self,
        shares: &[AuthShare<F2, F128b>],
        indices: &[(usize, usize)],
    ) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        // [x], [y] is the input
        // take two random bits [a], [b]
        let beaver_triples = self.beaver_triples(indices.len() as u64)?;
        // d = Open([x + a]), e = Open([y + b])
        let (shares_d, shares_e): (Vec<_>, Vec<_>) = izip!(indices, &beaver_triples)
            .map(|((i, j), (a, b, _c))| {
                let unopened_d = &shares[*i] + a;
                let unopened_e = &shares[*j] + b;
                (unopened_d, unopened_e)
            })
            .unzip();

        let ds = self.open_values_to(ReceiverParty::All, &shares_d)?.unwrap();
        let es = self.open_values_to(ReceiverParty::All, &shares_e)?.unwrap();

        // z = d * [y] + [a] * e + [c]
        Ok(izip!(indices, ds, es, beaver_triples)
            .map(|((_idx_x, idx_y), d, e, beaver_triple)| {
                let share_y = &shares[*idx_y];
                let (share_a, _, share_c) = beaver_triple;
                share_y * d + &(share_a * e) + &share_c
            })
            .collect_vec())
    }

    /// Open values `xs` to a party with ID `party_id`.
    /// Returns None if the caller does not have ID `party_id`, otherwise return the opened values.
    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError>;

    fn done(&mut self);
}

pub trait Preprocessor: StaticPreprocessor {
    /// Perform setup, depending on the preprocessing implementation,
    /// this step might do nothing.
    fn prep(&mut self);
}

#[allow(clippy::large_enum_variant)]
enum InsecurePreprocessorReq {
    Delta(u16),
    Bits(u16, u64),
    BeaverTriples(u16, u64),
    OpenValuesTo(u16, ReceiverParty, Vec<AuthShare<F2, F128b>>),
    Done(u16),
}

impl InsecurePreprocessorReq {
    fn get_party_id(&self) -> u16 {
        *match self {
            InsecurePreprocessorReq::Delta(pid) => pid,
            InsecurePreprocessorReq::Bits(pid, _) => pid,
            InsecurePreprocessorReq::BeaverTriples(pid, _) => pid,
            InsecurePreprocessorReq::OpenValuesTo(pid, _, _) => pid,
            InsecurePreprocessorReq::Done(pid) => pid,
        }
    }

    fn take_delta(self) -> Result<(), GcError> {
        match self {
            InsecurePreprocessorReq::Delta(_) => Ok(()),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_bits(self) -> Result<u64, GcError> {
        match self {
            InsecurePreprocessorReq::Bits(_, x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_beaver_triples(self) -> Result<u64, GcError> {
        match self {
            InsecurePreprocessorReq::BeaverTriples(_, x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_open_values_to(self) -> Result<(ReceiverParty, Vec<AuthShare<F2, F128b>>), GcError> {
        match self {
            InsecurePreprocessorReq::OpenValuesTo(_, receiver, values) => Ok((receiver, values)),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_done(self) -> Result<(), GcError> {
        match self {
            InsecurePreprocessorReq::Done(_) => Ok(()),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum InsecurePreprocessorResp {
    Delta(F128b),
    Bits(Vec<AuthShare<F2, F128b>>),
    BeaverTriples(Vec<Triple>),
    OpenValuesTo(Option<Vec<F2>>),
}

impl InsecurePreprocessorResp {
    fn expect_delta(self) -> Result<F128b, GcError> {
        match self {
            InsecurePreprocessorResp::Delta(delta) => Ok(delta),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }

    fn expect_bits(self) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        match self {
            InsecurePreprocessorResp::Bits(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }

    fn expect_beaver_triples(self) -> Result<Vec<Triple>, GcError> {
        match self {
            InsecurePreprocessorResp::BeaverTriples(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }

    fn expect_open_values_to(self) -> Result<Option<Vec<F2>>, GcError> {
        match self {
            InsecurePreprocessorResp::OpenValuesTo(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }
}

pub struct InsecurePreprocessorRunner {
    recv_chan: Receiver<InsecurePreprocessorReq>,
    send_chans: Vec<Sender<InsecurePreprocessorResp>>,
    open_delay: Option<Duration>,

    deltas: Vec<F128b>,
    auth_bits: Vec<Vec<AuthShare<F2, F128b>>>,
    beaver_triples: Vec<Vec<Triple>>,
}

fn elements_all_equal<T: PartialEq>(elems: &[T]) -> Option<&T> {
    match elems {
        [head, tail @ ..] => tail.iter().all(|x| x == head).then_some(head),
        [] => None,
    }
}

impl InsecurePreprocessorRunner {
    pub fn run_blocking(mut self) -> Result<(), GcError> {
        let party_count = self.send_chans.len();

        #[cfg(test)]
        println!("Starting InsecurePreprocessorRunner for {party_count} parties");

        loop {
            // always wait for n requests
            let mut batch = Vec::with_capacity(party_count);
            for _ in 0..party_count {
                let msg = self.recv_chan.recv()?;
                batch.push(msg);
            }

            // NOTE: sorting is not strictly necessary if we do not reconstruct with verification
            // when processing auth_mul
            batch.sort_by_key(|a| a.get_party_id());

            // we need to make sure all messages in the batch are the same
            match &batch[0] {
                InsecurePreprocessorReq::Delta(_) => {
                    let _out = batch
                        .into_iter()
                        .map(|x| x.take_delta())
                        .collect::<Result<Vec<_>, _>>()?;

                    // output the deltas (they do not change when called multiple times)
                    for (ch, delta) in self.send_chans.iter().zip(&self.deltas) {
                        ch.send(InsecurePreprocessorResp::Delta(*delta))?;
                    }
                }
                InsecurePreprocessorReq::Bits(..) => {
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_bits())
                        .collect::<Result<Vec<_>, _>>()?;
                    let n = *elements_all_equal(&reqs).ok_or(GcError::NotAllEqual)?;

                    let output = transpose(self.auth_bits.drain(0..n as usize).collect_vec());
                    for (ch, share) in self.send_chans.iter().zip(output) {
                        ch.send(InsecurePreprocessorResp::Bits(share))?;
                    }
                }
                InsecurePreprocessorReq::BeaverTriples(..) => {
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_beaver_triples())
                        .collect::<Result<Vec<_>, _>>()?;
                    let n = *elements_all_equal(&reqs).ok_or(GcError::NotAllEqual)?;

                    let triples = transpose(self.beaver_triples.drain(0..n as usize).collect_vec());
                    for (ch, share) in self.send_chans.iter().zip(triples) {
                        ch.send(InsecurePreprocessorResp::BeaverTriples(share))?;
                    }
                }
                InsecurePreprocessorReq::OpenValuesTo(..) => {
                    let (receivers, reqs): (Vec<ReceiverParty>, _) = batch
                        .into_iter()
                        .map(|x| x.take_open_values_to())
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .unzip();
                    let receiver = *elements_all_equal(&receivers).ok_or(GcError::NotAllEqual)?;

                    let reqs = transpose(reqs);

                    let res = reqs
                        .into_iter()
                        .map(|req| verify_and_reconstruct(party_count as u16, req, &self.deltas))
                        .collect::<Result<Vec<_>, GcError>>()?;

                    if let Some(dur) = self.open_delay {
                        std::thread::sleep(dur);
                    }
                    match receiver {
                        ReceiverParty::All => {
                            for ch in self.send_chans.iter() {
                                ch.send(InsecurePreprocessorResp::OpenValuesTo(Some(res.clone())))?;
                            }
                        }
                        ReceiverParty::Party(receiver_id) => {
                            self.send_chans[receiver_id as usize]
                                .send(InsecurePreprocessorResp::OpenValuesTo(Some(res)))?;
                            for (i, ch) in self.send_chans.iter().enumerate() {
                                if receiver_id as usize != i {
                                    ch.send(InsecurePreprocessorResp::OpenValuesTo(None))?;
                                }
                            }
                        }
                    }
                }
                InsecurePreprocessorReq::Done(_) => {
                    let _out = batch
                        .into_iter()
                        .map(|x| x.take_done())
                        .collect::<Result<Vec<_>, _>>()?;
                    debug_assert_eq!(self.auth_bits.len(), 0);
                    debug_assert_eq!(self.beaver_triples.len(), 0);
                    return Ok(());
                }
            }
        }
    }
}

/// This struct needs to be initialized correctly so that
/// all instances of [Self] are connected to [InsecurePreprocessorRunner].
pub struct InsecurePreprocessor {
    party_id: u16,
    party_count: u16,
    /// Channel for sending commands to the central [InsecurePreprocessorRunner].
    send_chan: Sender<InsecurePreprocessorReq>,
    /// Channel for receiving results from the central [InsecurePreprocessorRunner].
    recv_chan: Receiver<InsecurePreprocessorResp>,
}

impl StaticPreprocessor for InsecurePreprocessor {
    fn my_party_id(&self) -> u16 {
        self.party_id
    }

    fn party_count(&self) -> u16 {
        self.party_count
    }

    fn init_delta(&mut self) -> Result<F128b, GcError> {
        self.send_chan
            .send(InsecurePreprocessorReq::Delta(self.party_id))?;
        let res = self.recv_chan.recv()?;
        res.expect_delta()
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        self.send_chan
            .send(InsecurePreprocessorReq::Bits(self.party_id, m))?;
        let res = self.recv_chan.recv()?;
        res.expect_bits()
    }

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError> {
        self.send_chan
            .send(InsecurePreprocessorReq::BeaverTriples(self.party_id, m))?;
        let res = self.recv_chan.recv()?;
        res.expect_beaver_triples()
    }

    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        self.send_chan.send(InsecurePreprocessorReq::OpenValuesTo(
            self.party_id,
            receiver_party,
            xs.to_vec(),
        ))?;
        let res = self.recv_chan.recv()?.expect_open_values_to()?;
        match receiver_party {
            ReceiverParty::All => {
                if res.is_none() {
                    Err(GcError::WrongOpening(
                        "empty result when opening to all".to_string(),
                    ))
                } else {
                    Ok(res)
                }
            }
            ReceiverParty::Party(receiver_id) => match (self.party_id == receiver_id, res) {
                (true, Some(inner)) => Ok(Some(inner)),
                (true, None) => Err(GcError::WrongOpening(
                    "empty result when opening to a party".to_string(),
                )),
                (false, Some(_)) => Err(GcError::WrongOpening(
                    "unexpected message in opening".to_string(),
                )),
                (false, None) => Ok(None),
            },
        }
    }

    fn done(&mut self) {
        let _ = self
            .send_chan
            .send(InsecurePreprocessorReq::Done(self.party_id));
    }
}

impl InsecurePreprocessor {
    pub fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        party_count: u16,
        tweak_delta_lsb: bool,
        bits: usize,
        triples: usize,
        open_delay: Option<Duration>,
    ) -> (Vec<Self>, InsecurePreprocessorRunner) {
        let (req_send_chan, req_recv_chan) = mpsc::channel();
        let (resp_send_chans, preps) = (0..party_count)
            .map(|party_id| {
                let (resp_send_chan, resp_recv_chan) = mpsc::channel();
                (
                    resp_send_chan,
                    Self {
                        party_id,
                        party_count,
                        send_chan: req_send_chan.clone(),
                        recv_chan: resp_recv_chan,
                    },
                )
            })
            .unzip();

        let deltas: Vec<_> = {
            let mut tmp: Vec<F128b> = (0..party_count).map(|_| F128b::random(rng)).collect();
            if tweak_delta_lsb {
                let mut tmp0_buf = tmp[0].to_bytes();
                tmp0_buf[0] |= 1;
                tmp[0] = F128b::from_bytes(&tmp0_buf).unwrap();
                tmp
            } else {
                tmp
            }
        };

        let auth_bits = (0..bits)
            .map(|_| {
                let secret = F2::random(rng);
                secret_share_with_delta(secret, &deltas, rng)
            })
            .collect_vec();

        let beaver_triples = (0..triples)
            .map(|_| {
                let a = F2::random(rng);
                let b = F2::random(rng);
                let c = a * b;
                let auth_a = secret_share_with_delta(a, &deltas, rng);
                let auth_b = secret_share_with_delta(b, &deltas, rng);
                let auth_c = secret_share_with_delta(c, &deltas, rng);
                izip!(auth_a, auth_b, auth_c)
                    .map(|(a, b, c)| (a, b, c))
                    .collect_vec()
            })
            .collect_vec();

        let runner = InsecurePreprocessorRunner {
            deltas,
            recv_chan: req_recv_chan,
            send_chans: resp_send_chans,
            auth_bits,
            beaver_triples,
            open_delay,
        };

        (preps, runner)
    }
}

impl Preprocessor for InsecurePreprocessor {
    fn prep(&mut self) {
        unimplemented!("unsupported")
    }
}

// The this preprocessor produces wrong values,
// it should only be used for benchmarking the garbler.
#[derive(Clone)]
pub struct InsecureBenchPreprocessor {
    party_count: u16,
    delta: F128b,
    dummy_auth_bits: Vec<AuthShare<F2, F128b>>,
}

impl InsecureBenchPreprocessor {
    pub fn new<R: Rng + CryptoRng>(party_count: u16, max_auth_bits: usize, rng: &mut R) -> Self {
        let deltas: Vec<_> = (0..party_count).map(|_| F128b::random(rng)).collect();
        let dummy_auth_bits = (0..max_auth_bits)
            .map(|_| secret_share_with_delta(F2::ZERO, &deltas, rng)[0].clone())
            .collect();
        Self {
            party_count,
            delta: deltas[0],
            dummy_auth_bits,
        }
    }
}

impl StaticPreprocessor for InsecureBenchPreprocessor {
    fn my_party_id(&self) -> u16 {
        // the party ID here doesn't matter
        // since only one party is garbling
        1
    }

    fn beaver_triples(&mut self, m: u64) -> Result<Vec<Triple>, GcError> {
        let m_auth_bits = self.dummy_auth_bits[0..m as usize].to_vec();
        Ok(izip!(m_auth_bits.clone(), m_auth_bits.clone(), m_auth_bits)
            .map(|(a, b, c)| (a, b, c))
            .collect())
    }

    fn party_count(&self) -> u16 {
        self.party_count
    }

    fn init_delta(&mut self) -> Result<F128b, GcError> {
        Ok(self.delta)
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        Ok(self.dummy_auth_bits[..m as usize].to_vec())
    }

    fn open_values_to(
        &mut self,
        receiver_party: ReceiverParty,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        match receiver_party {
            ReceiverParty::All => Ok(Some(vec![F2::ZERO; xs.len()])),
            ReceiverParty::Party(party_id) => {
                if party_id == self.my_party_id() {
                    Ok(Some(vec![F2::ZERO; xs.len()]))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn done(&mut self) {
        // do nothing
    }
}

impl Preprocessor for InsecureBenchPreprocessor {
    fn prep(&mut self) {
        todo!()
    }
}
