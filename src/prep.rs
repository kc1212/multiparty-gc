use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

use itertools::Itertools;
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

/// Static preprocessor is one that has no networking.
///
/// Authenticated shares are only consistent
/// if this function is called in the same order
/// by all parties.
pub trait StaticPreprocessor {
    fn party_count(&self) -> u16;
    fn init_delta(&mut self) -> Result<F128b, GcError>;
    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError>;
    fn auth_mul(
        &mut self,
        x: &AuthShare<F2, F128b>,
        y: &AuthShare<F2, F128b>,
    ) -> Result<AuthShare<F2, F128b>, GcError>;

    fn auth_muls(
        &mut self,
        shares: &[AuthShare<F2, F128b>],
        indices: &[(usize, usize)],
    ) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        // default implementation
        let mut out = Vec::with_capacity(indices.len());
        for (i, j) in indices {
            out.push(self.auth_mul(&shares[*i], &shares[*j])?);
        }
        Ok(out)
    }

    /// Compute z = x*y and then output unauthenticated shares <x * \Delta^i>
    fn and_output_mask(
        &mut self,
        x: &AuthShare<F2, F128b>,
        y: &AuthShare<F2, F128b>,
    ) -> Result<Vec<F128b>, GcError>;

    /// Open values `xs` to a party with ID `party_id`.
    /// Returns None if the caller does not have ID `party_id`, otherwise return the opened values.
    fn open_values_to(
        &mut self,
        party_id: u16,
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
    AuthMul(u16, (AuthShare<F2, F128b>, AuthShare<F2, F128b>)),
    AuthMuls(u16, Vec<(AuthShare<F2, F128b>, AuthShare<F2, F128b>)>),
    OpenValuesTo(u16, Vec<AuthShare<F2, F128b>>),
    Done(u16),
}

impl InsecurePreprocessorReq {
    fn get_party_id(&self) -> u16 {
        *match self {
            InsecurePreprocessorReq::Delta(pid) => pid,
            InsecurePreprocessorReq::Bits(pid, _) => pid,
            InsecurePreprocessorReq::AuthMul(pid, (_, _)) => pid,
            InsecurePreprocessorReq::AuthMuls(pid, _) => pid,
            InsecurePreprocessorReq::OpenValuesTo(pid, _) => pid,
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

    #[allow(clippy::type_complexity)]
    fn take_auth_mul(self) -> Result<(AuthShare<F2, F128b>, AuthShare<F2, F128b>), GcError> {
        match self {
            InsecurePreprocessorReq::AuthMul(_, t) => Ok(t),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    #[allow(clippy::type_complexity)]
    fn take_auth_muls(self) -> Result<Vec<(AuthShare<F2, F128b>, AuthShare<F2, F128b>)>, GcError> {
        match self {
            InsecurePreprocessorReq::AuthMuls(_, t) => Ok(t),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_open_values_to(self) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        match self {
            InsecurePreprocessorReq::OpenValuesTo(_, values) => Ok(values),
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
    AuthMul(AuthShare<F2, F128b>),
    AuthMuls(Vec<AuthShare<F2, F128b>>),
    OpenValuesTo(Vec<F2>),
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

    fn expect_auth_mul(self) -> Result<AuthShare<F2, F128b>, GcError> {
        match self {
            InsecurePreprocessorResp::AuthMul(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }

    fn expect_auth_mults(self) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        match self {
            InsecurePreprocessorResp::AuthMuls(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }

    fn expect_open_values_to(self) -> Result<Vec<F2>, GcError> {
        match self {
            InsecurePreprocessorResp::OpenValuesTo(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }
}

pub struct InsecurePreprocessorRunner {
    tweak_delta_lsb: bool,
    recv_chan: Receiver<InsecurePreprocessorReq>,
    send_chans: Vec<Sender<InsecurePreprocessorResp>>,
}

fn elements_all_equal<T: PartialEq>(elems: &[T]) -> Option<&T> {
    match elems {
        [head, tail @ ..] => tail.iter().all(|x| x == head).then_some(head),
        [] => None,
    }
}

impl InsecurePreprocessorRunner {
    pub fn run_blocking<R>(&self, rng: &mut R) -> Result<(), GcError>
    where
        R: Rng + CryptoRng,
    {
        let party_count = self.send_chans.len();
        let deltas: Vec<_> = {
            let mut tmp: Vec<F128b> = (0..party_count).map(|_| F128b::random(rng)).collect();
            if self.tweak_delta_lsb {
                let mut tmp0_buf = tmp[0].to_bytes();
                tmp0_buf[0] |= 1;
                tmp[0] = F128b::from_bytes(&tmp0_buf).unwrap();
                tmp
            } else {
                tmp
            }
        };

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
                    for (ch, delta) in self.send_chans.iter().zip(&deltas) {
                        ch.send(InsecurePreprocessorResp::Delta(*delta))?;
                    }
                }
                InsecurePreprocessorReq::Bits(..) => {
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_bits())
                        .collect::<Result<Vec<_>, _>>()?;
                    let n = *elements_all_equal(&reqs).ok_or(GcError::NotAllEqual)?;

                    let mut output = vec![vec![]; party_count];
                    for _i in 0..n {
                        let secret = F2::random(rng);
                        let shares = secret_share_with_delta(secret, &deltas, rng);
                        for (party_id, share) in shares.into_iter().enumerate() {
                            output[party_id].push(share);
                        }
                    }

                    for (ch, share) in self.send_chans.iter().zip(output) {
                        ch.send(InsecurePreprocessorResp::Bits(share))?;
                    }
                }
                InsecurePreprocessorReq::AuthMul(..) => {
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_auth_mul())
                        .collect::<Result<Vec<_>, _>>()?;

                    // sum the as and bs
                    let (bits_a, bits_b) = reqs.into_iter().unzip();
                    let a = verify_and_reconstruct(party_count as u16, bits_a, &deltas).unwrap();
                    let b = verify_and_reconstruct(party_count as u16, bits_b, &deltas).unwrap();

                    let prod = a * b;

                    let prod_shares = secret_share_with_delta(prod, &deltas, rng);
                    for (ch, share) in self.send_chans.iter().zip(prod_shares) {
                        ch.send(InsecurePreprocessorResp::AuthMul(share))?;
                    }
                }
                InsecurePreprocessorReq::AuthMuls(..) => {
                    // reqs are indexed by parties
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_auth_muls())
                        .collect::<Result<Vec<_>, _>>()?;
                    // transpose the requests so that they're indexed by the element in the batch
                    let reqs = transpose(reqs);
                    let result = transpose(
                        reqs.into_iter()
                            .map(|req| {
                                let (bits_a, bits_b) = req.into_iter().unzip();
                                let a = verify_and_reconstruct(party_count as u16, bits_a, &deltas)
                                    .unwrap();
                                let b = verify_and_reconstruct(party_count as u16, bits_b, &deltas)
                                    .unwrap();
                                let prod = a * b;
                                secret_share_with_delta(prod, &deltas, rng)
                            })
                            .collect(),
                    );
                    debug_assert_eq!(result.len(), self.send_chans.len());
                    for (ch, share) in self.send_chans.iter().zip(result) {
                        ch.send(InsecurePreprocessorResp::AuthMuls(share))?;
                    }
                }
                InsecurePreprocessorReq::OpenValuesTo(..) => {
                    let receivers = batch.iter().map(|x| x.get_party_id()).collect_vec();
                    let receiver = *elements_all_equal(&receivers).ok_or(GcError::NotAllEqual)?;

                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_open_values_to())
                        .collect::<Result<Vec<_>, _>>()?;

                    let reqs = transpose(reqs);

                    let res = reqs
                        .into_iter()
                        .map(|req| verify_and_reconstruct(party_count as u16, req, &deltas))
                        .collect::<Result<Vec<_>, GcError>>()?;
                    self.send_chans[receiver as usize]
                        .send(InsecurePreprocessorResp::OpenValuesTo(res))?;
                }
                InsecurePreprocessorReq::Done(_) => {
                    let _out = batch
                        .into_iter()
                        .map(|x| x.take_done())
                        .collect::<Result<Vec<_>, _>>()?;
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

    fn auth_mul(
        &mut self,
        x: &AuthShare<F2, F128b>,
        y: &AuthShare<F2, F128b>,
    ) -> Result<AuthShare<F2, F128b>, GcError> {
        self.send_chan.send(InsecurePreprocessorReq::AuthMul(
            self.party_id,
            (x.clone(), y.clone()),
        ))?;
        let res = self.recv_chan.recv()?;
        res.expect_auth_mul()
    }

    fn auth_muls(
        &mut self,
        shares: &[AuthShare<F2, F128b>],
        indices: &[(usize, usize)],
    ) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        let query = indices
            .iter()
            .map(|(a, b)| (shares[*a].clone(), shares[*b].clone()))
            .collect();

        self.send_chan
            .send(InsecurePreprocessorReq::AuthMuls(self.party_id, query))?;

        let res = self.recv_chan.recv()?;
        res.expect_auth_mults()
    }

    fn and_output_mask(
        &mut self,
        _x: &AuthShare<F2, F128b>,
        _y: &AuthShare<F2, F128b>,
    ) -> Result<Vec<F128b>, GcError> {
        unimplemented!()
    }

    fn open_values_to(
        &mut self,
        party_id: u16,
        xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        self.send_chan
            .send(InsecurePreprocessorReq::OpenValuesTo(party_id, xs.to_vec()))?;
        if self.party_id == party_id {
            let res = self.recv_chan.recv()?;
            Ok(Some(res.expect_open_values_to()?))
        } else {
            Ok(None)
        }
    }

    fn done(&mut self) {
        let _ = self
            .send_chan
            .send(InsecurePreprocessorReq::Done(self.party_id));
    }
}

impl InsecurePreprocessor {
    pub fn new(party_count: u16, tweak_delta_lsb: bool) -> (Vec<Self>, InsecurePreprocessorRunner) {
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

        let runner = InsecurePreprocessorRunner {
            tweak_delta_lsb,
            recv_chan: req_recv_chan,
            send_chans: resp_send_chans,
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
    fn party_count(&self) -> u16 {
        self.party_count
    }

    fn init_delta(&mut self) -> Result<F128b, GcError> {
        Ok(self.delta)
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        Ok(self.dummy_auth_bits[..m as usize].to_vec())
    }

    fn auth_mul(
        &mut self,
        _x: &AuthShare<F2, F128b>,
        _y: &AuthShare<F2, F128b>,
    ) -> Result<AuthShare<F2, F128b>, GcError> {
        Ok(self.dummy_auth_bits[0].clone())
    }

    fn auth_muls(
        &mut self,
        _shares: &[AuthShare<F2, F128b>],
        indices: &[(usize, usize)],
    ) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        Ok(self.dummy_auth_bits[..indices.len()].to_vec())
    }

    fn and_output_mask(
        &mut self,
        _x: &AuthShare<F2, F128b>,
        _y: &AuthShare<F2, F128b>,
    ) -> Result<Vec<F128b>, GcError> {
        todo!()
    }

    fn open_values_to(
        &mut self,
        _party_id: u16,
        _xs: &[AuthShare<F2, F128b>],
    ) -> Result<Option<Vec<F2>>, GcError> {
        todo!()
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