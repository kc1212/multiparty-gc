use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

use rand::CryptoRng;
use rand::Rng;
use scuttlebutt::ring::FiniteRing;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::error::GcError;
use crate::sharing::AuthShare;
use crate::sharing::secret_share_with_delta;

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

    /// Compute z = x*y and then output unauthenticated shares <x * \Delta^i>
    fn and_output_mask(
        &mut self,
        x: &AuthShare<F2, F128b>,
        y: &AuthShare<F2, F128b>,
    ) -> Result<Vec<F128b>, GcError>;

    fn open_value(&mut self, x: &AuthShare<F2, F128b>);
    fn open_values(&mut self, x: &[AuthShare<F2, F128b>]);

    fn done(&mut self);
}

pub trait Preprocessor: StaticPreprocessor {
    /// Perform setup, depending on the preprocessing implementation,
    /// this step might do nothing.
    fn prep(&mut self);
}

enum InsecurePreprocessorReq {
    Delta,
    Bits(u64),
    Triple((AuthShare<F2, F128b>, AuthShare<F2, F128b>)),
    // Triples(Vec<(AuthShare<F2, F128b>, AuthShare<F2, F128b>)>),
    Done,
}

impl InsecurePreprocessorReq {
    fn take_delta(self) -> Result<(), GcError> {
        match self {
            InsecurePreprocessorReq::Delta => Ok(()),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_bits(self) -> Result<u64, GcError> {
        match self {
            InsecurePreprocessorReq::Bits(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    fn take_triple(self) -> Result<(AuthShare<F2, F128b>, AuthShare<F2, F128b>), GcError> {
        match self {
            InsecurePreprocessorReq::Triple(t) => Ok(t),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }

    // fn take_triples(self) -> Result<Vec<(AuthShare<F2, F128b>, AuthShare<F2, F128b>)>, GcError> {
    //     match self {
    //         InsecurePreprocessorReq::Triples(t) => Ok(t),
    //         _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
    //     }
    // }

    fn take_done(self) -> Result<(), GcError> {
        match self {
            InsecurePreprocessorReq::Done => Ok(()),
            _ => Err(GcError::UnexpectedMessageType("in request".to_string())),
        }
    }
}

enum InsecurePreprocessorResp {
    Delta(F128b),
    Bits(Vec<AuthShare<F2, F128b>>),
    Triple(AuthShare<F2, F128b>),
    // Triples(Vec<AuthShare<F2, F128b>>),
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

    fn expect_triple(self) -> Result<AuthShare<F2, F128b>, GcError> {
        match self {
            InsecurePreprocessorResp::Triple(x) => Ok(x),
            _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
        }
    }

    // fn expect_triples(self) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
    //     match self {
    //         InsecurePreprocessorResp::Triples(x) => Ok(x),
    //         _ => Err(GcError::UnexpectedMessageType("in resopnse".to_string())),
    //     }
    // }
}

pub struct InsecurePreprocessorRunner {
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
        let deltas: Vec<_> = (0..party_count).map(|_| F128b::random(rng)).collect();

        #[cfg(test)]
        println!("Starting InsecurePreprocessorRunner for {party_count} parties");

        loop {
            // always wait for n requests
            let mut batch = Vec::with_capacity(party_count);
            for _ in 0..party_count {
                let msg = self.recv_chan.recv()?;
                batch.push(msg);
            }

            // we need to make sure all messages in the batch are the same
            match &batch[0] {
                InsecurePreprocessorReq::Delta => {
                    let _out = batch
                        .into_iter()
                        .map(|x| x.take_delta())
                        .collect::<Result<Vec<_>, _>>()?;

                    // output the deltas (they do not change when called multiple times)
                    for (ch, delta) in self.send_chans.iter().zip(&deltas) {
                        ch.send(InsecurePreprocessorResp::Delta(*delta))?;
                    }
                }
                InsecurePreprocessorReq::Bits(_) => {
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_bits())
                        .collect::<Result<Vec<_>, _>>()?;
                    let n = *elements_all_equal(&reqs).ok_or(GcError::NotAllEqual)?;

                    let mut output = vec![vec![]; party_count];
                    for _ in 0..n {
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
                InsecurePreprocessorReq::Triple(_) => {
                    let reqs = batch
                        .into_iter()
                        .map(|x| x.take_triple())
                        .collect::<Result<Vec<_>, _>>()?;

                    // sum the as and bs
                    let (a, b) = reqs
                        .into_iter()
                        .map(|(a, b)| (a.share, b.share))
                        .fold((F2::ZERO, F2::ZERO), |acc, (a, b)| (acc.0 + a, acc.0 + b));

                    let prod = a * b;

                    let prod_shares = secret_share_with_delta(prod, &deltas, rng);
                    for (ch, share) in self.send_chans.iter().zip(prod_shares) {
                        ch.send(InsecurePreprocessorResp::Triple(share))?;
                    }
                }
                // InsecurePreprocessorReq::Triples(_) => {
                //     unimplemented!()
                // }
                InsecurePreprocessorReq::Done => {
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
        self.send_chan.send(InsecurePreprocessorReq::Delta)?;
        let res = self.recv_chan.recv()?;
        res.expect_delta()
    }

    fn auth_bits(&mut self, m: u64) -> Result<Vec<AuthShare<F2, F128b>>, GcError> {
        self.send_chan.send(InsecurePreprocessorReq::Bits(m))?;
        let res = self.recv_chan.recv()?;
        res.expect_bits()
    }

    fn auth_mul(
        &mut self,
        x: &AuthShare<F2, F128b>,
        y: &AuthShare<F2, F128b>,
    ) -> Result<AuthShare<F2, F128b>, GcError> {
        self.send_chan
            .send(InsecurePreprocessorReq::Triple((x.clone(), y.clone())))?;
        let res = self.recv_chan.recv()?;
        res.expect_triple()
    }

    fn and_output_mask(
        &mut self,
        _x: &AuthShare<F2, F128b>,
        _y: &AuthShare<F2, F128b>,
    ) -> Result<Vec<F128b>, GcError> {
        unimplemented!()
    }

    fn open_value(&mut self, _x: &AuthShare<F2, F128b>) {
        unimplemented!()
    }

    fn open_values(&mut self, _x: &[AuthShare<F2, F128b>]) {
        unimplemented!()
    }

    fn done(&mut self) {
        let _ = self.send_chan.send(InsecurePreprocessorReq::Done);
    }
}

impl InsecurePreprocessor {
    pub fn new(party_count: u16) -> (Vec<Self>, InsecurePreprocessorRunner) {
        let (req_send_chan, req_recv_chan) = mpsc::channel();
        let (resp_send_chans, preps) = (0..party_count)
            .map(|_| {
                let (resp_send_chan, resp_recv_chan) = mpsc::channel();
                (
                    resp_send_chan,
                    Self {
                        party_count,
                        send_chan: req_send_chan.clone(),
                        recv_chan: resp_recv_chan,
                    },
                )
            })
            .unzip();

        let runner = InsecurePreprocessorRunner {
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
