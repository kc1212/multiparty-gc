//! Run one party of the garbling protocol over the network.
//!
//! Party `n-1` is the evaluator, all other parties are garblers. Every party garbles
//! (the preprocessor communicates on its own session), then the garblers send their
//! garbled circuits and input messages to the evaluator over the `online` session:
//!
//! 1. every garbler sends its garbled circuit and input message 1 to the evaluator,
//! 2. the evaluator broadcasts the masked inputs (input message 2),
//! 3. every garbler sends its input labels and output decoder (input message 3),
//! 4. the evaluator evaluates, and if the protocol has an output check, it broadcasts
//!    the public part of output message 1, sends the private part to every garbler
//!    and receives output message 2 from every garbler,
//! 5. the evaluator checks and decodes the output.

use std::time::{Duration, Instant};

use bristol_fashion::Circuit;
use rand::{CryptoRng, Rng};
use swanky_field_binary::{F2, F128b};

use crate::{
    ExtractOutputMsg1, InputMsg2, InputMsg3, MsgShape, OutputMsg1,
    error::GcError,
    evaluator::Evaluator,
    garbler::Garbler,
    net::{Session, Wire},
};

/// The result of [run_party].
#[derive(Debug)]
pub struct PartyReport {
    /// The circuit output, only the evaluator obtains it.
    pub outputs: Option<Vec<F2>>,
    /// From the start of garbling until the evaluator received the garbled circuits
    /// and input labels (for garblers: until they sent input message 3).
    pub garbling_duration: Duration,
    /// Evaluation, output check and decoding.
    pub evaluation_duration: Duration,
}

/// Run the party of `garbler` with the messages sent over `online`.
///
/// Only the evaluator (party `n-1`) has `inputs`, they are all the inputs of the circuit.
/// Any error aborts the network so that the other parties stop as well.
pub fn run_party<G, E, R>(
    garbler: G,
    online: &mut Session,
    circuit: &Circuit,
    inputs: Option<&[F2]>,
    rng: &mut R,
) -> Result<PartyReport, GcError>
where
    G: Garbler,
    E: Evaluator<
            Gc = G::Gc,
            Label = F128b,
            Decoder = <G::IM3 as InputMsg3>::Decoder,
            OM1 = G::OM1,
            OM2 = G::OM2,
        >,
    E::GarbledOutput: ExtractOutputMsg1<OM1 = G::OM1>,
    R: Rng + CryptoRng,
{
    let result = run_party_inner::<G, E, R>(garbler, online, circuit, inputs, rng);
    if let Err(err) = &result {
        online.abort(&format!("party failed: {err}"));
    }
    result
}

fn run_party_inner<G, E, R>(
    mut garbler: G,
    online: &mut Session,
    circuit: &Circuit,
    inputs: Option<&[F2]>,
    rng: &mut R,
) -> Result<PartyReport, GcError>
where
    G: Garbler,
    E: Evaluator<
            Gc = G::Gc,
            Label = F128b,
            Decoder = <G::IM3 as InputMsg3>::Decoder,
            OM1 = G::OM1,
            OM2 = G::OM2,
        >,
    E::GarbledOutput: ExtractOutputMsg1<OM1 = G::OM1>,
    R: Rng + CryptoRng,
{
    let me = online.party_id();
    let n = online.party_count();
    if garbler.party_id() != me || garbler.num_parties() != n {
        return Err(GcError::UnexpectedMessageType(
            "the garbler does not match the session".into(),
        ));
    }
    let evaluator = n - 1;
    let shape = |sender| MsgShape::new(circuit, n, sender);
    let garblers = 0..evaluator;

    let start = Instant::now();
    let gc = garbler.garble(rng, circuit)?;

    if me != evaluator {
        if inputs.is_some() {
            return Err(GcError::UnexpectedMessageType(
                "only the evaluator has inputs".into(),
            ));
        }
        online.send_msg(evaluator, &gc)?;
        online.send_msg(evaluator, &garbler.input_round_1())?;
        let msg2: G::IM2 = online.broadcast_from_msg(evaluator, None, &shape(evaluator))?;
        let masked_inputs = msg2.clone().into_masked_inputs();
        online.send_msg(evaluator, &garbler.input_round_3(msg2))?;
        let garbling_duration = start.elapsed();

        let eval_start = Instant::now();
        if G::OUTPUT_CHECK {
            let public = online.broadcast_from_msg(evaluator, None, &shape(evaluator))?;
            let private = online.recv_msg(evaluator, &shape(evaluator))?;
            let msg1 = G::OM1::join(public, private);
            let msg2 = garbler.check_output_msg1(msg1, &masked_inputs, circuit)?;
            online.send_msg(evaluator, &msg2)?;
        }
        return Ok(PartyReport {
            outputs: None,
            garbling_duration,
            evaluation_duration: eval_start.elapsed(),
        });
    }

    let inputs = inputs
        .ok_or_else(|| GcError::UnexpectedMessageType("the evaluator needs the inputs".into()))?;
    let gcs = garblers
        .clone()
        .map(|i| online.recv_msg::<G::Gc>(i, &shape(i)))
        .collect::<Result<Vec<_>, _>>()?;
    let msgs1 = garblers
        .clone()
        .map(|i| online.recv_msg::<G::IM1>(i, &shape(i)))
        .collect::<Result<Vec<_>, _>>()?;

    // The masked inputs are the same for every garbler, we broadcast them so that
    // all garblers are guaranteed to agree on them.
    let msgs2 = garbler.input_round_2(inputs, msgs1)?;
    let msg2 = msgs2
        .into_iter()
        .next()
        .ok_or_else(|| GcError::UnexpectedMessageType("no masked inputs".into()))?;
    let msg2: G::IM2 = online.broadcast_from_msg(evaluator, Some(&msg2), &shape(evaluator))?;
    let masked_inputs = msg2.into_masked_inputs();

    let (labels, decoders): (Vec<_>, Vec<_>) = garblers
        .clone()
        .map(|i| {
            online
                .recv_msg::<G::IM3>(i, &shape(i))
                .map(|msg| msg.into_labels_and_decoder())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    let garbling_duration = start.elapsed();

    let eval_start = Instant::now();
    let evaluator_state = E::from_garbling(gc);
    let encoded = evaluator_state.eval(circuit, gcs, masked_inputs, labels)?;
    let msgs1 = encoded.extract_outupt_msg1(rng);
    let (chi, msgs2) = if G::OUTPUT_CHECK {
        if msgs1.len() != garblers.len() {
            return Err(GcError::UnexpectedMessageType(
                "expected one output message per garbler".into(),
            ));
        }
        let chi = msgs1[0].chi();
        let (publics, privates): (Vec<_>, Vec<_>) =
            msgs1.into_iter().map(|msg| msg.split()).unzip();
        // the public parts are identical, we broadcast one of them
        debug_assert!(
            publics
                .iter()
                .all(|p| p.to_wire_bytes() == publics[0].to_wire_bytes())
        );
        let public = publics.into_iter().next().unwrap();
        online.broadcast_from_msg(evaluator, Some(&public), &shape(evaluator))?;
        for (i, private) in garblers.clone().zip(privates) {
            online.send_msg(i, &private)?;
        }
        let msgs2 = garblers
            .clone()
            .map(|i| online.recv_msg::<G::OM2>(i, &shape(i)))
            .collect::<Result<Vec<_>, _>>()?;
        (chi, msgs2)
    } else {
        if !msgs1.is_empty() {
            return Err(GcError::UnexpectedMessageType(
                "unexpected output check messages".into(),
            ));
        }
        ([0u8; 32], vec![])
    };
    let outputs = evaluator_state.check_and_decode(msgs2, &chi, encoded, decoders, circuit)?;

    Ok(PartyReport {
        outputs: Some(outputs),
        garbling_duration,
        evaluation_duration: eval_start.elapsed(),
    })
}
