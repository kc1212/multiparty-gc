use swanky_field_binary::{F2, F128b};

pub trait GcPrf {
    fn run(&self, key: F128b, player: usize, gate: usize) -> F128b;
}

pub trait MsgRound1 {}

pub trait MsgRound2 {
    fn into_masked_inputs(self) -> Vec<F2>;
}

pub trait MsgRound3 {
    fn into_labels(self) -> Vec<F128b>;
}

pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod prep;
pub mod sharing;

#[cfg(test)]
mod test {
    use bristol_fashion::Circuit;
    use fancy_garbling::circuit::BinaryCircuit;
    use itertools::Itertools;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, ring::FiniteRing};
    use swanky_field_binary::{F2, F128b};

    use crate::{MsgRound2, MsgRound3, evaluator::Evaluator, garbler::Garbler};

    fn circuit_to_binary_circuit(circuit: &Circuit) -> BinaryCircuit {
        todo!()
    }

    fn generic_framework<G: Garbler, E: Evaluator<Gc = G::Gc, Label = F128b>>(
        mut garblers: Vec<G>,
        circuit: &Circuit,
        true_inputs: Vec<F2>,
    ) {
        let mut rng = AesRng::from_entropy();
        let mut gcs = vec![];
        for garbler in &mut garblers {
            gcs.push(garbler.garble(&mut rng, circuit));
        }

        let evaluator = garblers.pop().unwrap();
        let evaluator_gc = gcs.pop().unwrap();

        // do the first round of communication
        // the garblers (n-1 of them) send a message to the evaluator
        let msgs_round1 = garblers
            .iter()
            .map(|garbler| garbler.input_round_1())
            .collect_vec();

        // do the second round of communication
        // the evaluator processes the messages and then creates the response
        let msgs_round2 = evaluator.input_round_2(true_inputs, msgs_round1).unwrap();
        let masked_inputs = msgs_round2[0].clone().into_masked_inputs();

        // do the final round of communication
        let msgs_round3 = garblers
            .iter()
            .zip(msgs_round2)
            .map(|(garbler, msg)| garbler.input_round_3(msg).into_labels())
            .collect();

        let evaluator = E::from_garbling(evaluator_gc);
        let encoded_output = evaluator
            .eval(circuit, gcs, masked_inputs, msgs_round3)
            .unwrap();

        // now we need to decode the output
        let decoder = todo!();
        let final_result = evaluator.decode(encoded_output, decoder).unwrap();

        use fancy_garbling::circuit::eval_plain;
        let plain_eval_inputs = true_inputs
            .iter()
            .map(|x| if *x == F2::ZERO { 0u16 } else { 1u16 })
            .collect_vec();
        let expected_result = eval_plain(
            &circuit_to_binary_circuit(&circuit),
            &[],
            &plain_eval_inputs,
        )
        .unwrap()
        .into_iter()
        .map(|x| x as u8)
        .collect_vec();

        assert_eq!(final_result, expected_result)
    }
}
