use swanky_field_binary::{F2, F128b};

pub trait GcPrf {
    fn run(&self, key: F128b, player: usize, gate: usize) -> F128b;
}

pub trait MsgRound1 {}

pub trait MsgRound2 {
    fn into_masked_inputs(self) -> Vec<F2>;
}

pub trait MsgRound3 {
    type Decoder;

    fn into_labels_and_decoder(self) -> (Vec<F128b>, Self::Decoder);
}

pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod prep;
pub mod sharing;

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use bristol_fashion::Circuit;
    use itertools::Itertools;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, ring::FiniteRing};
    use swanky_field_binary::{F2, F128b};

    use crate::{
        MsgRound2, MsgRound3,
        evaluator::{Evaluator, wrk17::Wrk17Evaluator},
        garbler::{Garbler, wrk17::Wrk17Garbler},
        prep::InsecureCircuitPreprocessor,
    };

    fn eval_clear_circuit(circuit: &Circuit, inputs: Vec<u8>) -> Vec<u8> {
        let wire_count = circuit.nwires() as usize;
        let total_inputs: u64 = circuit.input_sizes().iter().sum();
        assert_eq!(inputs.len() as u64, total_inputs);

        let mut buffer = [inputs, vec![0u8; wire_count - total_inputs as usize]].concat();
        for gate in circuit.gates() {
            match gate {
                bristol_fashion::Gate::XOR { a, b, out } => {
                    buffer[*out as usize] = buffer[*a as usize] ^ buffer[*b as usize];
                }
                bristol_fashion::Gate::AND { a, b, out } => {
                    buffer[*out as usize] = buffer[*a as usize] & buffer[*b as usize];
                }
                bristol_fashion::Gate::INV { a, out } => {
                    buffer[*out as usize] = buffer[*a as usize] ^ 1;
                }
                bristol_fashion::Gate::EQ { lit: _, out: _ } => unimplemented!(),
                bristol_fashion::Gate::EQW { a: _, out: _ } => unimplemented!(),
            }
        }

        let output_len: u64 = circuit.output_sizes().iter().sum();
        buffer.split_off(wire_count - output_len as usize)
    }

    fn run_and_check<
        G: Garbler,
        E: Evaluator<Gc = G::Gc, Label = F128b, Decoder = <<G as Garbler>::MR3 as MsgRound3>::Decoder>,
    >(
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
        let msgs_round2 = evaluator
            .input_round_2(true_inputs.clone(), msgs_round1)
            .unwrap();
        let masked_inputs = msgs_round2[0].clone().into_masked_inputs();

        // do the final round of communication
        let (msgs_round3, decoder): (Vec<Vec<F128b>>, Vec<_>) = garblers
            .iter()
            .zip(msgs_round2)
            .map(|(garbler, msg)| garbler.input_round_3(msg).into_labels_and_decoder())
            .unzip();

        let evaluator = E::from_garbling(evaluator_gc);
        let encoded_output = evaluator
            .eval(circuit, gcs, masked_inputs, msgs_round3)
            .unwrap();

        // now we need to decode the output
        let final_result = evaluator.decode(encoded_output, decoder).unwrap();

        let plain_eval_inputs = true_inputs
            .iter()
            .map(|x| if *x == F2::ZERO { 0u8 } else { 1u8 })
            .collect_vec();
        let expected_result = eval_clear_circuit(circuit, plain_eval_inputs)
            .into_iter()
            .collect_vec();

        assert_eq!(final_result, expected_result)
    }

    #[test]
    fn test_clear_circuit() {
        let f = std::fs::File::open("circuits/and.txt").unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();
        assert_eq!(1, circuit.output_sizes().len());
        assert_eq!(1, circuit.output_sizes()[0]);
        assert_eq!(eval_clear_circuit(&circuit, vec![1, 1]), vec![1]);
    }

    #[test]
    fn test_wrk17() {
        let f = std::fs::File::open("circuits/and.txt").unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();
        let true_inputs = vec![F2::ONE, F2::ONE];
        let total_num_parties = 3;

        // prepare preprocessor
        let mut rng = AesRng::new();
        let preps = InsecureCircuitPreprocessor::new(total_num_parties, &circuit, &mut rng);

        let garblers = preps
            .into_iter()
            .enumerate()
            .map(|(party_id, prep)| Wrk17Garbler::new(party_id as u16, total_num_parties, prep))
            .collect_vec();

        run_and_check::<_, Wrk17Evaluator>(garblers, &circuit, true_inputs);
    }
}
