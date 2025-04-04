use swanky_field_binary::{F2, F128b};

pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod prep;
pub mod sharing;

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

pub(crate) fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use bristol_fashion::Circuit;
    use itertools::Itertools;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, ring::FiniteRing, serialization::CanonicalSerialize};
    use swanky_field_binary::{F2, F128b};

    use crate::{
        MsgRound2, MsgRound3,
        evaluator::{Evaluator, copz::CopzEvaluator, wrk17::Wrk17Evaluator},
        garbler::{Garbler, copz::CopzGarbler, wrk17::Wrk17Garbler},
        prep::InsecurePreprocessor,
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
        G: Garbler + Send + 'static,
        E: Evaluator<Gc = G::Gc, Label = F128b, Decoder = <<G as Garbler>::MR3 as MsgRound3>::Decoder>,
    >(
        mut garblers: Vec<G>,
        circuit: &Circuit,
        true_inputs: Vec<F2>,
    ) where
        <G as Garbler>::Gc: Send,
    {
        // We use scoped threads so that we can borrow non-static data and
        // garble in parallel.
        let mut gcs = std::thread::scope(|s| {
            let mut handles = vec![];
            for (i, garbler) in garblers.iter_mut().enumerate() {
                handles.push(s.spawn(move || {
                    let mut rng = AesRng::from_entropy();
                    (garbler.garble(&mut rng, circuit), i)
                }));
            }

            let mut gcs = vec![];
            for handle in handles {
                let (gc, i) = handle.join().unwrap();
                println!("Joined garbler {i}");
                gcs.push(gc);
            }
            gcs
        });

        let final_garbler = garblers.pop().unwrap();
        let evaluator_gc = gcs.pop().unwrap();

        // do the first round of communication
        // the garblers (n-1 of them) send a message to the evaluator
        let msgs_round1 = garblers
            .iter()
            .map(|garbler| garbler.input_round_1())
            .collect_vec();

        // do the second round of communication
        // the evaluator processes the messages and then creates the response
        let msgs_round2 = final_garbler
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
            .map(|x| F2::from_bytes(&[x].into()).unwrap())
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

    fn run_wrk17_insecure_prep(circuit: &Circuit, num_parties: u16, true_inputs: Vec<F2>) {
        // prepare preprocessor
        let (preps, runner) = InsecurePreprocessor::new(num_parties, false);
        let prep_handler = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            runner.run_blocking(&mut rng).unwrap()
        });

        let garblers = preps
            .into_iter()
            .enumerate()
            .map(|(party_id, prep)| Wrk17Garbler::new(party_id as u16, num_parties, prep))
            .collect_vec();

        run_and_check::<_, Wrk17Evaluator>(garblers, circuit, true_inputs);

        // shutdown
        prep_handler.join().unwrap();
    }

    fn run_copz_insecure_prep(circuit: &Circuit, num_parties: u16, true_inputs: Vec<F2>) {
        // prepare preprocessor
        let (preps, runner) = InsecurePreprocessor::new(num_parties, true);
        let prep_handler = std::thread::spawn(move || {
            let mut rng = AesRng::new();
            runner.run_blocking(&mut rng).unwrap()
        });

        let garblers = preps
            .into_iter()
            .enumerate()
            .map(|(party_id, prep)| CopzGarbler::new(party_id as u16, num_parties, prep))
            .collect_vec();

        run_and_check::<_, CopzEvaluator>(garblers, circuit, true_inputs);

        // shutdown
        prep_handler.join().unwrap();
    }

    #[test]
    fn test_wrk17_aes() {
        let f = std::fs::File::open("circuits/aes_128.txt").unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();
        let num_parties = 3;

        let input_length: u64 = circuit.input_sizes().iter().sum();
        let true_inputs = vec![F2::ZERO; input_length as usize];
        run_wrk17_insecure_prep(&circuit, num_parties, true_inputs);
    }

    #[test]
    fn test_wrk17_basic() {
        let circuits_inputs = vec![
            ("circuits/and.txt", vec![F2::ZERO, F2::ZERO]),
            ("circuits/and.txt", vec![F2::ONE, F2::ONE]),
            ("circuits/and.txt", vec![F2::ONE, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ZERO, F2::ZERO, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ONE, F2::ONE, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ONE, F2::ONE, F2::ONE]),
            ("circuits/inv.txt", vec![F2::ONE, F2::ONE]),
        ];

        for (circuit_file, true_inputs) in circuits_inputs {
            let f = std::fs::File::open(circuit_file).unwrap();
            let buf_reader = BufReader::new(f);
            let circuit = bristol_fashion::read(buf_reader).unwrap();
            let num_parties = 5;

            run_wrk17_insecure_prep(&circuit, num_parties, true_inputs);
        }
    }

    #[test]
    fn test_copz_basic() {
        let circuits_inputs = vec![
            ("circuits/and.txt", vec![F2::ZERO, F2::ZERO]),
            ("circuits/and.txt", vec![F2::ONE, F2::ONE]),
            ("circuits/and.txt", vec![F2::ZERO, F2::ONE]),
            ("circuits/and.txt", vec![F2::ONE, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ZERO, F2::ZERO, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ONE, F2::ONE, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ONE, F2::ONE, F2::ONE]),
            ("circuits/inv.txt", vec![F2::ONE, F2::ONE]),
        ];

        for (circuit_file, true_inputs) in circuits_inputs {
            let f = std::fs::File::open(circuit_file).unwrap();
            let buf_reader = BufReader::new(f);
            let circuit = bristol_fashion::read(buf_reader).unwrap();
            let num_parties = 2;

            run_copz_insecure_prep(&circuit, num_parties, true_inputs);
        }
    }
}
