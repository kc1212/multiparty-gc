use std::io::Read;

use bristol_fashion::Circuit;
use evaluator::Evaluator;
use garbler::Garbler;
use generic_array::GenericArray;
use itertools::Itertools;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AesRng, ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};

pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod prep;
pub mod sharing;

pub trait InputMsg1 {}

pub trait InputMsg2 {
    fn into_masked_inputs(self) -> Vec<F2>;
}

pub trait InputMsg3 {
    type Decoder;

    fn into_labels_and_decoder(self) -> (Vec<F128b>, Self::Decoder);
}

pub trait ExtractOutputMsg1 {
    type OM1: OutputMsg1;

    fn extract_outupt_msg1<R: Rng + CryptoRng>(&self, rng: &mut R) -> Vec<Self::OM1>;
}

pub trait OutputMsg1 {
    fn chi(&self) -> [u8; 32];
}

pub trait OutputMsg2 {}

pub struct DummyOutput;

impl OutputMsg1 for DummyOutput {
    fn chi(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

impl OutputMsg2 for DummyOutput {}

pub(crate) fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    debug_assert!(!v.is_empty());
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

// TODO consider using carryless multiplication
pub fn universal_hash(chi: &[u8; 32], elements: &[F128b]) -> F128b {
    let n = elements.len();

    // expand chi into n elements
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"UNIVERSAL_HASH");
    hasher.update(chi);
    let mut hreader = hasher.finalize_xof();

    let xs = (0..n).map(|_| {
        // TODO avoid creating this temporary buffer
        let mut buf = GenericArray::<u8, <F128b as CanonicalSerialize>::ByteReprLen>::default();
        hreader.read_exact(&mut buf).unwrap();
        F128b::from_bytes(&buf).unwrap()
    });

    elements
        .iter()
        .zip(xs)
        .map(|(e, x)| e * x)
        .fold(F128b::ZERO, |acc, x| acc + x)
}

pub struct EvaluationMaterial<E: Evaluator> {
    evaluator: E,
    gcs: Vec<E::Gc>,
    masked_inputs: Vec<F2>,
    input_labels: Vec<Vec<E::Label>>,
    decoder: Vec<E::Decoder>,
}

pub fn simulate_until_eval<
    G: Garbler + Send + 'static,
    E: Evaluator<
            Gc = G::Gc,
            Label = F128b,
            Decoder = <<G as Garbler>::IM3 as InputMsg3>::Decoder,
            OM1 = G::OM1,
            OM2 = G::OM2,
            GarbledOutput = EO,
        >,
    EO: ExtractOutputMsg1<OM1 = G::OM1>,
>(
    garblers: &mut Vec<G>,
    circuit: &Circuit,
    true_inputs: &[F2],
) -> EvaluationMaterial<E>
where
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
            let (gc, _i) = handle.join().unwrap();
            #[cfg(test)]
            println!("Joined garbler {_i}");
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
        .input_round_2(true_inputs, msgs_round1)
        .unwrap();
    let masked_inputs = msgs_round2[0].clone().into_masked_inputs();

    // do the final round of communication
    let (msgs_round3, decoder): (Vec<Vec<F128b>>, Vec<_>) = garblers
        .iter()
        .zip(msgs_round2)
        .map(|(garbler, msg)| garbler.input_round_3(msg).into_labels_and_decoder())
        .unzip();

    let evaluator = E::from_garbling(evaluator_gc);

    EvaluationMaterial {
        evaluator,
        gcs,
        masked_inputs,
        input_labels: msgs_round3,
        decoder,
    }
}

pub fn simulate_eval_and_decode<
    G: Garbler + Send + 'static,
    E: Evaluator<
            Gc = G::Gc,
            Label = F128b,
            Decoder = <<G as Garbler>::IM3 as InputMsg3>::Decoder,
            OM1 = G::OM1,
            OM2 = G::OM2,
            GarbledOutput = EO,
        >,
    EO: ExtractOutputMsg1<OM1 = G::OM1>,
>(
    garblers: Vec<G>,
    circuit: &Circuit,
    true_inputs: Vec<F2>,
    eval_material: EvaluationMaterial<E>,
    check_output: bool,
) where
    <G as Garbler>::Gc: Send,
{
    let EvaluationMaterial::<E> {
        evaluator,
        gcs,
        masked_inputs,
        input_labels: msgs_round3,
        decoder,
    } = eval_material;

    let encoded_output = evaluator
        .eval(circuit, gcs, masked_inputs.clone(), msgs_round3)
        .unwrap();

    let mut rng = AesRng::new();
    let output_msgs_1 = encoded_output.extract_outupt_msg1(&mut rng);
    let chi = if output_msgs_1.is_empty() {
        [0u8; 32]
    } else {
        output_msgs_1[0].chi()
    };

    let output_msgs2 = garblers
        .into_iter()
        .zip(output_msgs_1)
        .map(|(garbler, msg1)| {
            garbler
                .check_output_msg1(msg1, &masked_inputs, circuit)
                .unwrap()
        })
        .collect_vec();

    // now we need to decode the output
    let final_result = evaluator
        .check_and_decode(output_msgs2, &chi, encoded_output, decoder, circuit)
        .unwrap();

    if check_output {
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
}

pub fn full_simulation<
    G: Garbler + Send + 'static,
    E: Evaluator<
            Gc = G::Gc,
            Label = F128b,
            Decoder = <<G as Garbler>::IM3 as InputMsg3>::Decoder,
            OM1 = G::OM1,
            OM2 = G::OM2,
            GarbledOutput = EO,
        >,
    EO: ExtractOutputMsg1<OM1 = G::OM1>,
>(
    mut garblers: Vec<G>,
    circuit: &Circuit,
    true_inputs: Vec<F2>,
    check_output: bool,
) where
    <G as Garbler>::Gc: Send,
{
    let eval_material: EvaluationMaterial<E> =
        simulate_until_eval(&mut garblers, circuit, &true_inputs);

    simulate_eval_and_decode(garblers, circuit, true_inputs, eval_material, check_output);
}

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

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use bristol_fashion::Circuit;
    use itertools::Itertools;
    use scuttlebutt::{AesRng, ring::FiniteRing};
    use swanky_field_binary::F2;

    use crate::{
        eval_clear_circuit,
        evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
        full_simulation,
        garbler::{copz::CopzGarbler, wrk17::Wrk17Garbler},
        prep::InsecurePreprocessor,
    };

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

        full_simulation::<_, Wrk17Evaluator, _>(garblers, circuit, true_inputs, true);

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

        full_simulation::<_, CopzEvaluator, _>(garblers, circuit, true_inputs, true);

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
    fn test_copz_aes() {
        let f = std::fs::File::open("circuits/aes_128.txt").unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();
        let num_parties = 3;

        let input_length: u64 = circuit.input_sizes().iter().sum();
        let true_inputs = vec![F2::ZERO; input_length as usize];
        run_copz_insecure_prep(&circuit, num_parties, true_inputs);
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
            let num_parties = 5;

            run_copz_insecure_prep(&circuit, num_parties, true_inputs);
        }
    }
}
