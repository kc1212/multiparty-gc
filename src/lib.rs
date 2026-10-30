use std::{
    io::{BufReader, Read},
    path::Path,
    time::Duration,
};

use bristol_fashion::Circuit;
use driver::run_party;
use error::GcError;
use evaluator::Evaluator;
use garbler::Garbler;
use generic_array::GenericArray;
use itertools::Itertools;
use rand::{CryptoRng, Rng, SeedableRng};
use scuttlebutt::{AesRng, ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};

use crate::net::{
    Network, NetworkConfig, Session, Wire,
    memory::{LinkModel, mesh},
};

pub mod driver;
pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod net;
pub mod prep;
pub mod sharing;

/// Public parameters that determine the size of every protocol message,
/// `sender` is the party that sends the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgShape {
    pub party_count: u16,
    pub sender: u16,
    /// Number of circuit input wires.
    pub inputs: usize,
    /// Number of circuit output wires.
    pub outputs: usize,
    pub and_gates: usize,
}

impl MsgShape {
    pub fn new(circuit: &Circuit, party_count: u16, sender: u16) -> Self {
        Self {
            party_count,
            sender,
            inputs: circuit.input_sizes().iter().sum::<u64>() as usize,
            outputs: circuit.output_sizes().iter().sum::<u64>() as usize,
            and_gates: circuit.nand() as usize,
        }
    }
}

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

/// The message of the output check that the evaluator sends to every garbler.
///
/// It consists of a part that must be the same for all garblers, which the evaluator
/// broadcasts, and a part that is sent to one garbler only.
pub trait OutputMsg1: Sized {
    type Public: Wire<Shape = MsgShape>;
    type Private: Wire<Shape = MsgShape>;

    fn chi(&self) -> [u8; 32];

    fn split(self) -> (Self::Public, Self::Private);

    fn join(public: Self::Public, private: Self::Private) -> Self;
}

pub trait OutputMsg2 {}

pub struct DummyOutput;

impl OutputMsg1 for DummyOutput {
    type Public = DummyOutput;
    type Private = DummyOutput;

    fn chi(&self) -> [u8; 32] {
        [0u8; 32]
    }

    fn split(self) -> (DummyOutput, DummyOutput) {
        (DummyOutput, DummyOutput)
    }

    fn join(_: DummyOutput, _: DummyOutput) -> Self {
        DummyOutput
    }
}

impl OutputMsg2 for DummyOutput {}

impl Wire for DummyOutput {
    type Shape = MsgShape;

    fn encoded_len(_: &MsgShape) -> usize {
        0
    }

    fn encode(&self, _: &mut Vec<u8>) {}

    fn decode(_: &mut net::wire::Reader<'_>, _: &MsgShape) -> Result<Self, net::wire::WireError> {
        Ok(DummyOutput)
    }
}

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

pub struct NamedCircuit {
    circuit: Circuit,
    name: String,
}

impl NamedCircuit {
    pub fn from_path<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let name = path
            .as_ref()
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let f = std::fs::File::open(path).unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();

        Self { circuit, name }
    }

    pub fn input_sizes(&self) -> &Vec<u64> {
        self.circuit.input_sizes()
    }

    pub fn nand(&self) -> u64 {
        self.circuit.nand()
    }

    pub fn circuit(&self) -> &Circuit {
        &self.circuit
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Evaluate the circuit in the clear.
    pub fn eval_clear(&self, inputs: &[F2]) -> Vec<F2> {
        let inputs = inputs
            .iter()
            .map(|x| if *x == F2::ZERO { 0u8 } else { 1u8 })
            .collect_vec();
        eval_clear_circuit(&self.circuit, inputs)
            .into_iter()
            .map(|x| F2::from(x == 1))
            .collect_vec()
    }
}

/// The network and sessions of one party.
pub struct PartySetup {
    pub network: Network,
    /// Session for the preprocessor, it is also used for the openings during garbling.
    pub prep: Session,
    /// Session for the online phase, see [driver::run_party].
    pub online: Session,
}

/// Connect `party_count` parties in this process with the in-memory transport.
pub fn in_memory_setup(party_count: u16, model: LinkModel) -> Result<Vec<PartySetup>, GcError> {
    mesh(party_count, model, NetworkConfig::default())?
        .into_iter()
        .map(|network| {
            Ok(PartySetup {
                prep: network.session("prep")?,
                online: network.session("online")?,
                network,
            })
        })
        .collect()
}

/// A party of [full_simulation].
pub struct SimParty<G> {
    pub garbler: G,
    pub online: Session,
    /// Used to report the communication.
    pub network: Network,
}

/// Run all parties in this process (one thread per party) with [driver::run_party].
///
/// The evaluator (the last party) has all the inputs. If `check_output` is set,
/// the output is compared with the plaintext evaluation of the circuit.
/// The `prep_duration` of the report is zero.
pub fn full_simulation<G, E>(
    parties: Vec<SimParty<G>>,
    circuit: &NamedCircuit,
    true_inputs: Vec<F2>,
    check_output: bool,
    benchmark_tag: Option<String>,
    latency: Option<Duration>,
) -> Result<BenchmarkReport, GcError>
where
    G: Garbler + Send,
    E: Evaluator<
            Gc = G::Gc,
            Label = F128b,
            Decoder = <G::IM3 as InputMsg3>::Decoder,
            OM1 = G::OM1,
            OM2 = G::OM2,
        >,
    E::GarbledOutput: ExtractOutputMsg1<OM1 = G::OM1>,
{
    let party_count = parties.len();
    let input_count = true_inputs.len();
    let evaluator = party_count - 1;
    let results = std::thread::scope(|s| {
        let handles = parties
            .into_iter()
            .enumerate()
            .map(|(i, party)| {
                let inputs = (i == evaluator).then_some(true_inputs.as_slice());
                s.spawn(move || {
                    let SimParty {
                        garbler,
                        mut online,
                        network,
                    } = party;
                    let mut rng = AesRng::from_entropy();
                    let report = run_party::<G, E, _>(
                        garbler,
                        &mut online,
                        &circuit.circuit,
                        inputs,
                        &mut rng,
                    );
                    (report, network.stats())
                })
            })
            .collect_vec();
        handles
            .into_iter()
            .map(|h| h.join().expect("party panicked"))
            .collect_vec()
    });

    let mut prep_bytes = 0;
    let mut online_bytes = 0;
    let mut reports = vec![];
    for (report, stats) in results {
        for (label, stats) in stats {
            if label == "online" {
                online_bytes += stats.bytes_sent;
            } else {
                prep_bytes += stats.bytes_sent;
            }
        }
        reports.push(report?);
    }
    let report = reports.pop().expect("at least two parties");

    if check_output {
        assert_eq!(report.outputs, Some(circuit.eval_clear(&true_inputs)));
    }

    Ok(BenchmarkReport {
        prep_duration: Duration::ZERO,
        garbling_duration: report.garbling_duration,
        evaluation_duration: report.evaluation_duration,
        party_count,
        input_count,
        circuit_name: circuit.name.clone(),
        benchmark_tag,
        latency,
        prep_bytes,
        online_bytes,
    })
}

pub struct BenchmarkReport {
    /// Duration of the function-independent preprocessing, it is not part of [Self::total_duration].
    pub prep_duration: Duration,
    pub garbling_duration: Duration,
    pub evaluation_duration: Duration,
    pub party_count: usize,
    pub input_count: usize,
    pub circuit_name: String,
    pub benchmark_tag: Option<String>,
    pub latency: Option<Duration>,
    /// Bytes sent by all parties on the preprocessing session (the function-independent
    /// preprocessing and the openings during garbling).
    pub prep_bytes: u64,
    /// Bytes sent by all parties in the online phase.
    pub online_bytes: u64,
}

impl BenchmarkReport {
    pub fn total_duration(&self) -> Duration {
        self.garbling_duration + self.evaluation_duration
    }

    pub fn csv_header() -> String {
        "garbling_duration,evaluation_duration,total_duration,latency,party_count,input_count,circuit,tag,prep_duration,prep_bytes,online_bytes"
            .to_string()
    }

    pub fn csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{}",
            self.garbling_duration.as_millis(),
            self.evaluation_duration.as_millis(),
            self.total_duration().as_millis(),
            self.latency.unwrap_or_default().as_millis(),
            self.party_count,
            self.input_count,
            self.circuit_name,
            match &self.benchmark_tag {
                Some(tag) => tag,
                None => "-",
            },
            self.prep_duration.as_millis(),
            self.prep_bytes,
            self.online_bytes,
        )
    }
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
    use std::{io::BufReader, sync::Arc, time::Duration};

    use itertools::Itertools;
    use rand::Rng;
    use scuttlebutt::{AesRng, ring::FiniteRing};
    use swanky_field_binary::F2;

    use crate::{
        BenchmarkReport, ExtractOutputMsg1, InputMsg3, MsgShape, NamedCircuit, SimParty,
        error::GcError,
        eval_clear_circuit,
        evaluator::{Evaluator, copz::CopzEvaluator, wrk17::Wrk17Evaluator},
        full_simulation,
        garbler::{
            Garbler,
            copz::{CopzGarbler, CopzGarbling, CopzInputMsg2},
            wrk17::{Wrk17Garbler, Wrk17InputMsg2},
        },
        in_memory_setup,
        net::{
            Network, NetworkConfig, PartyId, Session, StreamId, Wire,
            memory::{LinkModel, Tamper, mesh_with_tamper},
        },
        prep::{
            InsecurePreprocessor, Preprocessor, SecurePrepParams, SecurePreprocessor, run_prep,
        },
    };
    use swanky_field_binary::F128b;

    #[test]
    fn test_clear_circuit() {
        let f = std::fs::File::open("circuits/and.txt").unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();
        assert_eq!(1, circuit.output_sizes().len());
        assert_eq!(1, circuit.output_sizes()[0]);
        assert_eq!(eval_clear_circuit(&circuit, vec![1, 1]), vec![1]);
    }

    /// (preprocessor session, online session, network) of every party
    type Setup = Vec<(Session, Session, Network)>;

    fn make_setup(n: u16, model: LinkModel, tamper: Option<Tamper>) -> Setup {
        match tamper {
            None => in_memory_setup(n, model)
                .unwrap()
                .into_iter()
                .map(|s| (s.prep, s.online, s.network))
                .collect(),
            Some(tamper) => mesh_with_tamper(n, model, NetworkConfig::default(), tamper)
                .unwrap()
                .into_iter()
                .map(|net| {
                    (
                        net.session("prep").unwrap(),
                        net.session("online").unwrap(),
                        net,
                    )
                })
                .collect(),
        }
    }

    /// The stream of the online session, it is the same for all parties.
    fn online_stream() -> StreamId {
        make_setup(2, LinkModel::default(), None)[0].1.stream_id()
    }

    fn counts(circuit: &NamedCircuit) -> (usize, usize) {
        let inputs: u64 = circuit.input_sizes().iter().sum();
        ((circuit.nand() + inputs) as usize, circuit.nand() as usize)
    }

    /// Run the preprocessing and then the protocol with `new` creating the garblers.
    fn simulate<P, G, E>(
        setup: Setup,
        circuit: &NamedCircuit,
        true_inputs: Vec<F2>,
        make_prep: impl Fn(Session) -> P,
        new: impl Fn(u16, u16, P) -> G,
    ) -> Result<BenchmarkReport, GcError>
    where
        P: Preprocessor + Send,
        G: Garbler + Send,
        E: Evaluator<
                Gc = G::Gc,
                Label = F128b,
                Decoder = <G::IM3 as InputMsg3>::Decoder,
                OM1 = G::OM1,
                OM2 = G::OM2,
            >,
        E::GarbledOutput: ExtractOutputMsg1<OM1 = G::OM1>,
    {
        let n = setup.len() as u16;
        let (preps, rest): (Vec<_>, Vec<_>) = setup
            .into_iter()
            .map(|(prep, online, network)| (make_prep(prep), (online, network)))
            .unzip();
        let preps = run_prep(preps)?;
        let parties = preps
            .into_iter()
            .zip(rest)
            .enumerate()
            .map(|(i, (prep, (online, network)))| SimParty {
                garbler: new(i as u16, n, prep),
                online,
                network,
            })
            .collect_vec();
        full_simulation::<G, E>(parties, circuit, true_inputs, true, None, None)
    }

    #[derive(Clone, Copy)]
    enum Prep {
        Insecure,
        Secure,
    }

    #[derive(Clone, Copy)]
    enum Protocol {
        Wrk17,
        Copz,
    }

    fn run(
        protocol: Protocol,
        prep: Prep,
        setup: Setup,
        circuit: &NamedCircuit,
        true_inputs: Vec<F2>,
    ) -> Result<BenchmarkReport, GcError> {
        let (bits, triples) = counts(circuit);
        let seed: [u8; 32] = AesRng::new().r#gen();
        let insecure = |s| InsecurePreprocessor::new(s, seed, true, bits, triples);
        let secure = |s| {
            SecurePreprocessor::new(
                s,
                &mut AesRng::new(),
                true,
                bits,
                triples,
                SecurePrepParams::default(),
            )
            .unwrap()
        };
        match (protocol, prep) {
            (Protocol::Wrk17, Prep::Insecure) => simulate::<_, _, Wrk17Evaluator>(
                setup,
                circuit,
                true_inputs,
                insecure,
                Wrk17Garbler::new,
            ),
            (Protocol::Wrk17, Prep::Secure) => simulate::<_, _, Wrk17Evaluator>(
                setup,
                circuit,
                true_inputs,
                secure,
                Wrk17Garbler::new,
            ),
            (Protocol::Copz, Prep::Insecure) => simulate::<_, _, CopzEvaluator>(
                setup,
                circuit,
                true_inputs,
                insecure,
                CopzGarbler::new,
            ),
            (Protocol::Copz, Prep::Secure) => simulate::<_, _, CopzEvaluator>(
                setup,
                circuit,
                true_inputs,
                secure,
                CopzGarbler::new,
            ),
        }
    }

    fn basic_circuits_inputs() -> Vec<(&'static str, Vec<F2>)> {
        vec![
            ("circuits/and.txt", vec![F2::ZERO, F2::ZERO]),
            ("circuits/and.txt", vec![F2::ONE, F2::ONE]),
            ("circuits/and.txt", vec![F2::ZERO, F2::ONE]),
            ("circuits/and.txt", vec![F2::ONE, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ZERO, F2::ZERO, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ONE, F2::ONE, F2::ZERO]),
            ("circuits/and2.txt", vec![F2::ONE, F2::ONE, F2::ONE]),
            ("circuits/inv.txt", vec![F2::ONE, F2::ONE]),
        ]
    }

    fn random_inputs(circuit: &NamedCircuit) -> Vec<F2> {
        let mut rng = AesRng::new();
        let input_length: u64 = circuit.input_sizes().iter().sum();
        (0..input_length).map(|_| F2::random(&mut rng)).collect()
    }

    #[test]
    fn test_basic_circuits() {
        for protocol in [Protocol::Wrk17, Protocol::Copz] {
            for prep in [Prep::Insecure, Prep::Secure] {
                for (circuit_file, true_inputs) in basic_circuits_inputs() {
                    let circuit = NamedCircuit::from_path(circuit_file);
                    let parties = make_setup(4, LinkModel::default(), None);
                    run(protocol, prep, parties, &circuit, true_inputs).unwrap();
                }
            }
        }
    }

    #[test]
    fn test_two_parties() {
        let circuit = NamedCircuit::from_path("circuits/and2.txt");
        for protocol in [Protocol::Wrk17, Protocol::Copz] {
            for prep in [Prep::Insecure, Prep::Secure] {
                let parties = make_setup(2, LinkModel::default(), None);
                run(protocol, prep, parties, &circuit, random_inputs(&circuit)).unwrap();
            }
        }
    }

    #[test]
    fn test_wrk17_aes() {
        let circuit = NamedCircuit::from_path("circuits/aes_128.txt");
        for prep in [Prep::Insecure, Prep::Secure] {
            let parties = make_setup(3, LinkModel::default(), None);
            run(
                Protocol::Wrk17,
                prep,
                parties,
                &circuit,
                random_inputs(&circuit),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_copz_aes() {
        let circuit = NamedCircuit::from_path("circuits/aes_128.txt");
        for prep in [Prep::Insecure, Prep::Secure] {
            let parties = make_setup(3, LinkModel::default(), None);
            run(
                Protocol::Copz,
                prep,
                parties,
                &circuit,
                random_inputs(&circuit),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_report_with_latency() {
        let circuit = NamedCircuit::from_path("circuits/and2.txt");
        let latency = Duration::from_millis(20);
        let parties = make_setup(
            3,
            LinkModel {
                latency,
                bandwidth: None,
            },
            None,
        );
        let report = run(
            Protocol::Copz,
            Prep::Insecure,
            parties,
            &circuit,
            random_inputs(&circuit),
        )
        .unwrap();
        // at least the Beaver openings and three online rounds
        assert!(report.total_duration() >= 4 * latency);
        assert!(report.prep_bytes > 0);
        assert!(report.online_bytes > 0);
    }

    /// Flip a bit of the frame number `index` on the online stream from `from` to `to`.
    fn flip(from: PartyId, to: PartyId, index: u64, offsets: Vec<usize>) -> Tamper {
        let online = online_stream();
        Arc::new(move |sender, receiver, stream, i, frame: &mut Vec<u8>| {
            if sender == from && receiver == to && stream == online && i == index {
                for offset in &offsets {
                    frame[*offset] ^= 1;
                }
            }
        })
    }

    #[test]
    fn test_tampered_garbling_is_detected() {
        let circuit = NamedCircuit::from_path("circuits/and.txt");
        let n = 3;
        // the first frame from garbler 0 to the evaluator is its garbled circuit,
        // flip the first byte of every row (WRK17) or table (COPZ)
        let wrk17_row = 1 + 16 * (n as usize - 1) + 16;
        let tamper = flip(0, n - 1, 0, (0..4).map(|r| r * wrk17_row).collect());
        let parties = make_setup(n, LinkModel::default(), Some(tamper));
        let result = run(
            Protocol::Wrk17,
            Prep::Insecure,
            parties,
            &circuit,
            random_inputs(&circuit),
        );
        assert!(
            matches!(result, Err(GcError::MacCheckFailure)),
            "{:?}",
            result.err()
        );

        // The evaluator uses C1 only if the external value of the left input is 1, and
        // then also uses C2, so flipping the same bit in C1 and C2 cancels out. We flip
        // both C2 tables, one of which is always used.
        let copz_table = 16 * (n as usize - 1);
        let tamper = flip(0, n - 1, 0, vec![copz_table, 2 * copz_table]);
        let parties = make_setup(n, LinkModel::default(), Some(tamper));
        let result = run(
            Protocol::Copz,
            Prep::Insecure,
            parties,
            &circuit,
            random_inputs(&circuit),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_input_labels_are_detected() {
        let circuit = NamedCircuit::from_path("circuits/and.txt");
        let n = 3;
        // frames from garbler 0 to the evaluator: garbled circuit, input message 1,
        // the echo of the masked inputs, input message 3 (starting with the labels)
        let tamper = flip(0, n - 1, 3, vec![0]);
        let parties = make_setup(n, LinkModel::default(), Some(tamper));
        let result = run(
            Protocol::Wrk17,
            Prep::Insecure,
            parties,
            &circuit,
            random_inputs(&circuit),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_equivocating_evaluator_is_detected() {
        let circuit = NamedCircuit::from_path("circuits/and2.txt");
        let n = 3;
        for protocol in [Protocol::Wrk17, Protocol::Copz] {
            // the first frame from the evaluator to garbler 1 is the broadcast of the
            // masked inputs, change the first masked input for garbler 1 only
            let tamper = flip(n - 1, 1, 0, vec![0]);
            let parties = make_setup(n, LinkModel::default(), Some(tamper));
            let result = run(
                protocol,
                Prep::Insecure,
                parties,
                &circuit,
                random_inputs(&circuit),
            );
            assert!(
                matches!(result, Err(GcError::CheatDetected(_))),
                "{:?}",
                result.err()
            );
        }

        // frames from the evaluator to garbler 1 in COPZ: masked inputs, echo,
        // public part of output message 1 (starting with the external values)
        let tamper = flip(n - 1, 1, 2, vec![0]);
        let parties = make_setup(n, LinkModel::default(), Some(tamper));
        let result = run(
            Protocol::Copz,
            Prep::Insecure,
            parties,
            &circuit,
            random_inputs(&circuit),
        );
        assert!(
            matches!(result, Err(GcError::CheatDetected(_))),
            "{:?}",
            result.err()
        );
    }

    /// Garble `circuit` with the secure preprocessing and return the garblers' circuits.
    fn garblings<G: Garbler + Send>(
        circuit: &NamedCircuit,
        num_parties: u16,
        new: impl Fn(u16, u16, SecurePreprocessor) -> G,
    ) -> Vec<G::Gc>
    where
        G::Gc: Send,
    {
        let (bits, triples) = counts(circuit);
        let preps = make_setup(num_parties, LinkModel::default(), None)
            .into_iter()
            .map(|(prep, _, _)| {
                SecurePreprocessor::new(
                    prep,
                    &mut AesRng::new(),
                    true,
                    bits,
                    triples,
                    SecurePrepParams::default(),
                )
                .unwrap()
            })
            .collect_vec();
        let mut garblers = run_prep(preps)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(party_id, prep)| new(party_id as u16, num_parties, prep))
            .collect_vec();
        std::thread::scope(|s| {
            let handles = garblers
                .iter_mut()
                .map(|g| {
                    s.spawn(|| {
                        let mut rng = AesRng::new();
                        g.garble(&mut rng, &circuit.circuit).unwrap()
                    })
                })
                .collect_vec();
            let mut gcs = handles.into_iter().map(|h| h.join().unwrap()).collect_vec();
            gcs.pop(); // the evaluator's garbling is never sent
            gcs
        })
    }

    /// Check that `gcs` roundtrip and that wrong lengths or senders are rejected.
    fn check_garbling_encoding<T: Wire<Shape = MsgShape>>(
        gcs: &[T],
        circuit: &NamedCircuit,
        num_parties: u16,
    ) {
        for (sender, gc) in gcs.iter().enumerate() {
            let shape = MsgShape::new(&circuit.circuit, num_parties, sender as u16);
            let bytes = gc.to_wire_bytes();
            let decoded = T::from_wire_bytes(&bytes, &shape).unwrap();
            assert_eq!(decoded.to_wire_bytes(), bytes);
            assert!(T::from_wire_bytes(&bytes[1..], &shape).is_err());
            assert!(T::from_wire_bytes(&[bytes.as_slice(), &[0]].concat(), &shape).is_err());
            let wrong_parties = MsgShape {
                party_count: num_parties + 1,
                ..shape
            };
            assert!(T::from_wire_bytes(&bytes, &wrong_parties).is_err());
        }
    }

    #[test]
    fn test_garbling_encoding() {
        let circuit = NamedCircuit::from_path("circuits/and2.txt");
        let n = 3;
        let gcs = garblings(&circuit, n, Wrk17Garbler::new);
        check_garbling_encoding(&gcs, &circuit, n);

        let gcs = garblings(&circuit, n, CopzGarbler::new);
        check_garbling_encoding(&gcs, &circuit, n);
        // only party 0 sends the bits b_w, so the senders cannot be confused
        let bytes0 = gcs[0].to_wire_bytes();
        let bytes1 = gcs[1].to_wire_bytes();
        let shape = |sender| MsgShape::new(&circuit.circuit, n, sender);
        assert!(CopzGarbling::from_wire_bytes(&bytes0, &shape(1)).is_err());
        assert!(CopzGarbling::from_wire_bytes(&bytes1, &shape(0)).is_err());
    }

    #[test]
    fn test_input_messages_reject_padding() {
        // and2 has three inputs, so one byte with five padding bits
        let circuit = NamedCircuit::from_path("circuits/and2.txt");
        let shape = MsgShape::new(&circuit.circuit, 3, 2);
        assert_eq!(shape.inputs, 3);
        assert!(Wrk17InputMsg2::from_wire_bytes(&[0b111], &shape).is_ok());
        assert!(Wrk17InputMsg2::from_wire_bytes(&[0b1111], &shape).is_err());
        assert!(CopzInputMsg2::from_wire_bytes(&[0b1000], &shape).is_err());
    }
}
