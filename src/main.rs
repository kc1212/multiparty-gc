mod config;

use config::{gen_config, read_config};

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand, ValueEnum};
use itertools::Itertools;
use multiparty_gc::{
    BenchmarkReport, NamedCircuit, SimParty,
    driver::run_party,
    error::GcError,
    evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
    full_simulation,
    garbler::{copz::CopzGarbler, wrk17::Wrk17Garbler},
    in_memory_setup,
    net::{
        NetError, Network, Session,
        memory::LinkModel,
        quic::{self, Identity, QuicConfig},
    },
    prep::{InsecurePreprocessor, Preprocessor, SecurePrepParams, SecurePreprocessor, run_prep},
};
use rand::Rng;
use scuttlebutt::{AesRng, ring::FiniteRing};
use swanky_field_binary::F2;

#[derive(ValueEnum, Clone, Debug, Default)]
enum Circuit {
    #[default]
    Aes128,
    Aes256,
}

impl Circuit {
    fn file_name(&self) -> &str {
        match self {
            Circuit::Aes128 => "circuits/aes_128.txt",
            Circuit::Aes256 => "circuits/aes_256.txt",
        }
    }
}

#[derive(ValueEnum, Clone, Debug, Default)]
enum Protocol {
    #[default]
    Copz,
    Wrk17,
}

#[derive(ValueEnum, Clone, Debug, Default)]
enum Prep {
    /// Trusted dealer, only for benchmarking the garbling.
    #[default]
    Insecure,
    /// Maliciously secure preprocessing from WRK17.
    Secure,
}

/// Benchmark multiparty garbling and preprocessing.
///
/// By default all parties run in this process over an in-memory network. With
/// `--party-id`, `--config` and `--key`, this process runs a single party that connects
/// to the other parties over QUIC, see the `gen-config` command.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(2..))]
    num_parties: u16,

    #[arg(short, long, required = true)]
    protocol: Option<Protocol>,

    #[arg(short, long, required = true)]
    circuit: Option<Circuit>,

    #[arg(long, value_enum, default_value_t = Prep::Insecure)]
    prep: Prep,

    /// Statistical security parameter of the secure preprocessing.
    #[arg(long, default_value_t = 40)]
    rho: usize,

    /// Bucket size of the secure preprocessing, chosen from the circuit size if not set.
    #[arg(long, default_value = None)]
    bucket_size: Option<usize>,

    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    average_over: u32,

    /// One-way latency of every link.
    #[arg(long, default_value = None)]
    latency_ms: Option<u64>,

    /// Bandwidth of every link (in each direction), unlimited if not set.
    #[arg(long, default_value = None)]
    bandwidth_mbps: Option<u64>,

    #[arg(long)]
    show_header: bool,

    /// Run only this party over QUIC, the last party is the evaluator.
    #[arg(long, requires_all = ["config", "key"])]
    party_id: Option<u16>,

    /// The parties' addresses and certificates, see `gen-config`.
    #[arg(long)]
    config: Option<PathBuf>,

    /// The private key (PEM) of this party.
    #[arg(long)]
    key: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate certificates, keys and a configuration for parties on one host.
    GenConfig {
        #[arg(short, long, value_parser = clap::value_parser!(u16).range(2..))]
        num_parties: u16,

        /// Directory for the files, it is created if needed.
        #[arg(long)]
        dir: PathBuf,

        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Party `i` listens on `base-port + i`.
        #[arg(long, default_value_t = 7000)]
        base_port: u16,
    },
}

impl Args {
    fn protocol(&self) -> &Protocol {
        self.protocol.as_ref().expect("required by clap")
    }

    fn circuit(&self) -> &Circuit {
        self.circuit.as_ref().expect("required by clap")
    }
}

fn run_protocol<P: Preprocessor + Send + 'static>(
    args: &Args,
    circuit: &NamedCircuit,
    preps: Vec<P>,
    others: Vec<(Session, Network)>,
    true_inputs: Vec<F2>,
) -> Result<BenchmarkReport, GcError> {
    let mut benchmark_tag = format!("{:?}", args.protocol()).to_ascii_lowercase();
    if matches!(args.prep, Prep::Secure) {
        benchmark_tag.push_str("+secure_prep");
    }
    let latency = args.latency_ms.map(Duration::from_millis);
    let n = args.num_parties;
    match args.protocol() {
        Protocol::Copz => {
            let parties = preps
                .into_iter()
                .zip(others)
                .enumerate()
                .map(|(i, (prep, (online, network)))| SimParty {
                    garbler: CopzGarbler::new(i as u16, n, prep),
                    online,
                    network,
                })
                .collect_vec();
            full_simulation::<_, CopzEvaluator>(
                parties,
                circuit,
                true_inputs,
                true,
                Some(benchmark_tag),
                latency,
            )
        }
        Protocol::Wrk17 => {
            let parties = preps
                .into_iter()
                .zip(others)
                .enumerate()
                .map(|(i, (prep, (online, network)))| SimParty {
                    garbler: Wrk17Garbler::new(i as u16, n, prep),
                    online,
                    network,
                })
                .collect_vec();
            full_simulation::<_, Wrk17Evaluator>(
                parties,
                circuit,
                true_inputs,
                true,
                Some(benchmark_tag),
                latency,
            )
        }
    }
}

fn bench_once(args: &Args) -> Result<BenchmarkReport, GcError> {
    let circuit = NamedCircuit::from_path(args.circuit().file_name());

    let mut rng = AesRng::new();

    // prepare input
    let input_length: u64 = circuit.input_sizes().iter().sum();
    let true_inputs = (0..input_length).map(|_| F2::random(&mut rng)).collect();

    // prepare the network and the preprocessing
    let triples = circuit.nand() as usize;
    let bits = (circuit.nand() + input_length) as usize;
    let model = LinkModel {
        latency: Duration::from_millis(args.latency_ms.unwrap_or(0)),
        bandwidth: args.bandwidth_mbps.map(|mbps| mbps * 1_000_000 / 8),
    };
    let setups = in_memory_setup(args.num_parties, model)?;
    let mut prep_sessions = vec![];
    let mut others = vec![];
    for setup in setups {
        prep_sessions.push(setup.prep);
        others.push((setup.online, setup.network));
    }

    match args.prep {
        Prep::Insecure => {
            let seed: [u8; 32] = rng.r#gen();
            let preps = prep_sessions
                .into_iter()
                .map(|session| InsecurePreprocessor::new(session, seed, true, bits, triples))
                .collect_vec();
            let start = Instant::now();
            let preps = run_prep(preps)?;
            let prep_duration = start.elapsed();
            let mut report = run_protocol(args, &circuit, preps, others, true_inputs)?;
            report.prep_duration = prep_duration;
            Ok(report)
        }
        Prep::Secure => {
            let params = SecurePrepParams {
                rho: args.rho,
                bucket_size: args.bucket_size,
            };
            let preps = prep_sessions
                .into_iter()
                .map(|session| {
                    SecurePreprocessor::new(session, &mut rng, true, bits, triples, params)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let start = Instant::now();
            let preps = run_prep(preps)?;
            let prep_duration = start.elapsed();
            let mut report = run_protocol(args, &circuit, preps, others, true_inputs)?;
            report.prep_duration = prep_duration;
            Ok(report)
        }
    }
}

/// Run a single party over QUIC, only the evaluator returns a report.
fn run_networked(args: &Args, party_id: u16) -> Result<Option<BenchmarkReport>, GcError> {
    let config = args.config.as_ref().expect("required by clap");
    let key = args.key.as_ref().expect("required by clap");
    let peers = read_config(config)?;
    let n = peers.len() as u16;
    if n != args.num_parties || party_id >= n {
        return Err(GcError::Net(NetError::Config(format!(
            "the configuration has {n} parties but -n is {}",
            args.num_parties
        ))));
    }
    let key = std::fs::read(key).map_err(|e| GcError::Net(NetError::Config(e.to_string())))?;
    let certificate = peers[party_id as usize].1.clone();
    let identity = Identity::from_certificate_and_key_pem(certificate, &key)?;
    let network = quic::connect(party_id, identity, &peers, QuicConfig::default())?;

    let circuit = NamedCircuit::from_path(args.circuit().file_name());
    let mut rng = AesRng::new();
    let input_length: u64 = circuit.input_sizes().iter().sum();
    let triples = circuit.nand() as usize;
    let bits = (circuit.nand() + input_length) as usize;
    let evaluator = n - 1;
    let inputs: Option<Vec<F2>> =
        (party_id == evaluator).then(|| (0..input_length).map(|_| F2::random(&mut rng)).collect());

    let prep_session = network.session("prep")?;
    let mut online = network.session("online")?;
    let start = Instant::now();
    let report = match args.prep {
        Prep::Insecure => {
            // the dealer's seed only needs to be shared, this preprocessing is insecure anyway
            let seed = network.session("insecure dealer seed")?.coin(&mut rng)?;
            let mut prep = InsecurePreprocessor::new(prep_session, seed, true, bits, triples);
            prep.prep()?;
            let prep_duration = start.elapsed();
            run_one(
                args,
                party_id,
                n,
                prep,
                &mut online,
                &circuit,
                inputs.as_deref(),
            )?
            .map(|r| (r, prep_duration))
        }
        Prep::Secure => {
            let params = SecurePrepParams {
                rho: args.rho,
                bucket_size: args.bucket_size,
            };
            let mut prep =
                SecurePreprocessor::new(prep_session, &mut rng, true, bits, triples, params)?;
            prep.prep()?;
            let prep_duration = start.elapsed();
            run_one(
                args,
                party_id,
                n,
                prep,
                &mut online,
                &circuit,
                inputs.as_deref(),
            )?
            .map(|r| (r, prep_duration))
        }
    };
    let Some((report, prep_duration)) = report else {
        return Ok(None);
    };
    let outputs = report.outputs.expect("the evaluator has outputs");
    assert_eq!(outputs, circuit.eval_clear(inputs.as_deref().unwrap()));

    let mut tag = format!("{:?}", args.protocol()).to_ascii_lowercase();
    if matches!(args.prep, Prep::Secure) {
        tag.push_str("+secure_prep");
    }
    tag.push_str("+quic");
    let stats = network.stats();
    let bytes = |label: &str| {
        stats
            .iter()
            .filter(|(l, _)| (l == "online") == (label == "online"))
            .map(|(_, s)| s.bytes_sent)
            .sum()
    };
    Ok(Some(BenchmarkReport {
        prep_duration,
        garbling_duration: report.garbling_duration,
        evaluation_duration: report.evaluation_duration,
        party_count: n as usize,
        input_count: input_length as usize,
        circuit_name: circuit.name().to_string(),
        benchmark_tag: Some(tag),
        latency: None,
        // only the bytes sent by the evaluator
        prep_bytes: bytes("prep"),
        online_bytes: bytes("online"),
    }))
}

fn run_one<P: Preprocessor>(
    args: &Args,
    party_id: u16,
    n: u16,
    prep: P,
    online: &mut Session,
    circuit: &NamedCircuit,
    inputs: Option<&[F2]>,
) -> Result<Option<multiparty_gc::driver::PartyReport>, GcError> {
    let mut rng = AesRng::new();
    let report = match args.protocol() {
        Protocol::Copz => run_party::<_, CopzEvaluator, _>(
            CopzGarbler::new(party_id, n, prep),
            online,
            circuit.circuit(),
            inputs,
            &mut rng,
        )?,
        Protocol::Wrk17 => run_party::<_, Wrk17Evaluator, _>(
            Wrk17Garbler::new(party_id, n, prep),
            online,
            circuit.circuit(),
            inputs,
            &mut rng,
        )?,
    };
    Ok(report.outputs.is_some().then_some(report))
}

fn main() -> Result<(), GcError> {
    let args = Args::parse();
    if let Some(Command::GenConfig {
        num_parties,
        dir,
        host,
        base_port,
    }) = &args.command
    {
        return gen_config(*num_parties, dir, host, *base_port);
    }
    if let Some(party_id) = args.party_id {
        if let Some(report) = run_networked(&args, party_id)? {
            if args.show_header {
                println!("{}", BenchmarkReport::csv_header());
            }
            println!("{}", report.csv());
        }
        return Ok(());
    }
    let reports = (0..args.average_over)
        .map(|_| bench_once(&args))
        .collect::<Result<Vec<_>, _>>()?;

    let final_report = BenchmarkReport {
        prep_duration: reports.iter().map(|r| r.prep_duration).sum::<Duration>()
            / args.average_over,
        garbling_duration: reports
            .iter()
            .map(|r| r.garbling_duration)
            .sum::<Duration>()
            / args.average_over,
        evaluation_duration: reports
            .iter()
            .map(|r| r.evaluation_duration)
            .sum::<Duration>()
            / args.average_over,
        party_count: reports[0].party_count,
        input_count: reports[0].input_count,
        circuit_name: reports[0].circuit_name.clone(),
        benchmark_tag: reports[0].benchmark_tag.clone(),
        latency: reports[0].latency,
        prep_bytes: reports.iter().map(|r| r.prep_bytes).sum::<u64>() / args.average_over as u64,
        online_bytes: reports.iter().map(|r| r.online_bytes).sum::<u64>()
            / args.average_over as u64,
    };

    // print the result
    if args.show_header {
        println!("{}", BenchmarkReport::csv_header());
    }
    println!("{}", final_report.csv());
    Ok(())
}
