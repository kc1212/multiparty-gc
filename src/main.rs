use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use itertools::Itertools;
use multiparty_gc::{
    BenchmarkReport, NamedCircuit,
    error::GcError,
    evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
    full_simulation,
    garbler::{copz::CopzGarbler, wrk17::Wrk17Garbler},
    prep::{InsecurePreprocessor, Preprocessor, SecurePrepParams, SecurePreprocessor, run_prep},
};
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
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(2..))]
    num_parties: u16,

    #[arg(short, long)]
    protocol: Protocol,

    #[arg(short, long)]
    circuit: Circuit,

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

    #[arg(long, default_value = None)]
    latency_ms: Option<u64>,

    #[arg(long)]
    show_header: bool,
}

fn run_protocol<P: Preprocessor + Send + 'static>(
    args: &Args,
    circuit: &NamedCircuit,
    preps: Vec<P>,
    true_inputs: Vec<F2>,
) -> BenchmarkReport {
    let mut benchmark_tag = format!("{:?}", args.protocol).to_ascii_lowercase();
    if matches!(args.prep, Prep::Secure) {
        benchmark_tag.push_str("+secure_prep");
    }
    let latency = args.latency_ms.map(Duration::from_millis);
    match args.protocol {
        Protocol::Copz => {
            let garblers = preps
                .into_iter()
                .enumerate()
                .map(|(party_id, prep)| CopzGarbler::new(party_id as u16, args.num_parties, prep))
                .collect_vec();

            full_simulation::<_, CopzEvaluator, _>(
                garblers,
                circuit,
                true_inputs,
                true,
                Some(benchmark_tag),
                latency,
            )
        }
        Protocol::Wrk17 => {
            let garblers = preps
                .into_iter()
                .enumerate()
                .map(|(party_id, prep)| Wrk17Garbler::new(party_id as u16, args.num_parties, prep))
                .collect_vec();

            full_simulation::<_, Wrk17Evaluator, _>(
                garblers,
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
    let circuit = NamedCircuit::from_path(args.circuit.file_name());

    let mut rng = AesRng::new();

    // prpeare input
    let input_length: u64 = circuit.input_sizes().iter().sum();
    let true_inputs = (0..input_length).map(|_| F2::random(&mut rng)).collect();

    // prepare preprocessing
    let triples = circuit.nand() as usize;
    let bits = (circuit.nand() + input_length) as usize;
    let latency = args.latency_ms.map(Duration::from_millis);
    let start = Instant::now();
    match args.prep {
        Prep::Insecure => {
            let (preps, runner) =
                InsecurePreprocessor::new(&mut rng, args.num_parties, true, bits, triples, latency);
            let prep_handler = std::thread::spawn(move || runner.run_blocking().unwrap());
            let prep_duration = start.elapsed();

            let mut report = run_protocol(args, &circuit, preps, true_inputs);
            prep_handler.join().unwrap();
            report.prep_duration = prep_duration;
            Ok(report)
        }
        Prep::Secure => {
            let params = SecurePrepParams {
                rho: args.rho,
                bucket_size: args.bucket_size,
            };
            let preps = SecurePreprocessor::new(
                &mut rng,
                args.num_parties,
                true,
                bits,
                triples,
                params,
                latency,
            )?;
            let preps = run_prep(preps)?;
            let prep_duration = start.elapsed();

            let mut report = run_protocol(args, &circuit, preps, true_inputs);
            report.prep_duration = prep_duration;
            Ok(report)
        }
    }
}

fn main() -> Result<(), GcError> {
    let args = Args::parse();
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
    };

    // print the result
    if args.show_header {
        println!("{}", BenchmarkReport::csv_header());
    }
    println!("{}", final_report.csv());
    Ok(())
}
