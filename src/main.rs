use std::time::Duration;

use clap::{Parser, ValueEnum};
use itertools::Itertools;
use multiparty_gc::{
    BenchmarkReport, NamedCircuit,
    evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
    full_simulation,
    garbler::{copz::CopzGarbler, wrk17::Wrk17Garbler},
    prep::InsecurePreprocessor,
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

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 3)]
    num_parties: u16,

    #[arg(short, long)]
    protocol: Protocol,

    #[arg(short, long)]
    circuit: Circuit,

    #[arg(long, default_value_t = 1)]
    average_over: u32,

    #[arg(long)]
    show_header: bool,
}

fn bench_once(args: &Args) -> BenchmarkReport {
    let circuit = NamedCircuit::from_path(args.circuit.file_name());

    let mut rng = AesRng::new();

    // prpeare input
    let input_length: u64 = circuit.input_sizes().iter().sum();
    let true_inputs = (0..input_length).map(|_| F2::random(&mut rng)).collect();

    // prepare preprocessing
    let triples = circuit.nand();
    let bits = circuit.nand() + input_length;
    let (preps, runner) = InsecurePreprocessor::new(
        &mut rng,
        args.num_parties,
        true,
        bits as usize,
        triples as usize,
    );
    let prep_handler = std::thread::spawn(move || runner.run_blocking().unwrap());

    // run the full protocol
    let benchmark_tag = Some(format!("{:?}", args.protocol).to_ascii_lowercase());
    let report = match args.protocol {
        Protocol::Copz => {
            let garblers = preps
                .into_iter()
                .enumerate()
                .map(|(party_id, prep)| CopzGarbler::new(party_id as u16, args.num_parties, prep))
                .collect_vec();

            full_simulation::<_, CopzEvaluator, _>(
                garblers,
                &circuit,
                true_inputs,
                true,
                benchmark_tag,
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
                &circuit,
                true_inputs,
                true,
                benchmark_tag,
            )
        }
    };
    prep_handler.join().unwrap();

    report
}

fn main() {
    let args = Args::parse();
    let reports = (0..args.average_over)
        .map(|_| bench_once(&args))
        .collect_vec();

    let final_report = BenchmarkReport {
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
    };

    // print the result
    if args.show_header {
        println!("{}", BenchmarkReport::csv_header());
    }
    println!("{}", final_report.csv());
}
