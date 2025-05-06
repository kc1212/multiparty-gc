use std::io::BufReader;

use clap::{Parser, ValueEnum};
use itertools::Itertools;
use multiparty_gc::{
    BenchmarkReport,
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

    #[arg(long)]
    show_header: bool,
}

fn main() {
    let args = Args::parse();

    let f = std::fs::File::open(args.circuit.file_name()).unwrap();
    let buf_reader = BufReader::new(f);
    let circuit = bristol_fashion::read(buf_reader).unwrap();

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
    let report = match args.protocol {
        Protocol::Copz => {
            let garblers = preps
                .into_iter()
                .enumerate()
                .map(|(party_id, prep)| CopzGarbler::new(party_id as u16, args.num_parties, prep))
                .collect_vec();

            let benchmark_tag = Some(format!("copz-{:?}", args.circuit));
            full_simulation::<_, CopzEvaluator, _>(
                garblers,
                &circuit,
                true_inputs,
                false,
                benchmark_tag,
            )
        }
        Protocol::Wrk17 => {
            let garblers = preps
                .into_iter()
                .enumerate()
                .map(|(party_id, prep)| Wrk17Garbler::new(party_id as u16, args.num_parties, prep))
                .collect_vec();

            let benchmark_tag = Some(format!("wrk17-{:?}", args.circuit));
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

    // print the result
    if args.show_header {
        println!("{}", BenchmarkReport::csv_header());
    }
    println!("{}", report.csv());
}
