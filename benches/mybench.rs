use std::io::BufReader;

use criterion::{Criterion, criterion_group, criterion_main};
use itertools::Itertools;
use multiparty_gc::{
    evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
    full_simulation,
    garbler::{copz::CopzGarbler, wrk17::Wrk17Garbler},
    prep::InsecurePreprocessor,
};
use scuttlebutt::{AesRng, ring::FiniteRing};
use swanky_field_binary::F2;

fn copz_aes(c: &mut Criterion) {
    let num_parties = 2;
    let f = std::fs::File::open("circuits/aes_128.txt").unwrap();
    let buf_reader = BufReader::new(f);
    let circuit = bristol_fashion::read(buf_reader).unwrap();

    let input_length: u64 = circuit.input_sizes().iter().sum();
    let true_inputs = vec![F2::ZERO; input_length as usize];

    // shutdown
    c.bench_function("copz aes", |b| {
        let true_inputs = true_inputs.clone();
        b.iter(|| {
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
            full_simulation::<_, CopzEvaluator, _>(garblers, &circuit, true_inputs.clone(), false);

            prep_handler.join().unwrap()
        })
    });
}

fn wrk17_aes(c: &mut Criterion) {
    let num_parties = 2;
    let f = std::fs::File::open("circuits/aes_128.txt").unwrap();
    let buf_reader = BufReader::new(f);
    let circuit = bristol_fashion::read(buf_reader).unwrap();

    let input_length: u64 = circuit.input_sizes().iter().sum();
    let true_inputs = vec![F2::ZERO; input_length as usize];

    // shutdown
    c.bench_function("wrk17 aes", |b| {
        let true_inputs = true_inputs.clone();
        b.iter(|| {
            let (preps, runner) = InsecurePreprocessor::new(num_parties, true);
            let prep_handler = std::thread::spawn(move || {
                let mut rng = AesRng::new();
                runner.run_blocking(&mut rng).unwrap()
            });

            let garblers = preps
                .into_iter()
                .enumerate()
                .map(|(party_id, prep)| Wrk17Garbler::new(party_id as u16, num_parties, prep))
                .collect_vec();
            full_simulation::<_, Wrk17Evaluator, _>(garblers, &circuit, true_inputs.clone(), false);

            prep_handler.join().unwrap()
        })
    });
}

criterion_group!(benches, copz_aes, wrk17_aes);
criterion_main!(benches);
