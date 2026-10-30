use std::io::BufReader;

use criterion::{Criterion, criterion_group, criterion_main};
use itertools::Itertools;
use multiparty_gc::{
    NamedCircuit, SimParty,
    evaluator::{copz::CopzEvaluator, wrk17::Wrk17Evaluator},
    full_simulation,
    garbler::{Garbler, copz::CopzGarbler, wrk17::Wrk17Garbler},
    in_memory_setup,
    net::memory::LinkModel,
    prep::{InsecureBenchPreprocessor, InsecurePreprocessor, run_prep},
};
use rand::Rng;
use scuttlebutt::{AesRng, ring::FiniteRing};
use swanky_field_binary::F2;

macro_rules! bench_full_aes {
    ($garbler:ty,$evaluator:ty,$c:ident,$bench_name:expr) => {{
        let num_parties = 3;
        let circuit = NamedCircuit::from_path("circuits/aes_128.txt");

        let input_length: u64 = circuit.input_sizes().iter().sum();
        let true_inputs = vec![F2::ZERO; input_length as usize];

        let input_wire_count: u64 = circuit.input_sizes().iter().sum();
        let triples = circuit.nand() as usize;
        let bits = (circuit.nand() + input_wire_count) as usize;

        $c.bench_function($bench_name, |b| {
            let true_inputs = true_inputs.clone();
            b.iter(|| {
                let mut rng = AesRng::new();
                let seed: [u8; 32] = rng.r#gen();
                let mut parties = vec![];
                for (party_id, setup) in in_memory_setup(num_parties, LinkModel::default())
                    .unwrap()
                    .into_iter()
                    .enumerate()
                {
                    let prep = InsecurePreprocessor::new(setup.prep, seed, true, bits, triples);
                    parties.push((prep, setup.online, setup.network, party_id));
                }
                let (preps, rest): (Vec<_>, Vec<_>) = parties
                    .into_iter()
                    .map(|(prep, online, network, i)| (prep, (online, network, i)))
                    .unzip();
                let preps = run_prep(preps).unwrap();
                let parties = preps
                    .into_iter()
                    .zip(rest)
                    .map(|(prep, (online, network, i))| SimParty {
                        garbler: <$garbler>::new(i as u16, num_parties, prep),
                        online,
                        network,
                    })
                    .collect_vec();
                full_simulation::<_, $evaluator>(
                    parties,
                    &circuit,
                    true_inputs.clone(),
                    false,
                    Some($bench_name.to_string()),
                    None,
                )
                .unwrap()
            })
        });
    }};
}

fn copz_full_aes(c: &mut Criterion) {
    bench_full_aes!(
        CopzGarbler::<InsecurePreprocessor>,
        CopzEvaluator,
        c,
        "copz full aes"
    )
}

fn wrk17_aes(c: &mut Criterion) {
    bench_full_aes!(
        Wrk17Garbler::<InsecurePreprocessor>,
        Wrk17Evaluator,
        c,
        "wrk17 full aes"
    )
}

macro_rules! bench_garble_aes {
    ($garbler:ty,$c:ident,$bench_name:expr) => {{
        let party_count = 3;
        let f = std::fs::File::open("circuits/aes_128.txt").unwrap();
        let buf_reader = BufReader::new(f);
        let circuit = bristol_fashion::read(buf_reader).unwrap();
        let mut rng = AesRng::new();
        let prep = InsecureBenchPreprocessor::new(party_count, circuit.nwires() as usize, &mut rng);
        $c.bench_function($bench_name, |b| {
            b.iter(|| {
                let mut garbler = <$garbler>::new(0, party_count, prep.clone());
                let mut rng = AesRng::new();
                let _ = garbler.garble(&mut rng, &circuit);
            });
        });
    }};
}

fn copz_garble_aes(c: &mut Criterion) {
    bench_garble_aes!(CopzGarbler<InsecureBenchPreprocessor>, c, "copz garble aes")
}

fn wrk17_garble_aes(c: &mut Criterion) {
    bench_garble_aes!(
        Wrk17Garbler<InsecureBenchPreprocessor>,
        c,
        "wrk17 garble aes"
    )
}

criterion_group!(
    benches,
    copz_full_aes,
    wrk17_aes,
    copz_garble_aes,
    wrk17_garble_aes
);
criterion_main!(benches);
