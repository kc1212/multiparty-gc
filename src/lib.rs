use swanky_field_binary::F128b;

pub trait GcPrf {
    fn run(&self, key: F128b, player: usize, gate: usize) -> F128b;
}

pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod prep;
pub mod sharing;
