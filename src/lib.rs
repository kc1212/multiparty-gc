use swanky_field_binary::{F2, F128b};

pub trait GcPrf {
    fn run(&self, key: F128b, player: usize, gate: usize) -> F128b;
}

pub trait MsgRound1 {}

pub trait MsgRound2 {
    fn into_masked_inputs(self) -> Vec<F2>;
}

pub trait MsgRound3 {
    fn into_labels(self) -> Vec<F128b>;
}

pub mod error;
pub mod evaluator;
pub mod garbler;
pub mod prep;
pub mod sharing;

#[cfg(test)]
mod test {
    use crate::{
        evaluator::Evaluator,
        garbler::{Garbler, Garbling},
    };

    fn test_generic<Gc: Garbling, G: Garbler<Gc>, E: Evaluator>() {}
}
