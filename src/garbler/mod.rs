use bristol_fashion::Circuit;

mod wrk17;

pub trait Garbler<GT: GarbledTable> {
    fn garble(&mut self, circuit: &Circuit, output: &mut GT);
    fn party_id(&self) -> u16;
}

pub trait GarbledTable {
    type GarbledGate;

    fn push_gate(&mut self, garbled_gate: Self::GarbledGate);

    fn read_gate(&self, i: usize) -> &Self::GarbledGate;
}
