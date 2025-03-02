use bristol_fashion::Circuit;

mod wrk17;

trait Garbler {
    fn garble(&mut self, circuit: &Circuit);
    fn party_id(&self) -> u32;
}
