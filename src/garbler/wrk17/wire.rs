//! Canonical encodings of transmitted protocol messages.

use super::{
    Wrk17GarbledGate, Wrk17GarbledRow, Wrk17Garbling, Wrk17InputMsg1, Wrk17InputMsg2,
    Wrk17InputMsg3,
};
use crate::{
    MsgShape,
    net::{
        Bits, Wire,
        wire::{Reader, WireError},
    },
};
use swanky_field_binary::{F2, F128b};

/// Length of an encrypted row: the share, the MACs for the other parties and the label.
fn wrk17_row_len(party_count: u16) -> usize {
    1 + 16 * (party_count as usize - 1) + 16
}

/// The gates belong to `shape.sender`.
impl Wire for Wrk17Garbling {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        shape
            .and_gates
            .saturating_mul(4 * wrk17_row_len(shape.party_count))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for gate in &self.0 {
            for row in &gate.rows {
                out.extend_from_slice(&row.inner);
            }
        }
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        let row_len = wrk17_row_len(shape.party_count);
        let gates = (0..shape.and_gates)
            .map(|_| {
                let mut row = || -> Result<_, WireError> {
                    Ok(Wrk17GarbledRow {
                        inner: reader.take(row_len)?.to_vec(),
                    })
                };
                Ok(Wrk17GarbledGate {
                    party_id: shape.sender,
                    rows: [row()?, row()?, row()?, row()?],
                })
            })
            .collect::<Result<_, WireError>>()?;
        Ok(Wrk17Garbling(gates))
    }
}

impl Wire for Wrk17InputMsg1 {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        <(Bits, Vec<F128b>)>::encoded_len(&(shape.inputs, (shape.inputs, ())))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        Bits::from_f2(&self.shares).encode(out);
        self.macs.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            shares: Bits::decode(reader, &shape.inputs)?.into_f2(),
            macs: Vec::decode(reader, &(shape.inputs, ()))?,
        })
    }
}

impl Wire for Wrk17InputMsg2 {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        Bits::encoded_len(&shape.inputs)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        Bits::from_f2(&self.masked_inputs).encode(out);
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            masked_inputs: Bits::decode(reader, &shape.inputs)?.into_f2(),
        })
    }
}

impl Wire for Wrk17InputMsg3 {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        <(Vec<F128b>, Bits, Vec<F128b>)>::encoded_len(&(
            (shape.inputs, ()),
            shape.outputs,
            (shape.outputs, ()),
        ))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.labels.encode(out);
        let (shares, macs): (Vec<F2>, Vec<F128b>) = self.output_decoder.iter().copied().unzip();
        Bits::from_f2(&shares).encode(out);
        macs.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        let labels = Vec::decode(reader, &(shape.inputs, ()))?;
        let shares = Bits::decode(reader, &shape.outputs)?.into_f2();
        let macs: Vec<F128b> = Vec::decode(reader, &(shape.outputs, ()))?;
        Ok(Self {
            labels,
            output_decoder: shares.into_iter().zip(macs).collect(),
        })
    }
}
