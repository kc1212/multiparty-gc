//! Canonical encodings of transmitted protocol messages.

use super::{
    CopzGarbledGate, CopzGarbling, CopzInputMsg1, CopzInputMsg2, CopzInputMsg3,
    CopzOutputMsg1Private, CopzOutputMsg1Public, CopzOutputMsg2,
};
use crate::{
    MsgShape,
    net::{
        Bits, Wire,
        wire::{Reader, WireError},
    },
};
use swanky_field_binary::F128b;

/// Length of one encrypted table: the label share and the shares for the other garblers.
fn copz_table_len(party_count: u16) -> usize {
    16 * (party_count as usize - 1)
}

/// Encoding of the garbling sent to the evaluator.
/// Party 0 (P2 in the paper) additionally sends the bits `b_w` for every AND gate.
impl Wire for CopzGarbling {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        let b_w_len = if shape.sender == 0 {
            Bits::encoded_len(&shape.and_gates)
        } else {
            0
        };
        shape
            .and_gates
            .saturating_mul(3 * copz_table_len(shape.party_count))
            .saturating_add(b_w_len)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for gate in &self.gates {
            for table in &gate.inner {
                out.extend_from_slice(table);
            }
        }
        if let Some(b_w) = &self.b_w {
            Bits::from_f2(b_w).encode(out);
        }
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        let table_len = copz_table_len(shape.party_count);
        let gates = (0..shape.and_gates)
            .map(|_| {
                let mut table = || -> Result<_, WireError> { Ok(reader.take(table_len)?.to_vec()) };
                Ok(CopzGarbledGate {
                    inner: [table()?, table()?, table()?],
                })
            })
            .collect::<Result<_, WireError>>()?;
        let b_w = if shape.sender == 0 {
            Some(Bits::decode(reader, &shape.and_gates)?.into_f2())
        } else {
            None
        };
        Ok(CopzGarbling { gates, b_w })
    }
}

impl Wire for CopzInputMsg1 {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        Bits::encoded_len(&shape.inputs)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        Bits::from_f2(&self.shares).encode(out);
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            shares: Bits::decode(reader, &shape.inputs)?.into_f2(),
        })
    }
}

impl Wire for CopzInputMsg2 {
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

impl Wire for CopzInputMsg3 {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        <(Vec<F128b>, Bits)>::encoded_len(&((shape.inputs, ()), shape.outputs))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.labels.encode(out);
        Bits::from_f2(&self.output_decoder).encode(out);
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            labels: Vec::decode(reader, &(shape.inputs, ()))?,
            output_decoder: Bits::decode(reader, &shape.outputs)?.into_f2(),
        })
    }
}

impl Wire for CopzOutputMsg1Public {
    type Shape = MsgShape;

    fn encoded_len(shape: &MsgShape) -> usize {
        <(Bits, [u8; 32])>::encoded_len(&(shape.and_gates, ()))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        Bits::from_f2(&self.w_hats).encode(out);
        self.chi.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, shape: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            w_hats: Bits::decode(reader, &shape.and_gates)?.into_f2(),
            chi: Wire::decode(reader, &())?,
        })
    }
}

impl Wire for CopzOutputMsg1Private {
    type Shape = MsgShape;

    fn encoded_len(_: &MsgShape) -> usize {
        32
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.h.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, _: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            h: Wire::decode(reader, &())?,
        })
    }
}

impl Wire for CopzOutputMsg2 {
    type Shape = MsgShape;

    fn encoded_len(_: &MsgShape) -> usize {
        F128b::encoded_len(&())
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.z_i.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, _: &MsgShape) -> Result<Self, WireError> {
        Ok(Self {
            z_i: F128b::decode(reader, &())?,
        })
    }
}
