//! Strict binary encoding of protocol messages.
//!
//! The encoded length of every message is fully determined by public information
//! (its [Wire::Shape]), so a receiver knows how many bytes to expect and decoding
//! rejects anything that is not the canonical encoding of a value.

use std::ops::Index;

use scuttlebutt::{ring::FiniteRing, serialization::CanonicalSerialize};
use swanky_field_binary::{F2, F128b};
use thiserror::Error;

use super::PartyId;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("malformed message: {0}")]
pub struct WireError(pub String);

/// Reads the encoding of a message front to back.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Take the next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if n > self.buf.len() {
            return Err(WireError(format!(
                "needed {n} bytes but only {} are left",
                self.buf.len()
            )));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Check that the whole message was consumed.
    pub fn finish(self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError(format!("{} trailing bytes", self.buf.len())))
        }
    }
}

/// A message with a canonical binary encoding.
///
/// `encode` must write exactly [Wire::encoded_len] bytes for the shape of the value
/// and `decode` must only accept canonical encodings.
pub trait Wire: Sized {
    /// Public information that determines the length of the encoding.
    type Shape;

    fn encoded_len(shape: &Self::Shape) -> usize;

    fn encode(&self, out: &mut Vec<u8>);

    fn decode(reader: &mut Reader<'_>, shape: &Self::Shape) -> Result<Self, WireError>;

    fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        self.encode(&mut out);
        out
    }

    /// Decode a complete message, rejecting wrong lengths and trailing bytes.
    fn from_wire_bytes(bytes: &[u8], shape: &Self::Shape) -> Result<Self, WireError> {
        let expected = Self::encoded_len(shape);
        if bytes.len() != expected {
            return Err(WireError(format!(
                "expected {expected} bytes but got {}",
                bytes.len()
            )));
        }
        let mut reader = Reader::new(bytes);
        let value = Self::decode(&mut reader, shape)?;
        reader.finish()?;
        Ok(value)
    }
}

impl Wire for () {
    type Shape = ();

    fn encoded_len(_: &()) -> usize {
        0
    }

    fn encode(&self, _: &mut Vec<u8>) {}

    fn decode(_: &mut Reader<'_>, _: &()) -> Result<Self, WireError> {
        Ok(())
    }
}

impl Wire for bool {
    type Shape = ();

    fn encoded_len(_: &()) -> usize {
        1
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(*self as u8);
    }

    fn decode(reader: &mut Reader<'_>, _: &()) -> Result<Self, WireError> {
        match reader.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(WireError(format!("invalid bit {b}"))),
        }
    }
}

impl Wire for F128b {
    type Shape = ();

    fn encoded_len(_: &()) -> usize {
        16
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_bytes());
    }

    fn decode(reader: &mut Reader<'_>, _: &()) -> Result<Self, WireError> {
        // every 128-bit string is a canonical field element
        Ok(F128b::from_uniform_bytes(
            reader.take(16)?.try_into().unwrap(),
        ))
    }
}

impl<const N: usize> Wire for [u8; N] {
    type Shape = ();

    fn encoded_len(_: &()) -> usize {
        N
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }

    fn decode(reader: &mut Reader<'_>, _: &()) -> Result<Self, WireError> {
        Ok(reader.take(N)?.try_into().unwrap())
    }
}

/// A vector of `len` elements, the shape is `(len, element shape)`.
impl<T: Wire> Wire for Vec<T> {
    type Shape = (usize, T::Shape);

    fn encoded_len((len, shape): &Self::Shape) -> usize {
        len.saturating_mul(T::encoded_len(shape))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for x in self {
            x.encode(out);
        }
    }

    fn decode(reader: &mut Reader<'_>, (len, shape): &Self::Shape) -> Result<Self, WireError> {
        (0..*len).map(|_| T::decode(reader, shape)).collect()
    }
}

impl<A: Wire, B: Wire> Wire for (A, B) {
    type Shape = (A::Shape, B::Shape);

    fn encoded_len((a, b): &Self::Shape) -> usize {
        A::encoded_len(a).saturating_add(B::encoded_len(b))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
        self.1.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, (a, b): &Self::Shape) -> Result<Self, WireError> {
        Ok((A::decode(reader, a)?, B::decode(reader, b)?))
    }
}

impl<A: Wire, B: Wire, C: Wire> Wire for (A, B, C) {
    type Shape = (A::Shape, B::Shape, C::Shape);

    fn encoded_len((a, b, c): &Self::Shape) -> usize {
        A::encoded_len(a)
            .saturating_add(B::encoded_len(b))
            .saturating_add(C::encoded_len(c))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
        self.1.encode(out);
        self.2.encode(out);
    }

    fn decode(reader: &mut Reader<'_>, (a, b, c): &Self::Shape) -> Result<Self, WireError> {
        Ok((
            A::decode(reader, a)?,
            B::decode(reader, b)?,
            C::decode(reader, c)?,
        ))
    }
}

/// A packed bit vector, the shape is the number of bits.
/// The padding bits of the last byte must be zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bits(pub Vec<bool>);

impl Bits {
    pub fn from_f2(xs: &[F2]) -> Self {
        Self(xs.iter().map(|x| bool::from(*x)).collect())
    }

    pub fn into_f2(self) -> Vec<F2> {
        self.0.into_iter().map(F2::from).collect()
    }
}

impl Wire for Bits {
    type Shape = usize;

    fn encoded_len(len: &usize) -> usize {
        len.div_ceil(8)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for chunk in self.0.chunks(8) {
            out.push(
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, b)| acc | ((*b as u8) << i)),
            );
        }
    }

    fn decode(reader: &mut Reader<'_>, len: &usize) -> Result<Self, WireError> {
        let bytes = reader.take(len.div_ceil(8))?;
        if !len.is_multiple_of(8) && bytes[bytes.len() - 1] >> (len % 8) != 0 {
            return Err(WireError("non-zero padding bits".into()));
        }
        Ok(Self(
            (0..*len)
                .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
                .collect(),
        ))
    }
}

/// Messages received from every peer, indexed by party.
#[derive(Debug)]
pub struct PerParty<T> {
    me: PartyId,
    items: Vec<Option<T>>,
}

impl<T> PerParty<T> {
    pub(crate) fn new(me: PartyId, items: Vec<Option<T>>) -> Self {
        Self { me, items }
    }

    /// The messages of all peers in ascending order of party.
    pub fn iter(&self) -> impl Iterator<Item = (PartyId, &T)> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(j, x)| x.as_ref().map(|x| (j as PartyId, x)))
    }

    pub fn into_peers(self) -> impl Iterator<Item = (PartyId, T)> {
        self.items
            .into_iter()
            .enumerate()
            .filter_map(|(j, x)| x.map(|x| (j as PartyId, x)))
    }
}

impl<T> Index<usize> for PerParty<T> {
    type Output = T;

    fn index(&self, party: usize) -> &T {
        self.items[party]
            .as_ref()
            .unwrap_or_else(|| panic!("no message from party {party}, we are party {}", self.me))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Wire + PartialEq + std::fmt::Debug>(x: T, shape: T::Shape) {
        let bytes = x.to_wire_bytes();
        assert_eq!(bytes.len(), T::encoded_len(&shape));
        assert_eq!(T::from_wire_bytes(&bytes, &shape).unwrap(), x);
        // wrong lengths are rejected
        assert!(T::from_wire_bytes(&[bytes.as_slice(), &[0]].concat(), &shape).is_err());
        if !bytes.is_empty() {
            assert!(T::from_wire_bytes(&bytes[1..], &shape).is_err());
        }
    }

    #[test]
    fn test_roundtrips() {
        roundtrip((), ());
        roundtrip(true, ());
        roundtrip(F128b::from_uniform_bytes(&[7; 16]), ());
        roundtrip([3u8; 32], ());
        roundtrip(Bits(vec![true, false, true]), 3);
        roundtrip(Bits(vec![true; 16]), 16);
        roundtrip(Bits(vec![]), 0);
        roundtrip(vec![[1u8; 2], [2u8; 2]], (2, ()));
        roundtrip((true, vec![F128b::ONE; 3], [9u8; 4]), ((), (3, ()), ()));
    }

    #[test]
    fn test_reject_non_canonical() {
        assert!(bool::from_wire_bytes(&[2], &()).is_err());
        // padding bits must be zero
        assert!(Bits::from_wire_bytes(&[0b1000], &3).is_err());
        assert_eq!(
            Bits::from_wire_bytes(&[0b101], &3).unwrap(),
            Bits(vec![true, false, true])
        );
    }

    #[test]
    fn test_bits_f2() {
        let xs = vec![F2::ONE, F2::ZERO, F2::ONE];
        assert_eq!(Bits::from_f2(&xs).into_f2(), xs);
    }
}
