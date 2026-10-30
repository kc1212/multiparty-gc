use std::sync::mpsc::{RecvError, SendError};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GcError {
    #[error(transparent)]
    ChanRecvError(#[from] RecvError),
    #[error("Channel send error")]
    ChanSendError,
    #[error("Unexpected message type {0}")]
    UnexpectedMessageType(String),
    #[error("Not all elements are equal")]
    NotAllEqual,
    #[error("MAC check failure")]
    MacCheckFailure,
    #[error("Decoder MAC check failure")]
    DecoderCheckFailure,
    #[error("Decoder length error")]
    DecoderLengthError,
    #[error("Input round 2 MAC check failure")]
    InputRound2CheckFailure,
    #[error("Output check failure {0}")]
    OutputCheckFailure(String),
    #[error("Wrong party received opening {0}")]
    WrongOpening(String),
    #[error("Cheating detected: {0}")]
    CheatDetected(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Oblivious transfer error: {0}")]
    OtError(String),
    #[error("Not enough preprocessed material: {0}")]
    NotEnoughMaterial(String),
    #[error("Invalid preprocessing parameters: {0}")]
    InvalidPrepParams(String),
}

impl From<ocelot::Error> for GcError {
    fn from(err: ocelot::Error) -> Self {
        Self::OtError(err.to_string())
    }
}

impl<T> From<SendError<T>> for GcError {
    fn from(_err: SendError<T>) -> Self {
        Self::ChanSendError
    }
}
