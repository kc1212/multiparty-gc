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
    #[error("Wrong party received opening")]
    WrongOpening,
}

impl<T> From<SendError<T>> for GcError {
    fn from(_err: SendError<T>) -> Self {
        Self::ChanSendError
    }
}
