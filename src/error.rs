use thiserror::Error;

#[derive(Error, Debug)]
pub enum GcError {
    #[error("MAC check failure")]
    MacCheckFailure,
    #[error("Decoder MAC check failure")]
    DecoderCheckFailure,
    #[error("Input round 2 MAC check failure")]
    InputRound2CheckFailure,
}
