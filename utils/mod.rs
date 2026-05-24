pub mod error;
pub mod url_utils;
pub mod helpers;
pub mod diff;

pub use error::ScanError;
pub use diff::{diff_responses, confidence_from_diff};
