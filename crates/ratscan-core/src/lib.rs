//! Static scanner and rules engine shared by RatScan services.
//!
//! Some recognizer helpers are retained for rule-set compatibility while their
//! corresponding rules are disabled; they are deliberately not exported as API.
#![allow(
    dead_code,
    clippy::collapsible_if,
    clippy::collapsible_str_replace,
    clippy::double_ended_iterator_last,
    clippy::manual_is_multiple_of,
    clippy::manual_range_patterns,
    clippy::needless_borrow,
    clippy::obfuscated_if_else,
    clippy::too_many_arguments
)]

pub mod models {
    pub use ratscan_models::scan;
}

pub mod rules;
pub mod scanner;
