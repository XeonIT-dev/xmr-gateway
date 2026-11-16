//! Core domain models and strict integer arithmetic for `xmr-gateway`.
//!
//! All monetary values are represented exclusively in atomic piconero integers (`u64`) via
//! [`amount::Piconero`], and invoice lifecycle invariants are enforced by [`invoice::Invoice`]
//! and [`invoice::InvoiceStatus`].

pub mod amount;
pub mod invoice;
