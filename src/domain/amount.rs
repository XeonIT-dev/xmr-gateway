//! Atomic Monero monetary arithmetic in piconero (`1 XMR = 10^12 piconero`).
//!
//! # Financial Safety Invariant
//! Floating-point types (`f32`, `f64`) are **strictly forbidden** throughout the domain,
//! persistence, RPC, and API layers because IEEE-754 binary floats cannot represent arbitrary
//! base-10 piconero fractions without silent rounding errors. All amounts use [`Piconero`], a
//! transparent `u64` wrapper, and convert to/from decimal strings strictly via integer division
//! and modulo operations.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Number of atomic piconero in exactly 1 Monero (XMR): $10^{12}$.
pub const PICONERO_PER_XMR: u64 = 1_000_000_000_000;

/// Number of decimal digits after the radix point in canonical Monero representation.
pub const XMR_DECIMAL_PLACES: usize = 12;

/// Strongly-typed atomic Monero amount in piconero ($1\text{ XMR} = 10^{12}\text{ piconero}$).
///
/// # Invariants
/// - Internal unit is always atomic piconero (`u64`).
/// - SQLite stores signed 64-bit `INTEGER`s, so persistence conversions ([`Piconero::to_i64`]
///   and [`Piconero::from_i64`]) verify bounds against `0..=i64::MAX` (`~9.22M XMR`) explicitly
///   rather than silently wrapping via `as i64`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Piconero(pub u64);

impl Piconero {
    /// Zero piconero (`0.000000000000 XMR`).
    pub const ZERO: Self = Self(0);

    /// Maximum piconero value representable in an unsigned 64-bit integer.
    pub const MAX: Self = Self(u64::MAX);

    /// Wraps a raw `u64` piconero count.
    #[must_use]
    pub const fn from_piconero(value: u64) -> Self {
        Self(value)
    }

    /// Extracts the underlying `u64` piconero count.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns `true` if the amount is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Checked addition returning [`DomainError::AmountOverflow`] on `u64` overflow.
    ///
    /// # Errors
    /// Returns [`DomainError::AmountOverflow`] if `self.0 + rhs.0 > u64::MAX`.
    pub fn checked_add(self, rhs: Self) -> Result<Self, DomainError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or_else(|| DomainError::AmountOverflow(format!("{} + {}", self.0, rhs.0)))
    }

    /// Checked subtraction returning [`DomainError::AmountUnderflow`] if `rhs > self`.
    ///
    /// # Errors
    /// Returns [`DomainError::AmountUnderflow`] if `self.0 < rhs.0`.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, DomainError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or_else(|| DomainError::AmountUnderflow(format!("{} - {}", self.0, rhs.0)))
    }

    /// Saturating addition clamped at `u64::MAX`.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction clamped at `0`.
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Converts to a signed `i64` for SQLite `INTEGER` binding without bit-wrapping.
    ///
    /// # Errors
    /// Returns [`DomainError::AmountOverflow`] if `self.0 > i64::MAX as u64`.
    pub fn to_i64(self) -> Result<i64, DomainError> {
        i64::try_from(self.0).map_err(|_| {
            DomainError::AmountOverflow(format!(
                "piconero amount {} exceeds signed SQLite INTEGER maximum {}",
                self.0,
                i64::MAX
            ))
        })
    }

    /// Converts a SQLite `INTEGER` back into [`Piconero`], rejecting negative values.
    ///
    /// # Errors
    /// Returns [`DomainError::AmountUnderflow`] if `value < 0`.
    pub fn from_i64(value: i64) -> Result<Self, DomainError> {
        u64::try_from(value)
            .map(Self)
            .map_err(|_| DomainError::AmountUnderflow(format!("negative database amount {value}")))
    }

    /// Formats the atomic amount into an exact 12-decimal XMR string using pure integer math.
    ///
    /// Examples:
    /// - `0` -> `"0.000000000000"`
    /// - `1` -> `"0.000000000001"`
    /// - `1_000_000_000_000` -> `"1.000000000000"`
    /// - `u64::MAX` -> `"18446744.073709551615"`
    #[must_use]
    pub fn to_xmr_string(self) -> String {
        let whole = self.0 / PICONERO_PER_XMR;
        let frac = self.0 % PICONERO_PER_XMR;
        format!("{whole}.{frac:0XMR_DECIMAL_PLACES$}")
    }

    /// Parses a decimal XMR string (e.g., `"1.5"`, `"0.000000000001"`, `"42"`) into [`Piconero`]
    /// using pure integer arithmetic.
    ///
    /// # Rules & Invariants
    /// - Signs (`+`, `-`), whitespace, underscores, scientific notation, and leading/trailing dots
    ///   (like `".5"` or `"1."`) are rejected.
    /// - Up to 12 fractional digits are accepted; more than 12 digits are rejected so atomic
    ///   precision is never silently truncated.
    /// - Overflows above `u64::MAX` return [`DomainError::AmountOverflow`].
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidAmountFormat`] for malformed strings or excessive decimal
    /// precision, and [`DomainError::AmountOverflow`] if the parsed value exceeds `u64::MAX`.
    pub fn from_xmr_str(raw: &str) -> Result<Self, DomainError> {
        if raw.is_empty() {
            return Err(DomainError::InvalidAmountFormat(
                "amount string cannot be empty".to_string(),
            ));
        }

        let (whole_str, frac_str) = match raw.split_once('.') {
            Some((whole, frac)) => {
                if frac.contains('.') {
                    return Err(DomainError::InvalidAmountFormat(format!(
                        "multiple decimal points in '{raw}'"
                    )));
                }
                if whole.is_empty() || frac.is_empty() {
                    return Err(DomainError::InvalidAmountFormat(format!(
                        "missing integer or fractional digits in '{raw}'"
                    )));
                }
                (whole, frac)
            }
            None => (raw, ""),
        };

        if !whole_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DomainError::InvalidAmountFormat(format!(
                "invalid integer digits in '{raw}'"
            )));
        }

        if !frac_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DomainError::InvalidAmountFormat(format!(
                "invalid fractional digits in '{raw}'"
            )));
        }

        if frac_str.len() > XMR_DECIMAL_PLACES {
            return Err(DomainError::InvalidAmountFormat(format!(
                "fractional precision exceeds {XMR_DECIMAL_PLACES} decimal places in '{raw}'"
            )));
        }

        let whole: u64 = whole_str
            .parse()
            .map_err(|_| DomainError::AmountOverflow(format!("whole XMR overflow in '{raw}'")))?;

        let whole_piconero = whole
            .checked_mul(PICONERO_PER_XMR)
            .ok_or_else(|| DomainError::AmountOverflow(format!("piconero overflow in '{raw}'")))?;

        let frac_piconero = if frac_str.is_empty() {
            0
        } else {
            let parsed_frac: u64 = frac_str.parse().map_err(|_| {
                DomainError::InvalidAmountFormat(format!("invalid fraction in '{raw}'"))
            })?;
            let missing_zeros =
                u32::try_from(XMR_DECIMAL_PLACES - frac_str.len()).map_err(|_| {
                    DomainError::InvalidAmountFormat("fractional length overflow".to_string())
                })?;
            let scale = 10_u64.pow(missing_zeros);
            parsed_frac * scale
        };

        let total = whole_piconero
            .checked_add(frac_piconero)
            .ok_or_else(|| DomainError::AmountOverflow(format!("piconero overflow in '{raw}'")))?;

        Ok(Self(total))
    }
}

impl fmt::Display for Piconero {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_xmr_string())
    }
}

impl FromStr for Piconero {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_xmr_str(s)
    }
}

impl From<u64> for Piconero {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl TryFrom<i64> for Piconero {
    type Error = DomainError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::from_i64(value)
    }
}

impl TryFrom<Piconero> for i64 {
    type Error = DomainError;

    fn try_from(value: Piconero) -> Result<Self, Self::Error> {
        value.to_i64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_boundary_values_without_floating_point_loss() {
        assert_eq!(Piconero::ZERO.to_xmr_string(), "0.000000000000");
        assert_eq!(Piconero(1).to_xmr_string(), "0.000000000001");
        assert_eq!(
            Piconero(1_000_000_000_000).to_xmr_string(),
            "1.000000000000"
        );
        assert_eq!(
            Piconero(1_500_000_000_000).to_xmr_string(),
            "1.500000000000"
        );
        assert_eq!(Piconero::MAX.to_xmr_string(), "18446744.073709551615");
    }

    #[test]
    fn parses_xmr_strings_and_roundtrips() {
        assert_eq!(Piconero::from_xmr_str("0").unwrap(), Piconero::ZERO);
        assert_eq!(
            Piconero::from_xmr_str("0.000000000001").unwrap(),
            Piconero(1)
        );
        assert_eq!(
            Piconero::from_xmr_str("1").unwrap(),
            Piconero(1_000_000_000_000)
        );
        assert_eq!(
            Piconero::from_xmr_str("1.25").unwrap(),
            Piconero(1_250_000_000_000)
        );
        assert_eq!(
            Piconero::from_xmr_str("18446744.073709551615").unwrap(),
            Piconero::MAX
        );

        for sample in [
            0_u64,
            1,
            999,
            1_000_000_000_000,
            123_456_789_012_345,
            u64::MAX,
        ] {
            let amount = Piconero(sample);
            assert_eq!(
                Piconero::from_xmr_str(&amount.to_xmr_string()).unwrap(),
                amount
            );
        }
    }

    #[test]
    fn rejects_malformed_negative_over_precise_and_overflowing_strings() {
        assert!(Piconero::from_xmr_str("").is_err());
        assert!(Piconero::from_xmr_str("-1.0").is_err());
        assert!(Piconero::from_xmr_str("+1.0").is_err());
        assert!(Piconero::from_xmr_str(" 1.0").is_err());
        assert!(Piconero::from_xmr_str(".5").is_err());
        assert!(Piconero::from_xmr_str("1.").is_err());
        assert!(Piconero::from_xmr_str("1.2.3").is_err());
        assert!(Piconero::from_xmr_str("1e12").is_err());
        // 13 fractional digits must be rejected (no silent truncation)
        assert!(Piconero::from_xmr_str("0.0000000000001").is_err());
        // u64::MAX + 1 piconero
        assert!(Piconero::from_xmr_str("18446744.073709551616").is_err());
    }

    #[test]
    fn checked_arithmetic_and_sqlite_i64_bounds() {
        assert_eq!(
            Piconero(100).checked_add(Piconero(50)).unwrap(),
            Piconero(150)
        );
        assert!(Piconero::MAX.checked_add(Piconero(1)).is_err());
        assert_eq!(
            Piconero(100).checked_sub(Piconero(40)).unwrap(),
            Piconero(60)
        );
        assert!(Piconero(10).checked_sub(Piconero(11)).is_err());

        assert_eq!(Piconero(i64::MAX as u64).to_i64().unwrap(), i64::MAX);
        assert!(Piconero((i64::MAX as u64) + 1).to_i64().is_err());
        assert!(Piconero::from_i64(-1).is_err());
        assert_eq!(Piconero::from_i64(0).unwrap(), Piconero::ZERO);
    }
}
