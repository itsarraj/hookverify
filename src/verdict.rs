use std::fmt;

/// The outcome of a verification. Deliberately **not** a `bool`: the
/// three failure modes mean different things to whoever is reading the
/// output. "Your header is garbled" is a bug in your own plumbing,
/// "signature doesn't match" is a wrong secret or a tampered body, and
/// "signature matches but the timestamp is old" is a replay — a case
/// that a naive verifier reports as a clean success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Signature matched (and, for Stripe, the timestamp is inside the
    /// tolerance window).
    Valid,
    /// Well-formed signature that does not match the one we computed:
    /// wrong secret, or a body that changed after it was signed.
    Mismatch,
    /// The signature header could not be parsed at all. Reported apart
    /// from `Mismatch` on purpose — a typo'd header name or a
    /// double-JSON-encoded body should not look like an attack.
    Malformed(String),
    /// Stripe mode only: the HMAC is correct, but `t` is outside the
    /// tolerance window, so this is (or could be) a replay of a signature
    /// that was genuine once. `age_secs` is positive for a timestamp in
    /// the past, negative for one in the future (clock skew).
    StaleTimestamp { age_secs: i64, tolerance_secs: u64 },
}

impl Verdict {
    pub fn is_valid(&self) -> bool {
        matches!(self, Verdict::Valid)
    }

    /// Exit code for the CLI. A script that only checks `== 0` still gets
    /// the safe answer; one that wants to distinguish "my plumbing is
    /// broken" (2) from "replay attempt" (3) from "bad signature" (1) can.
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Valid => 0,
            Verdict::Mismatch => 1,
            Verdict::Malformed(_) => 2,
            Verdict::StaleTimestamp { .. } => 3,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Valid => write!(f, "VALID"),
            Verdict::Mismatch => write!(f, "INVALID — signature does not match"),
            Verdict::Malformed(why) => write!(f, "MALFORMED — {why}"),
            Verdict::StaleTimestamp {
                age_secs,
                tolerance_secs,
            } => {
                if *age_secs < 0 {
                    write!(
                        f,
                        "REJECTED — signature is correct but its timestamp is {}s in the future (tolerance {tolerance_secs}s); clock skew or a forged timestamp",
                        -age_secs
                    )
                } else {
                    write!(
                        f,
                        "REJECTED — signature is correct but {age_secs}s old (tolerance {tolerance_secs}s); treat as a replay"
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct_per_failure_mode() {
        assert_eq!(Verdict::Valid.exit_code(), 0);
        assert_eq!(Verdict::Mismatch.exit_code(), 1);
        assert_eq!(Verdict::Malformed("x".into()).exit_code(), 2);
        assert_eq!(
            Verdict::StaleTimestamp {
                age_secs: 900,
                tolerance_secs: 300
            }
            .exit_code(),
            3
        );
    }

    #[test]
    fn only_valid_is_valid() {
        assert!(Verdict::Valid.is_valid());
        assert!(!Verdict::Mismatch.is_valid());
        assert!(!Verdict::Malformed("x".into()).is_valid());
        // The one that matters: a correctly-signed but replayed webhook
        // must never read as valid.
        assert!(!Verdict::StaleTimestamp {
            age_secs: 900,
            tolerance_secs: 300
        }
        .is_valid());
    }
}
