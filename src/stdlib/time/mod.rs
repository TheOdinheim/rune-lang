// ═══════════════════════════════════════════════════════════════════════
// rune::time — Timestamps and Durations
//
// Clock-reading functions (now_*) require the `io` effect — reading the
// system clock is an observable side effect.
// Duration utilities are pure computation (no effect required).
// ═══════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants ───────────────────────────────────────────────────────

pub const MS_PER_SECOND: i64 = 1_000;
pub const MS_PER_MINUTE: i64 = 60_000;
pub const MS_PER_HOUR: i64 = 3_600_000;
pub const MS_PER_DAY: i64 = 86_400_000;

// ── Effect documentation ────────────────────────────────────────────

pub struct TimeEffects;

impl TimeEffects {
    pub const CLOCK: &'static str = "io";
}

// ── Timestamp functions (effect: io) ────────────────────────────────

/// Current time as Unix timestamp in milliseconds. Effect: io.
pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Current time as Unix timestamp in seconds. Effect: io.
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Milliseconds elapsed since a start timestamp. Pure computation.
pub fn elapsed_ms(start: i64) -> i64 {
    now_unix_ms() - start
}

// ── Duration utilities (pure — no effects) ──────────────────────────

/// Convert milliseconds to seconds as float.
pub fn duration_secs(ms: i64) -> f64 {
    ms as f64 / 1000.0
}

/// Format duration as human-readable string.
pub fn duration_human(ms: i64) -> String {
    if ms < 0 {
        return format!("-{}", duration_human(-ms));
    }
    if ms < MS_PER_SECOND {
        return format!("{ms}ms");
    }
    if ms < MS_PER_MINUTE {
        let s = ms as f64 / 1000.0;
        return if ms % MS_PER_SECOND == 0 {
            format!("{}s", ms / MS_PER_SECOND)
        } else {
            format!("{s:.1}s")
        };
    }
    let minutes = ms / MS_PER_MINUTE;
    let remaining_secs = (ms % MS_PER_MINUTE) / MS_PER_SECOND;
    if remaining_secs == 0 {
        format!("{minutes}m")
    } else {
        format!("{minutes}m {remaining_secs}s")
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_unix_ms_positive() {
        assert!(now_unix_ms() > 0);
    }

    #[test]
    fn test_now_unix_secs_positive() {
        assert!(now_unix_secs() > 0);
    }

    #[test]
    fn test_ms_and_secs_consistent() {
        let ms = now_unix_ms();
        let secs = now_unix_secs();
        // ms should be within 1 second of secs * 1000
        assert!((ms - secs * 1000).abs() < 1000);
    }

    #[test]
    fn test_elapsed_ms_non_negative() {
        let start = now_unix_ms();
        let elapsed = elapsed_ms(start);
        assert!(elapsed >= 0);
    }

    #[test]
    fn test_duration_secs_conversion() {
        assert!((duration_secs(1000) - 1.0).abs() < f64::EPSILON);
        assert!((duration_secs(1500) - 1.5).abs() < f64::EPSILON);
        assert!((duration_secs(500) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_duration_human_millis() {
        assert_eq!(duration_human(250), "250ms");
        assert_eq!(duration_human(0), "0ms");
    }

    #[test]
    fn test_duration_human_seconds() {
        assert_eq!(duration_human(1500), "1.5s");
        assert_eq!(duration_human(2000), "2s");
    }

    #[test]
    fn test_duration_human_minutes() {
        assert_eq!(duration_human(150_000), "2m 30s");
        assert_eq!(duration_human(60_000), "1m");
    }

    #[test]
    fn test_time_constants() {
        assert_eq!(MS_PER_SECOND, 1_000);
        assert_eq!(MS_PER_MINUTE, 60_000);
        assert_eq!(MS_PER_HOUR, 3_600_000);
        assert_eq!(MS_PER_DAY, 86_400_000);
    }
}
