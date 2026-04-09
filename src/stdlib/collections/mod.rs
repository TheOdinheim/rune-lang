// ═══════════════════════════════════════════════════════════════════════
// rune::collections — Collection Utilities
//
// Pure functions (no effects required). These operate on in-memory data
// and perform no I/O. Policy modules use these for data processing.
// ═══════════════════════════════════════════════════════════════════════

// ── Sorting ─────────────────────────────────────────────────────────

/// Sort integers in ascending order.
pub fn sort_i64(items: &mut Vec<i64>) {
    items.sort();
}

/// Sort strings alphabetically.
pub fn sort_strings(items: &mut Vec<String>) {
    items.sort();
}

// ── Deduplication ───────────────────────────────────────────────────

/// Remove duplicate integers, preserving first occurrence order.
pub fn unique_i64(items: &[i64]) -> Vec<i64> {
    let mut seen = std::collections::HashSet::new();
    items
        .iter()
        .filter(|x| seen.insert(**x))
        .copied()
        .collect()
}

/// Remove duplicate strings, preserving first occurrence order.
pub fn unique_strings(items: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .iter()
        .filter(|x| seen.insert(x.clone()))
        .cloned()
        .collect()
}

// ── Membership ──────────────────────────────────────────────────────

/// Check if value is present in the slice.
pub fn contains_i64(items: &[i64], value: i64) -> bool {
    items.contains(&value)
}

/// Check if value is present in the slice.
pub fn contains_string(items: &[String], value: &str) -> bool {
    items.iter().any(|s| s == value)
}

// ── Aggregation ─────────────────────────────────────────────────────

/// Minimum value, or None if empty.
pub fn min_i64(items: &[i64]) -> Option<i64> {
    items.iter().copied().min()
}

/// Maximum value, or None if empty.
pub fn max_i64(items: &[i64]) -> Option<i64> {
    items.iter().copied().max()
}

/// Sum of all values. Returns 0 for empty input.
pub fn sum_i64(items: &[i64]) -> i64 {
    items.iter().sum()
}

/// Arithmetic mean. Returns 0.0 for empty input.
pub fn avg_i64(items: &[i64]) -> f64 {
    if items.is_empty() {
        return 0.0;
    }
    sum_i64(items) as f64 / items.len() as f64
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_i64() {
        let mut v = vec![3, 1, 4, 1, 5];
        sort_i64(&mut v);
        assert_eq!(v, vec![1, 1, 3, 4, 5]);
    }

    #[test]
    fn test_sort_strings() {
        let mut v = vec!["banana".into(), "apple".into(), "cherry".into()];
        sort_strings(&mut v);
        assert_eq!(v, vec!["apple", "banana", "cherry"]);
    }

    #[test]
    fn test_unique_i64() {
        let result = unique_i64(&[3, 1, 4, 1, 5, 3]);
        assert_eq!(result, vec![3, 1, 4, 5]);
    }

    #[test]
    fn test_unique_strings() {
        let items: Vec<String> = vec!["a".into(), "b".into(), "a".into(), "c".into()];
        let result = unique_strings(&items);
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_contains_i64_present() {
        assert!(contains_i64(&[1, 2, 3], 2));
    }

    #[test]
    fn test_contains_i64_absent() {
        assert!(!contains_i64(&[1, 2, 3], 4));
    }

    #[test]
    fn test_contains_string_present() {
        let items: Vec<String> = vec!["hello".into(), "world".into()];
        assert!(contains_string(&items, "hello"));
    }

    #[test]
    fn test_contains_string_absent() {
        let items: Vec<String> = vec!["hello".into()];
        assert!(!contains_string(&items, "world"));
    }

    #[test]
    fn test_min_max_i64() {
        let items = vec![5, 2, 8, 1, 9];
        assert_eq!(min_i64(&items), Some(1));
        assert_eq!(max_i64(&items), Some(9));
    }

    #[test]
    fn test_min_max_empty() {
        let empty: Vec<i64> = vec![];
        assert_eq!(min_i64(&empty), None);
        assert_eq!(max_i64(&empty), None);
    }

    #[test]
    fn test_sum_i64() {
        assert_eq!(sum_i64(&[1, 2, 3, 4, 5]), 15);
        assert_eq!(sum_i64(&[]), 0);
    }

    #[test]
    fn test_avg_i64() {
        assert!((avg_i64(&[2, 4, 6]) - 4.0).abs() < f64::EPSILON);
        assert!((avg_i64(&[]) - 0.0).abs() < f64::EPSILON);
    }
}
