/// Structure representing the estimated effort for a given pattern.
pub struct PatternEstimate {
    pub attempts_needed: f64,
    pub time_at_min: f64,
    pub time_at_max: f64,
    pub has_invalid_chars: bool,
    pub invalid_chars: Vec<char>,
}

/// Checks if a character is valid in the Base58 alphabet
pub fn is_base58_char(c: char) -> bool {
    // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    // Excluded: 0 (zero), O (uppercase o), I (uppercase i), l (lowercase L)
    match c {
        '0' | 'O' | 'I' | 'l' => false,
        '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z' => true,
        _ => false,
    }
}

/// Estimates the number of attempts and time required to find an address matching the given pattern.
///
/// # Parameters
/// - `pattern`: The address pattern to search for.
/// - `is_start`: If true, the pattern is assumed to match at the beginning (after the initial character).
///
/// # Returns
/// A `PatternEstimate` with the adjusted number of attempts needed and time estimates at two speeds.
pub fn estimate_pattern(pattern: &str, is_start: bool) -> PatternEstimate {
    // Check for invalid Base58 characters
    let mut invalid_chars = Vec::new();
    for c in pattern.chars() {
        if !is_base58_char(c) && !invalid_chars.contains(&c) {
            invalid_chars.push(c);
        }
    }

    let has_invalid_chars = !invalid_chars.is_empty();

    // If there are invalid characters, the pattern is impossible to find
    if has_invalid_chars {
        return PatternEstimate {
            attempts_needed: f64::INFINITY,
            time_at_min: f64::INFINITY,
            time_at_max: f64::INFINITY,
            has_invalid_chars,
            invalid_chars,
        };
    }

    let pattern_length = pattern.len() as f64;

    // Calculate the base number of attempts based on the matching location.
    let attempts = if is_start {
        // For start patterns: second character must be one of [e,f,g,h,i] (5 possibilities)
        // followed by characters from a Base58 alphabet (58 possibilities each).
        5.0 * 58.0f64.powf(pattern_length - 1.0)
    } else {
        // For end/anywhere patterns:
        // Each character has 58 possibilities and there are multiple starting positions
        // in an average ~40-character address.
        let avg_addr_length = 40.0;
        let positions = avg_addr_length - pattern_length + 1.0;
        58.0f64.powf(pattern_length) / positions
    };

    // Apply a 20% safety margin.
    let adjusted_attempts = attempts * 1.2;

    // Use conservative speeds (addresses per second) for time estimates.
    let min_speed = 6_000.0;
    let max_speed = 12_000.0;

    PatternEstimate {
        attempts_needed: adjusted_attempts,
        time_at_min: adjusted_attempts / min_speed,
        time_at_max: adjusted_attempts / max_speed,
        has_invalid_chars: false,
        invalid_chars: Vec::new(),
    }
}

/// Converts a duration in seconds into a human-readable string.
pub fn format_time(seconds: f64) -> String {
    if seconds.is_infinite() {
        "impossible - pattern contains invalid characters".to_string()
    } else if seconds < 1.0 {
        "less than a second".to_string()
    } else if seconds < 60.0 {
        format!("{:.1} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else {
        format!("{:.1} days", seconds / 86400.0)
    }
}

/// Prints the estimated number of attempts and time required to find a matching address.
///
/// This displays the pattern, the estimated attempts needed, and the time estimates for two different speeds.
pub fn print_estimate(pattern: &str, is_start: bool) {
    let estimate = estimate_pattern(pattern, is_start);

    println!("\nPattern: \"{}\"", pattern);

    if estimate.has_invalid_chars {
        println!("WARNING: Pattern contains invalid Base58 characters:");
        println!("  Invalid characters: {}", estimate.invalid_chars.iter().collect::<String>());
        println!("  Valid characters: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
        println!("  This pattern is IMPOSSIBLE to find in a valid Ergo address.");
    } else {
        println!("Estimated attempts needed: {:.0}", estimate.attempts_needed);
        println!("Estimated time to find:");
        println!("  At 6,000 addr/s: {}", format_time(estimate.time_at_min));
        println!("  At 12,000 addr/s: {}", format_time(estimate.time_at_max));
    }
}

/// Wrapper function that prints the estimate and difficulty header
///
/// This is a convenience function called from main.rs
pub fn estimate_and_print(pattern: &str, is_start: bool) {
    // Print header only for the first pattern
    static HEADER_PRINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !HEADER_PRINTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        println!("Difficulty Estimation");
        println!("====================");
    }

    print_estimate(pattern, is_start);
}
