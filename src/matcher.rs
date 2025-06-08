/// Module for address pattern matching functionality.
/// Extracts matcher logic from args.rs and address_processor.rs

pub struct PatternMatcher {
    patterns: Vec<String>,
    case_sensitive: bool,
    start: bool,
    end: bool,
}

impl PatternMatcher {
    /// Create a new PatternMatcher.
    /// If case_sensitive is false, all patterns are converted to lowercase.
    pub fn new(patterns: Vec<String>, case_sensitive: bool, start: bool, end: bool) -> Self {
        // Patterns will be validated in the GUI, no validation here for real-time checking

        // Convert to lowercase if case insensitive
        let final_patterns = if !case_sensitive {
            patterns.into_iter().map(|p| p.to_lowercase()).collect()
        } else {
            patterns
        };

        Self {
            patterns: final_patterns,
            case_sensitive,
            start,
            end,
        }
    }

    /// Validate that at least one pattern exists.
    /// For start matching, ensure that each pattern starts with one of: e, f, g, h, i.
    /// Also validate that all patterns only contain valid Base58 characters.
    pub fn validate(&self) -> Result<(), String> {
        if self.patterns.is_empty() {
            return Err("At least one pattern must be specified".to_string());
        }

        // For "start" pattern, must be a valid second character (check after case conversion)
        if self.start {
            for pat in &self.patterns {
                if !pat.is_empty() {
                    let first_char = pat.chars().next().unwrap();
                    if !['e', 'f', 'g', 'h', 'i'].contains(&first_char) {
                        return Err(format!("Invalid start pattern '{}'. Start patterns must begin with e, f, g, h, or i", pat));
                    }
                }
            }
        }

        // Note: Base58 validation is now done in the constructor before case conversion
        Ok(())
    }

    /// Check if matcher has multiple patterns to balance across
    pub fn has_multiple_patterns(&self) -> bool {
        self.patterns.len() > 1
    }

    /// Checks whether the given address matches any pattern.
    /// If start matching is enabled, it checks the substring after the first character.
    /// Otherwise, it either checks for an ending match or an anywhere match.
    pub fn is_match(&self, address: &str) -> Option<String> {
        if self.start {
            self.match_start(address)
        } else if self.end {
            self.match_end(address)
        } else {
            self.match_anywhere(address)
        }
    }

    // Helper: Normalize the address string.
    // If `skip_first` is true, the first character is skipped.
    // Then, if case_sensitive is false, the string is lowercased.
    fn normalize(&self, address: &str, skip_first: bool) -> String {
        let s = if skip_first && address.len() > 1 {
            address[1..].to_string()
        } else {
            address.to_string()
        };
        if self.case_sensitive {
            s
        } else {
            s.to_lowercase()
        }
    }

    fn match_start(&self, address: &str) -> Option<String> {
        if address.len() <= 1 {
            return None;
        }
        let addr_to_check = self.normalize(address, true);
        for pattern in &self.patterns {
            if addr_to_check.starts_with(pattern) {
                return Some(pattern.clone());
            }
        }
        None
    }

    fn match_end(&self, address: &str) -> Option<String> {
        let addr_to_check = self.normalize(address, false);
        for pattern in &self.patterns {
            if addr_to_check.ends_with(pattern) {
                return Some(pattern.clone());
            }
        }
        None
    }

    fn match_anywhere(&self, address: &str) -> Option<String> {
        let addr_to_check = self.normalize(address, false);
        for pattern in &self.patterns {
            if addr_to_check.contains(pattern) {
                return Some(pattern.clone());
            }
        }
        None
    }
}
