use serde::{Deserialize, Serialize};
use std::fmt;

use crate::cli::EnumMode;

// Represents a single enumeration test target
#[derive(Clone)]
pub struct TestTarget {
    pub username: String,                // The raw username part without domain
    pub email: String,                   // The full email to test (might be just username for VRFY)
    pub has_domain: bool,                // Whether this target has a domain part
    pub original_domain: Option<String>, // The original domain if applicable
}

impl std::fmt::Debug for TestTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has_domain {
            write!(
                f,
                "{}@{}",
                self.username,
                self.original_domain.as_ref().unwrap_or(&String::new())
            )
        } else {
            write!(f, "{}", self.username)
        }
    }
}

impl TestTarget {
    // Create a new test target for a username without a domain
    pub fn new_user_only(username: String) -> Self {
        Self {
            email: username.clone(),
            username,
            has_domain: false,
            original_domain: None,
        }
    }

    // Create a new test target with a domain
    pub fn new_with_domain(username: String, domain: String) -> Self {
        let email = format!("{username}@{domain}");
        Self {
            username,
            email,
            has_domain: true,
            original_domain: Some(domain),
        }
    }

    // Get a formatted email for SMTP commands based on the current mode
    pub fn get_formatted_email(&self, mode: EnumMode, wrap: bool) -> String {
        // For VRFY mode, we might want to use just the username part
        let email = match mode {
            EnumMode::Vrfy if !self.email.contains('@') => self.username.clone(),
            _ => self.email.clone(),
        };

        if wrap { format!("<{email}>") } else { email }
    }
}

// Status of a tested user
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserStatus {
    Valid,
    Invalid,
    Unknown,
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "VALID"),
            Self::Invalid => write!(f, "INVALID"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// Custom serde module for UserStatus
pub mod user_status_serde {
    use super::UserStatus;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(status: &UserStatus, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&status.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<UserStatus, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "VALID" => Ok(UserStatus::Valid),
            "INVALID" => Ok(UserStatus::Invalid),
            _ => Ok(UserStatus::Unknown),
        }
    }
}

// Result of a user test
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestResult {
    pub username: String,
    pub email: String,
    #[serde(with = "user_status_serde")]
    pub status: UserStatus,
    pub reason: String,
    pub response_time: u128, // Store as milliseconds for serialization
    pub raw_response: String,
}

// Function to generate all test targets from usernames and domains
pub fn generate_test_targets(usernames: &[String], domains: &[String]) -> Vec<TestTarget> {
    let mut targets = Vec::new();

    if domains.is_empty() {
        // Just test the usernames as-is (no domain appended)
        for username in usernames {
            targets.push(TestTarget::new_user_only(username.clone()));
        }
    } else {
        // Generate combinations of usernames with domains
        for username in usernames {
            for domain in domains {
                let domain_clean = domain.trim_start_matches('@');
                targets.push(TestTarget::new_with_domain(
                    username.clone(),
                    domain_clean.to_string(),
                ));
            }
        }
    }

    targets
}

// Randomize the order of test targets (for evading pattern detection)
pub fn randomize_targets(targets: Vec<TestTarget>) -> Vec<TestTarget> {
    use std::collections::HashSet;

    if targets.is_empty() {
        return targets;
    }

    let mut shuffled = Vec::with_capacity(targets.len());
    let mut indices: HashSet<usize> = HashSet::new();

    // Use current timestamp as seed
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs();

    let mut current_seed = seed;

    while indices.len() < targets.len() {
        // Simple pseudo-random number generation
        current_seed = (current_seed * 1_103_515_245 + 12345) % 2_147_483_647;
        let index = current_seed as usize % targets.len();

        if indices.insert(index) {
            shuffled.push(targets[index].clone());
        }
    }

    shuffled
}
