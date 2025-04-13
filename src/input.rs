use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

// Represents an input source that can be a single value or a file with multiple values
#[derive(Clone, Debug)]
pub enum InputSource {
    Single(String),
    File(PathBuf),
}

impl InputSource {
    // Create a new InputSource from a string, detecting if it's a file path or a direct value
    pub fn new(input: &str) -> Self {
        // Check if input is a file path that exists
        if let Ok(metadata) = std::fs::metadata(input) {
            if metadata.is_file() {
                return Self::File(PathBuf::from(input));
            }
            if metadata.is_dir() {
                println!("[!]: {input} is a directory, not a file.");
                std::process::exit(1);
            }
        }

        // Not a file path, treat as a single value
        Self::Single(input.to_string())
    }

    // Load all values from this input source
    pub fn load_values(&self) -> io::Result<Vec<String>> {
        match self {
            Self::Single(value) => Ok(vec![value.clone()]),
            Self::File(path) => read_values_from_file(path),
        }
    }

    // Returns true if this is a file source
    #[allow(dead_code)]
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }

    // Returns the raw value if this is a single value
    #[allow(dead_code)]
    pub fn single_value(&self) -> Option<&str> {
        match self {
            Self::Single(value) => Some(value),
            Self::File(_) => None,
        }
    }
}

// Read values from a file, skipping empty lines and comments
pub fn read_values_from_file(path: &PathBuf) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut values = Vec::new();

    for line in reader.lines() {
        let value = line?;
        let trimmed = value.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            values.push(trimmed.to_string());
        }
    }

    Ok(values)
}
