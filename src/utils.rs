use std::{fs::{self, File, OpenOptions}, path::{Path, PathBuf}};
use std::io::Write;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use serde_json;

use crate::models::{
    AquaTree, SecreatKeys, Revision, FileRevision, BaseRevision, 
    HashingMethod, create_version_string, generate_timestamp, generate_nonce
};

pub fn save_logs_to_file(logs : &Vec<String>, output_file : PathBuf, ) -> Result<String, String> {


 // Open the file in append mode, create it if it doesn't exist
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_file)
    {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open log file: {}", e)),
    };

    // Write each log entry to the file, adding a newline after each one
    for log in logs {
        if let Err(e) = writeln!(file, "{}", log) {
            return Err(format!("Failed to write to log file: {}", e));
        }
    }

    Ok("Log written successfully".to_string())
}

/// Read Aqua data from file using the new v3.2 schema
pub fn read_aqua_data(path: &PathBuf) -> Result<AquaTree, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Error reading file: {}", e))?;
    
    serde_json::from_str::<AquaTree>(&data)
        .map_err(|e| format!("Error parsing JSON: {}", e))
}

/// Read secret keys from file
pub fn read_secret_keys(path: &PathBuf) -> Result<SecreatKeys, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Error reading keys file: {}", e))?;
    
    serde_json::from_str::<SecreatKeys>(&data)
        .map_err(|e| format!("Error parsing keys JSON: {}", e))
}

/// Save AquaTree data to file
pub fn save_aqua_tree(aqua_tree: &AquaTree, original_path: &Path, extension: String) -> Result<(), String> {
    let output_path = original_path.with_extension(extension);
    
    let json_data = serde_json::to_string_pretty(aqua_tree)
        .map_err(|e| format!("Error serializing AquaTree: {}", e))?;
    
    fs::write(&output_path, json_data)
        .map_err(|e| format!("Error writing file: {}", e))?;
    
    println!("Aqua tree data saved to: {:?}", output_path);
    Ok(())
}

/// Generate SHA256 hash of input string
pub fn get_hash_sum(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("0x{}", hex::encode(result))
}

/// Generate canonical JSON string for hashing
pub fn to_canonical_json<T: serde::Serialize>(data: &T) -> Result<String, String> {
    // First convert to JSON value
    let mut value = serde_json::to_value(data)
        .map_err(|e| format!("Error converting to JSON value: {}", e))?;
    
    // Remove any null fields and sort recursively
    let canonical = canonical_json_recursive(&value);
    
    // Create compact JSON string (no extra whitespace)
    serde_json::to_string(&canonical)
        .map_err(|e| format!("Error serializing canonical JSON: {}", e))
}

/// Recursively sort JSON object keys for canonical representation
fn canonical_json_recursive(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted_map = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            
            for key in keys {
                let processed_value = canonical_json_recursive(&map[key]);
                // Skip null values in canonical representation
                if !processed_value.is_null() {
                    sorted_map.insert(key.clone(), processed_value);
                }
            }
            serde_json::Value::Object(sorted_map)
        },
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(
                arr.iter()
                   .map(canonical_json_recursive)
                   .filter(|v| !v.is_null())
                   .collect()
            )
        },
        _ => value.clone(),
    }
}

/// Calculate revision hash using the specified method
pub fn calculate_revision_hash(revision: &Revision, method: HashingMethod) -> Result<String, String> {
    match method {
        HashingMethod::Scalar => {
            // Create a copy of the revision for hashing
            let canonical_json = to_canonical_json(revision)?;
            let hash = get_hash_sum(&canonical_json);
            Ok(hash)
        },
        HashingMethod::Tree => {
            let canonical_json = to_canonical_json(revision)?;
            let hash = get_hash_sum(&canonical_json);
            Ok(hash)
        }
    }
}

/// Generate a new file revision
pub fn create_file_revision(
    file_content: Vec<u8>,
    filename: String,
    previous_hash: String,
) -> Result<(String, FileRevision), String> {
    let file_hash = get_hash_sum(&hex::encode(&file_content));
    let file_nonce = generate_nonce();
    
    let revision = FileRevision {
        base: BaseRevision {
            previous_verification_hash: previous_hash,
            local_timestamp: generate_timestamp(),
            version: create_version_string(HashingMethod::Scalar),
        },
        file_hash: file_hash.trim_start_matches("0x").to_string(),
        file_nonce,
        content: Some(String::from_utf8_lossy(&file_content).to_string()),
    };
    
    let revision_enum = Revision::File(revision.clone());
    let hash = calculate_revision_hash(&revision_enum, HashingMethod::Scalar)?;
    
    Ok((hash, revision))
}

/// Verify file hash matches content
pub fn verify_file_hash(content: &str, expected_hash: &str) -> bool {
    let calculated_hash = get_hash_sum(content);
    let expected_with_prefix = if expected_hash.starts_with("0x") {
        expected_hash.to_string()
    } else {
        format!("0x{}", expected_hash)
    };
    
    calculated_hash == expected_with_prefix
}

/// Extract the latest revision from an AquaTree
pub fn get_latest_revision(aqua_tree: &AquaTree) -> Option<(String, &Revision)> {
    if let Some(tree_mapping) = &aqua_tree.tree_mapping {
        if let Some(revision) = aqua_tree.revisions.get(&tree_mapping.latest_hash) {
            return Some((tree_mapping.latest_hash.clone(), revision));
        }
    }
    
    // Find the revision with no children (leaf node)
    let mut has_children = std::collections::HashSet::new();
    for (_, revision) in &aqua_tree.revisions {
        let previous_hash = match revision {
            Revision::File(r) => &r.base.previous_verification_hash,
            Revision::Form(r) => &r.base.previous_verification_hash,
            Revision::Signature(r) => &r.base.previous_verification_hash,
            Revision::Witness(r) => &r.base.previous_verification_hash,
            Revision::Link(r) => &r.base.previous_verification_hash,
        };
        if !previous_hash.is_empty() {
            has_children.insert(previous_hash.clone());
        }
    }
    
    // Find revision that is not referenced as a previous hash
    for (hash, revision) in &aqua_tree.revisions {
        if !has_children.contains(hash) {
            return Some((hash.clone(), revision));
        }
    }
    
    None
}

/// Build tree mapping from revisions
pub fn build_tree_mapping(revisions: &HashMap<String, Revision>) -> crate::models::TreeMapping {
    let mut paths: HashMap<String, Vec<String>> = HashMap::new();
    let mut latest_hash = String::new();
    
    // Build paths for each revision
    for (hash, _) in revisions {
        let mut path = Vec::new();
        let mut current_hash = hash.clone();
        
        while let Some(revision) = revisions.get(&current_hash) {
            path.insert(0, current_hash.clone());
            
            let previous_hash = match revision {
                Revision::File(r) => &r.base.previous_verification_hash,
                Revision::Form(r) => &r.base.previous_verification_hash,
                Revision::Signature(r) => &r.base.previous_verification_hash,
                Revision::Witness(r) => &r.base.previous_verification_hash,
                Revision::Link(r) => &r.base.previous_verification_hash,
            };
            
            if previous_hash.is_empty() {
                break;
            }
            current_hash = previous_hash.clone();
        }
        
        if path.len() > latest_hash.len() {
            latest_hash = hash.clone();
        }
        
        paths.insert(hash.clone(), path);
    }
    
    crate::models::TreeMapping {
        paths,
        latest_hash,
    }
}

pub fn is_valid_json_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() && path.extension().unwrap_or_default() == "json" {
        Ok(s.to_string())
    } else {
        Err("Invalid JSON file path".to_string())
    }
}

pub fn is_valid_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() {
        Ok(s.to_string())
    } else {
        Err("Invalid file path".to_string())
    }
}

pub fn is_valid_output_file(s: &str) -> Result<String, String> {
    let lowercase = s.to_lowercase();
    if lowercase.ends_with(".json") || lowercase.ends_with(".html") || lowercase.ends_with(".pdf") {
        Ok(s.to_string())
    } else {
        Err("Output file must be .json, .html, or .pdf".to_string())
    }
}

pub fn string_to_bool(s: String) -> bool {
    match s.to_lowercase().as_str() {
        "true" => true,
        "yes" => true,
        "false" => false,
        "no" => false,
        _ => false
    }
}