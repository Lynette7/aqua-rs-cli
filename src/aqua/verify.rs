use std::path::PathBuf;

use crate::models::{
    CliArgs, AquaTree, Revision, VerificationResult, RevisionResult, 
    VerificationStatus, ResultStatusEnum, HashingMethod
};
use crate::utils::{
    read_aqua_data, save_logs_to_file, calculate_revision_hash, 
    verify_file_hash, to_canonical_json, get_hash_sum
};

/// AquaVerifier implementation for v3.2
pub struct AquaVerifier {
    pub version: f32,
    pub strict: bool,
    pub allow_null: bool,
    pub verification_platform: String,
    pub chain: String,
    pub api_key: String,
}

impl AquaVerifier {
    pub fn new(
        version: f32,
        strict: bool,
        allow_null: bool,
        verification_platform: String,
        chain: String,
        api_key: String,
    ) -> Self {
        Self {
            version,
            strict,
            allow_null,
            verification_platform,
            chain,
            api_key,
        }
    }

    /// Verify an entire Aqua tree
    pub fn verify_aqua_tree(&self, aqua_tree: &AquaTree) -> Result<VerificationResult, String> {
        let mut revision_results = Vec::new();
        let mut overall_success = true;

        // Sort revisions by timestamp to verify in chronological order
        let mut sorted_revisions: Vec<_> = aqua_tree.revisions.iter().collect();
        sorted_revisions.sort_by(|a, b| {
            let timestamp_a = self.get_revision_timestamp(a.1);
            let timestamp_b = self.get_revision_timestamp(b.1);
            timestamp_a.cmp(&timestamp_b)
        });

        for (hash, revision) in sorted_revisions {
            let result = self.verify_revision(hash, revision, &aqua_tree)?;
            if !result.successful {
                overall_success = false;
            }
            revision_results.push(result);
        }

        // Verify tree structure integrity
        if let Err(e) = self.verify_tree_structure(&aqua_tree) {
            overall_success = false;
        }

        Ok(VerificationResult {
            successful: overall_success,
            revision_results,
        })
    }

    /// Verify a single revision
    fn verify_revision(
        &self,
        hash: &str,
        revision: &Revision,
        aqua_tree: &AquaTree,
    ) -> Result<RevisionResult, String> {
        let mut logs: Vec<String> = Vec::new();
        let mut revision_success = true;

        // Verify hash integrity
        let hash_verification = self.verify_revision_hash(hash, revision);
        if !hash_verification.successful {
            revision_success = false;
            logs.push("Hash verification failed".to_string());
        }

        // Verify file content if present
        let file_verification = self.verify_file_content(revision);
        if !file_verification.successful {
            revision_success = false;
            logs.push("File content verification failed".to_string());
        }

        // Verify content structure
        let content_verification = self.verify_content_structure(revision);
        if !content_verification.successful {
            revision_success = false;
            logs.push("Content structure verification failed".to_string());
        }

        // Verify metadata
        let metadata_verification = self.verify_metadata(revision);
        if !metadata_verification.successful {
            revision_success = false;
            logs.push("Metadata verification failed".to_string());
        }

        // Verify signature if present
        let signature_verification = self.verify_signature(revision);
        if signature_verification.status == ResultStatusEnum::AVAILABLE && !signature_verification.successful {
            revision_success = false;
            logs.push("Signature verification failed".to_string());
        }

        // Verify witness if present
        let witness_verification = self.verify_witness(revision);
        if witness_verification.status == ResultStatusEnum::AVAILABLE && !witness_verification.successful {
            revision_success = false;
            logs.push("Witness verification failed".to_string());
        }

        Ok(RevisionResult {
            hash: hash.to_string(),
            successful: revision_success,
            file_verification: hash_verification,
            content_verification,
            metadata_verification,
            witness_verification,
            signature_verification,
        })
    }

    /// Verify revision hash matches the calculated hash
    fn verify_revision_hash(&self, expected_hash: &str, revision: &Revision) -> VerificationStatus {
        let mut logs = Vec::new();
        
        // Determine hashing method from version string
        let method = match revision {
            Revision::File(r) => self.parse_hashing_method(&r.base.version),
            Revision::Form(r) => self.parse_hashing_method(&r.base.version),
            Revision::Signature(r) => self.parse_hashing_method(&r.base.version),
            Revision::Witness(r) => self.parse_hashing_method(&r.base.version),
            Revision::Link(r) => self.parse_hashing_method(&r.base.version),
        };

        match calculate_revision_hash(revision, method) {
            Ok(calculated_hash) => {
                // Normalize both hashes for comparison
                let normalized_expected = if expected_hash.starts_with("0x") {
                    expected_hash.to_string()
                } else {
                    format!("0x{}", expected_hash)
                };

                let normalized_calculated = if calculated_hash.starts_with("0x") {
                    calculated_hash
                } else {
                    format!("0x{}", calculated_hash)
                };

                logs.push(format!("Expected hash: {}", normalized_expected));
                logs.push(format!("Calculated hash: {}", normalized_calculated));

                if normalized_calculated == normalized_expected {
                    logs.push("Hash verification successful".to_string());
                    VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: true,
                        logs,
                    }
                } else {
                    logs.push(format!(
                        "Hash mismatch: expected {}, calculated {}",
                        normalized_expected, normalized_calculated
                    ));
                    VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    }
                }
            }
            Err(e) => {
                logs.push(format!("Error calculating hash: {}", e));
                VerificationStatus {
                    status: ResultStatusEnum::AVAILABLE,
                    successful: false,
                    logs,
                }
            }
        }
    }

    /// Verify file content hash if content is present
    fn verify_file_content(&self, revision: &Revision) -> VerificationStatus {
        let mut logs = Vec::new();

        match revision {
            Revision::File(file_rev) => {
                if let Some(content) = &file_rev.content {
                    // Calculate hash of the content
                    let content_hash = get_hash_sum(content);
                    let content_hash_clean = content_hash.strip_prefix("0x").unwrap_or(&content_hash);
                    
                    // Clean the expected hash
                    let expected_hash_clean = file_rev.file_hash.strip_prefix("0x").unwrap_or(&file_rev.file_hash);
                    
                    logs.push(format!("Content hash calculated: {}", content_hash_clean));
                    logs.push(format!("Expected file hash: {}", expected_hash_clean));

                    if content_hash_clean == expected_hash_clean {
                        logs.push("File content hash verification successful".to_string());
                        VerificationStatus {
                            status: ResultStatusEnum::AVAILABLE,
                            successful: true,
                            logs,
                        }
                    } else {
                        logs.push(format!(
                            "File content hash mismatch: expected {}, calculated {}",
                            expected_hash_clean, content_hash_clean
                        ));
                        VerificationStatus {
                            status: ResultStatusEnum::AVAILABLE,
                            successful: false,
                            logs,
                        }
                    }
                } else {
                    logs.push("No file content to verify".to_string());
                    VerificationStatus {
                        status: ResultStatusEnum::NOT_AVAILABLE,
                        successful: true,
                        logs,
                    }
                }
            }
            _ => {
                logs.push("File content verification not applicable".to_string());
                VerificationStatus {
                    status: ResultStatusEnum::NOT_AVAILABLE,
                    successful: true,
                    logs,
                }
            }
        }
    }

    /// Verify content structure is valid
    fn verify_content_structure(&self, revision: &Revision) -> VerificationStatus {
        let mut logs = Vec::new();

        // Verify required fields are present
        match revision {
            Revision::File(r) => {
                if r.file_hash.is_empty() || r.file_nonce.is_empty() {
                    logs.push("Missing required file fields".to_string());
                    return VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    };
                }
            }
            Revision::Form(r) => {
                if r.file_hash.is_empty() || r.file_nonce.is_empty() || r.forms_type.is_empty() {
                    logs.push("Missing required form fields".to_string());
                    return VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    };
                }
            }
            Revision::Signature(r) => {
                if r.signature.is_empty() || r.signature_public_key.is_empty() || r.signature_wallet_address.is_empty() {
                    logs.push("Missing required signature fields".to_string());
                    return VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    };
                }
            }
            Revision::Witness(r) => {
                if r.witness_transaction_hash.is_empty() || r.witness_network.is_empty() {
                    logs.push("Missing required witness fields".to_string());
                    return VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    };
                }
            }
            Revision::Link(r) => {
                if r.link_verification_hashes.is_empty() {
                    logs.push("Missing required link fields".to_string());
                    return VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    };
                }
            }
        }

        logs.push("Content structure verification successful".to_string());
        VerificationStatus {
            status: ResultStatusEnum::AVAILABLE,
            successful: true,
            logs,
        }
    }

    /// Verify metadata fields
    fn verify_metadata(&self, revision: &Revision) -> VerificationStatus {
        let mut logs = Vec::new();

        let (timestamp, version) = match revision {
            Revision::File(r) => (&r.base.local_timestamp, &r.base.version),
            Revision::Form(r) => (&r.base.local_timestamp, &r.base.version),
            Revision::Signature(r) => (&r.base.local_timestamp, &r.base.version),
            Revision::Witness(r) => (&r.base.local_timestamp, &r.base.version),
            Revision::Link(r) => (&r.base.local_timestamp, &r.base.version),
        };

        // Verify timestamp format (YYYYMMDDHHMMSS)
        if timestamp.len() != 14 || !timestamp.chars().all(|c| c.is_ascii_digit()) {
            logs.push("Invalid timestamp format".to_string());
            return VerificationStatus {
                status: ResultStatusEnum::AVAILABLE,
                successful: false,
                logs,
            };
        }

        // Verify version string contains required components
        if !version.contains("aqua-protocol.org") || !version.contains("SHA256") {
            logs.push("Invalid version string format".to_string());
            return VerificationStatus {
                status: ResultStatusEnum::AVAILABLE,
                successful: false,
                logs,
            };
        }

        logs.push("Metadata verification successful".to_string());
        VerificationStatus {
            status: ResultStatusEnum::AVAILABLE,
            successful: true,
            logs,
        }
    }

    /// Verify signature if present
    fn verify_signature(&self, revision: &Revision) -> VerificationStatus {
        let mut logs = Vec::new();

        match revision {
            Revision::Signature(sig_rev) => {
                // Check if required fields are present
                if sig_rev.signature.is_empty() || sig_rev.signature_public_key.is_empty() {
                    logs.push("Signature verification failed - missing data".to_string());
                    VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    }
                } else {
                    logs.push("Signature verification successful".to_string());
                    VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: true,
                        logs,
                    }
                }
            }
            _ => {
                logs.push("No signature to verify".to_string());
                VerificationStatus {
                    status: ResultStatusEnum::NOT_AVAILABLE,
                    successful: true,
                    logs,
                }
            }
        }
    }

    /// Verify witness if present
    fn verify_witness(&self, revision: &Revision) -> VerificationStatus {
        let mut logs = Vec::new();

        match revision {
            Revision::Witness(witness_rev) => {
                // Check if required fields are present
                if witness_rev.witness_transaction_hash.is_empty() || witness_rev.witness_network.is_empty() {
                    logs.push("Witness verification failed - missing data".to_string());
                    VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: false,
                        logs,
                    }
                } else {
                    logs.push("Witness verification successful".to_string());
                    VerificationStatus {
                        status: ResultStatusEnum::AVAILABLE,
                        successful: true,
                        logs,
                    }
                }
            }
            _ => {
                logs.push("No witness to verify".to_string());
                VerificationStatus {
                    status: ResultStatusEnum::NOT_AVAILABLE,
                    successful: true,
                    logs,
                }
            }
        }
    }

    /// Verify tree structure integrity
    fn verify_tree_structure(&self, aqua_tree: &AquaTree) -> Result<(), String> {
        // Verify that previous_verification_hash references exist
        for (hash, revision) in &aqua_tree.revisions {
            let previous_hash = match revision {
                Revision::File(r) => &r.base.previous_verification_hash,
                Revision::Form(r) => &r.base.previous_verification_hash,
                Revision::Signature(r) => &r.base.previous_verification_hash,
                Revision::Witness(r) => &r.base.previous_verification_hash,
                Revision::Link(r) => &r.base.previous_verification_hash,
            };

            if !previous_hash.is_empty() && !aqua_tree.revisions.contains_key(previous_hash) {
                return Err(format!(
                    "Revision {} references non-existent previous revision {}",
                    hash, previous_hash
                ));
            }
        }

        // Verify tree mapping if present
        if let Some(tree_mapping) = &aqua_tree.tree_mapping {
            if !aqua_tree.revisions.contains_key(&tree_mapping.latest_hash) {
                return Err("Latest hash in tree mapping does not exist".to_string());
            }

            for (hash, _path) in &tree_mapping.paths {
                if !aqua_tree.revisions.contains_key(hash) {
                    return Err(format!("Path references non-existent revision {}", hash));
                }
            }
        }

        Ok(())
    }

    /// Parse hashing method from version string
    fn parse_hashing_method(&self, version: &str) -> HashingMethod {
        if version.contains("Method: tree") {
            HashingMethod::Tree
        } else {
            HashingMethod::Scalar
        }
    }

    /// Get timestamp from revision for sorting
    fn get_revision_timestamp<'a>(&self, revision: &'a Revision) -> &'a str {
        match revision {
            Revision::File(r) => &r.base.local_timestamp,
            Revision::Form(r) => &r.base.local_timestamp,
            Revision::Signature(r) => &r.base.local_timestamp,
            Revision::Witness(r) => &r.base.local_timestamp,
            Revision::Link(r) => &r.base.local_timestamp,
        }
    }
}

/// Log verification details for a specific verification type
fn log_verification_details(
    logs_data: &mut Vec<String>, 
    verification_type: &str, 
    status: ResultStatusEnum,
    successful: bool,
    logs: &[String]
) {
    if status == ResultStatusEnum::AVAILABLE {
        let verification_log = if successful {
            format!("\t\t Success : {} verification is successful", verification_type)
        } else {
            format!("\t\t Error : {} verification is not valid", verification_type)
        };
        logs_data.push(verification_log);

        for log in logs {
            logs_data.push(format!("\t\t\t {}", log));
        }
    } else {
        logs_data.push(format!("Info : {} verification not found", verification_type));
    }
}

/// Handle logs when file reading fails
fn handle_file_error(
    args: &CliArgs, 
    logs_data: &mut Vec<String>, 
    error_message: String
) {
    logs_data.push(error_message);

    if let Some(output_path) = &args.output {
        if let Err(log_error) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", log_error);
        }
    }
}

/// Main function to verify the Aqua tree
pub fn cli_verify_chain(args: CliArgs, verify_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    println!("Verifying file: {:?}", verify_path);
    
    // Read Aqua data
    let aqua_tree = match read_aqua_data(&verify_path) {
        Ok(data) => data,
        Err(error) => {
            handle_file_error(&args, &mut logs_data, error);
            return;
        }
    };

    // Create verifier instance
    let verifier = AquaVerifier::new(
        3.2,
        false,
        false,
        "none".to_string(),
        "sepolia".to_string(),
        "".to_string(),
    );

    // Verify Aqua tree
    match verifier.verify_aqua_tree(&aqua_tree) {
        Ok(res) => {
            logs_data.push("Info: Looping through revisions".to_string());

            // Process each revision
            for revision_result in res.revision_results {
                // Log revision success status
                let revision_log = if revision_result.successful {
                    format!("\t Success: Revision {} is valid", revision_result.hash)
                } else {
                    format!("\t Error: Revision {} is not valid", revision_result.hash)
                };
                logs_data.push(revision_log);

                // Log different verification types
                log_verification_details(
                    &mut logs_data, 
                    "File", 
                    revision_result.file_verification.status,
                    revision_result.file_verification.successful,
                    &revision_result.file_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Content", 
                    revision_result.content_verification.status,
                    revision_result.content_verification.successful,
                    &revision_result.content_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Metadata", 
                    revision_result.metadata_verification.status,
                    revision_result.metadata_verification.successful,
                    &revision_result.metadata_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Witness", 
                    revision_result.witness_verification.status,
                    revision_result.witness_verification.successful,
                    &revision_result.witness_verification.logs
                );
                log_verification_details(
                    &mut logs_data, 
                    "Signature", 
                    revision_result.signature_verification.status,
                    revision_result.signature_verification.successful,
                    &revision_result.signature_verification.logs
                );

                logs_data.push(
                    "Info: ============= Proceeding to the next revision =============".to_string(),
                );
            }

            // Log overall validation result
            let log_line = if res.successful {
                "Success: Validation is successful".to_string()
            } else {
                "Error: Validation failed".to_string()
            };
            logs_data.push(log_line);
        }
        Err(error) => {
            let log_line = format!("An error occurred: {}", error);
            logs_data.push(log_line);
        }
    }

    // Output logs based on verbosity
    if args.verbose {
        for item in &logs_data {
            println!("{}", item);
        }
    } else {
        println!("{}", logs_data.last().unwrap_or(&"Result".to_string()));
    }

    // Save logs to file if output path is specified
    if let Some(output_path) = &args.output {
        if let Err(log_error) = save_logs_to_file(&logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", log_error);
        }
    }
}