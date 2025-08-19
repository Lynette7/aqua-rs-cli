use std::fs;
use std::collections::HashMap;

use crate::models::{
    CliArgs, AquaTree, Revision, FileRevision, BaseRevision, 
    HashingMethod, create_version_string, generate_timestamp, generate_nonce, TreeMapping
};
use crate::utils::{
    save_logs_to_file, save_aqua_tree, get_hash_sum, 
    calculate_revision_hash, build_tree_mapping
};

/// Result structure for Aqua chain generation
pub struct GenerationResult {
    pub aqua_tree: AquaTree,
    pub logs: Vec<String>,
}

/// Aqua chain generator implementation for v3.2
pub struct AquaGenerator {
    pub domain_id: String,
}

impl AquaGenerator {
    pub fn new(domain_id: String) -> Self {
        Self { domain_id }
    }

    /// Generate a new Aqua tree from file content
    pub fn generate_aqua_tree(
        &self,
        file_content: Vec<u8>,
        filename: String,
    ) -> Result<GenerationResult, Vec<String>> {
        let mut logs = Vec::new();
        logs.push("Starting Aqua tree generation...".to_string());

        // Calculate file hash from the raw file content
        let content_string = String::from_utf8_lossy(&file_content).to_string();
        let file_hash = get_hash_sum(&content_string);
        let file_hash_clean = file_hash.strip_prefix("0x").unwrap_or(&file_hash).to_string();
        logs.push(format!("File hash calculated: {}", file_hash));

        // Generate nonce
        let file_nonce = generate_nonce();
        logs.push("File nonce generated".to_string());

        // Create file revision (genesis revision)
        let file_revision = FileRevision {
            base: BaseRevision {
                previous_verification_hash: "".to_string(), // Genesis revision has empty previous hash
                local_timestamp: generate_timestamp(),
                version: create_version_string(HashingMethod::Scalar),
            },
            file_hash: file_hash_clean,
            file_nonce,
            content: Some(content_string), // Store the content as string
        };

        let revision = Revision::File(file_revision);

        // Calculate revision hash
        let revision_hash = calculate_revision_hash(&revision, HashingMethod::Scalar)
            .map_err(|e| vec![format!("Error calculating revision hash: {}", e)])?;

        logs.push(format!("Revision hash calculated: {}", revision_hash));

        // Create revisions map
        let mut revisions = HashMap::new();
        revisions.insert(revision_hash.clone(), revision);

        // Create file index
        let mut file_index = HashMap::new();
        file_index.insert(revision_hash.clone(), filename);

        // Build tree mapping
        let tree_mapping = build_tree_mapping(&revisions);

        // Create Aqua tree
        let aqua_tree = AquaTree {
            revisions,
            file_index: Some(file_index),
            tree_mapping: Some(tree_mapping),
        };

        logs.push("Aqua tree generation completed successfully".to_string());

        Ok(GenerationResult { aqua_tree, logs })
    }
}

/// Generates an Aqua tree from a given file using the provided CLI arguments
///
/// This function reads a file, processes it through the Aqua generation process,
/// and handles logging and output based on the provided CLI arguments.
///
/// # Arguments
///
/// * `args` - Command-line arguments containing configuration for the Aqua tree generation
/// * `domain_id` - A string identifier for the domain
///
/// # Behavior
///
/// - Reads the file specified in the arguments
/// - Creates a new Aqua tree with a genesis file revision
/// - Handles successful and failed generation scenarios
/// - Supports verbose logging and optional log file output
///
/// # Errors
///
/// - Prints error messages if file reading fails
/// - Logs generation errors if Aqua tree generation is unsuccessful
/// - Can save logs to a file if output path is specified
pub fn cli_generate_aqua_chain(args: CliArgs, domain_id: String) {
    let mut logs_data: Vec<String> = Vec::new();

    if let Some(file_path) = args.file {
        if let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) {
            // Read the file content into a Vec<u8>
            match fs::read(&file_path) {
                Ok(body_bytes) => {
                    // Convert the file name to a String
                    let file_name = file_name.to_string();
                    
                    // Create Aqua generator
                    let generator = AquaGenerator::new(domain_id);

                    // Attempt to generate the Aqua tree
                    match generator.generate_aqua_tree(body_bytes, file_name) {
                        Ok(result) => {
                            // Process successful generation
                            for log in result.logs {
                                logs_data.push(format!("\t\t {}", log));
                            }

                            logs_data.push(
                                "Success: Generating Aqua tree is successful".to_string(),
                            );

                            // Save Aqua tree data to a file
                            let save_result = save_aqua_tree(
                                &result.aqua_tree,
                                &file_path,
                                "aqua_tree.json".to_string(),
                            );

                            if let Err(e) = save_result {
                                logs_data.push(format!("Error saving Aqua tree data: {}", e));
                            }

                            // Handle log output based on verbosity
                            if args.verbose {
                                for item in logs_data.clone() {
                                    println!("{}", item);
                                }
                            } else {
                                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
                            }

                            // Optionally save logs to a file
                            if let Some(output_path) = args.output {
                                if let Err(e) = save_logs_to_file(&logs_data, output_path) {
                                    eprintln!("Error saving logs: {}", e);
                                }
                            }
                        }
                        Err(error_logs) => {
                            // Process failed generation
                            for log in error_logs {
                                logs_data.push(format!("\t\t {}", log));
                            }

                            logs_data.push("Error: Failed to generate Aqua tree".to_string());

                            // Optionally save logs to a file
                            if let Some(output_path) = args.output {
                                if let Err(e) = save_logs_to_file(&logs_data, output_path) {
                                    eprintln!("Error saving logs: {}", e);
                                }
                            }

                            // Handle log output based on verbosity
                            if args.verbose {
                                for item in logs_data {
                                    println!("{}", item);
                                }
                            } else {
                                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read file bytes: {}", e);
                }
            }
        } else {
            eprintln!("Error: Invalid file path provided with -f/--file");
        }
    } else {
        eprintln!("Failed to generate Aqua tree, check file path");
    }
}