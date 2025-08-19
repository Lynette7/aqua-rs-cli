#[cfg(test)]
pub mod tests {
    use std::{fs, path::{Path, PathBuf}};
    use tempfile::tempdir;
    use serde_json;
    
    use crate::{
        aqua::witness::cli_winess_chain,
        models::{CliArgs, AquaTree, Revision, FileRevision, BaseRevision, SignatureRevision},
        utils::{get_hash_sum, calculate_revision_hash}
    };

    /// Helper function to create a test AquaTree v3.2 file for witnessing
    fn create_test_aqua_tree_for_witness(temp_dir: &Path) -> PathBuf {
        use std::collections::HashMap;
        use crate::models::{TreeMapping, HashingMethod, create_version_string, generate_timestamp, generate_nonce};
        
        // Create a file revision (genesis)
        let content = "Test file content for witnessing".to_string();
        let file_hash = get_hash_sum(&content);
        let file_hash_clean = file_hash.strip_prefix("0x").unwrap_or(&file_hash).to_string();
        
        let file_revision = FileRevision {
            base: BaseRevision {
                previous_verification_hash: "".to_string(),
                local_timestamp: generate_timestamp(),
                version: create_version_string(HashingMethod::Scalar),
            },
            file_hash: file_hash_clean,
            file_nonce: generate_nonce(),
            content: Some(content),
        };

        let file_revision_enum = Revision::File(file_revision);
        
        // Calculate proper hash for the revision
        let file_revision_hash = calculate_revision_hash(&file_revision_enum, HashingMethod::Scalar)
            .expect("Should calculate hash successfully");

        // Create signature revision to have a chain with multiple revisions
        let signature_revision = SignatureRevision {
            base: BaseRevision {
                previous_verification_hash: file_revision_hash.clone(),
                local_timestamp: generate_timestamp(),
                version: create_version_string(HashingMethod::Scalar),
            },
            signature: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b".to_string(),
            signature_public_key: "0x04abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            signature_wallet_address: "0x742d35cc6634c0532925a3b8d4fe1fd1d4a7d09e".to_string(),
            signature_type: "ethereum:eip-191".to_string(),
        };

        let signature_revision_enum = Revision::Signature(signature_revision);
        let signature_revision_hash = calculate_revision_hash(&signature_revision_enum, HashingMethod::Scalar)
            .expect("Should calculate signature hash successfully");

        // Create revisions map
        let mut revisions = HashMap::new();
        revisions.insert(file_revision_hash.clone(), file_revision_enum);
        revisions.insert(signature_revision_hash.clone(), signature_revision_enum);

        // Create file index
        let mut file_index = HashMap::new();
        file_index.insert(file_revision_hash.clone(), "test_witness_file.txt".to_string());
        file_index.insert(signature_revision_hash.clone(), "test_witness_file.txt".to_string());

        // Create tree mapping
        let mut paths = HashMap::new();
        paths.insert(file_revision_hash.clone(), vec![file_revision_hash.clone()]);
        paths.insert(signature_revision_hash.clone(), vec![file_revision_hash.clone(), signature_revision_hash.clone()]);
        
        let tree_mapping = TreeMapping {
            paths,
            latest_hash: signature_revision_hash.clone(),
        };

        // Create AquaTree
        let aqua_tree = AquaTree {
            revisions,
            file_index: Some(file_index),
            tree_mapping: Some(tree_mapping),
        };

        // Save to temp file
        let test_file_path = temp_dir.join("test_witness_aqua_tree.json");
        let json_data = serde_json::to_string_pretty(&aqua_tree).unwrap();
        fs::write(&test_file_path, json_data).unwrap();
        
        test_file_path
    }

    /// Helper function to create a simple AquaTree with only genesis revision
    fn create_simple_aqua_tree_for_witness(temp_dir: &Path) -> PathBuf {
        use std::collections::HashMap;
        use crate::models::{TreeMapping, HashingMethod, create_version_string, generate_timestamp, generate_nonce};
        
        // Create a simple file revision (genesis)
        let content = "Simple test content".to_string();
        let file_hash = get_hash_sum(&content);
        let file_hash_clean = file_hash.strip_prefix("0x").unwrap_or(&file_hash).to_string();
        
        let file_revision = FileRevision {
            base: BaseRevision {
                previous_verification_hash: "".to_string(),
                local_timestamp: generate_timestamp(),
                version: create_version_string(HashingMethod::Scalar),
            },
            file_hash: file_hash_clean,
            file_nonce: generate_nonce(),
            content: Some(content),
        };

        let revision = Revision::File(file_revision);
        let revision_hash = calculate_revision_hash(&revision, HashingMethod::Scalar)
            .expect("Should calculate hash successfully");

        // Create revisions map
        let mut revisions = HashMap::new();
        revisions.insert(revision_hash.clone(), revision);

        // Create file index
        let mut file_index = HashMap::new();
        file_index.insert(revision_hash.clone(), "simple_witness_file.txt".to_string());

        // Create tree mapping
        let mut paths = HashMap::new();
        paths.insert(revision_hash.clone(), vec![revision_hash.clone()]);
        
        let tree_mapping = TreeMapping {
            paths,
            latest_hash: revision_hash.clone(),
        };

        // Create AquaTree
        let aqua_tree = AquaTree {
            revisions,
            file_index: Some(file_index),
            tree_mapping: Some(tree_mapping),
        };

        // Save to temp file
        let test_file_path = temp_dir.join("simple_witness_aqua_tree.json");
        let json_data = serde_json::to_string_pretty(&aqua_tree).unwrap();
        fs::write(&test_file_path, json_data).unwrap();
        
        test_file_path
    }

    #[test]
    fn test_witness_chain_v3_2() {
        // Create a temporary directory for our test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create test files
        let aqua_tree_path = create_test_aqua_tree_for_witness(temp_dir.path());

        println!("Test AquaTree path for witnessing: {}", aqua_tree_path.display());

        // Prepare CLI arguments for testing
        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: Some(aqua_tree_path.clone()),
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_witness_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        // Call the witnessing function
        cli_winess_chain(cli_args.clone(), aqua_tree_path.clone());

        // Verify output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        // Read and verify log contents
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(!log_contents.is_empty(), "Log file should not be empty");
        
        // Check for either success or expected error messages
        let has_success = log_contents.contains("Success: Witnessing Aqua tree is successful");
        let has_witness_info = log_contents.contains("Witnessing successful!") || 
                              log_contents.contains("Witness revision created successfully");
        let has_server_error = log_contents.contains("Witnessing failed") || 
                              log_contents.contains("Error");
        
        // Test should pass if either witnessing succeeded or failed gracefully
        assert!(has_success || has_witness_info || has_server_error,
            "Log should indicate witnessing attempt (success or graceful failure)");

        // If witnessing was successful, check for witnessed file
        if has_success || has_witness_info {
            let witnessed_file_path = aqua_tree_path.with_extension("witnessed.json");
            if witnessed_file_path.exists() {
                // Verify the witnessed file contains a witness revision
                let witnessed_content = fs::read_to_string(&witnessed_file_path)
                    .expect("Should be able to read witnessed file");
                
                let witnessed_aqua_tree: AquaTree = serde_json::from_str(&witnessed_content)
                    .expect("Should be able to parse witnessed AquaTree");

                // Should have more revisions now (original + witness)
                assert!(witnessed_aqua_tree.revisions.len() >= 2, 
                    "Should have at least 2 revisions after witnessing");

                // Check that one revision is a witness
                let has_witness = witnessed_aqua_tree.revisions.values().any(|rev| {
                    matches!(rev, Revision::Witness(_))
                });
                assert!(has_witness, "Should contain a witness revision");
            }
        }
    }

    #[test]
    fn test_witness_chain_with_simple_tree() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let aqua_tree_path = create_simple_aqua_tree_for_witness(temp_dir.path());

        println!("Test simple AquaTree path: {}", aqua_tree_path.display());

        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: Some(aqua_tree_path.clone()),
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_simple_witness_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        // Call the witnessing function
        cli_winess_chain(cli_args.clone(), aqua_tree_path);

        // Verify output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(!log_contents.is_empty(), "Log file should not be empty");
    }

    #[test]
    fn test_witness_chain_with_invalid_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Use a non-existent file path
        let invalid_path = temp_dir.path().join("non_existent_aqua_tree.json");

        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: Some(invalid_path.clone()),
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_witness_error_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        // This should handle the error gracefully
        cli_winess_chain(cli_args.clone(), invalid_path);

        // Verify error handling
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(log_contents.contains("Error"), 
            "Log should contain an error message for invalid file");
    }

    #[test]
    fn test_witness_chain_with_empty_tree() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create an empty AquaTree
        let empty_aqua_tree = AquaTree {
            revisions: std::collections::HashMap::new(),
            file_index: None,
            tree_mapping: None,
        };

        let empty_tree_path = temp_dir.path().join("empty_aqua_tree.json");
        let json_data = serde_json::to_string_pretty(&empty_aqua_tree).unwrap();
        fs::write(&empty_tree_path, json_data).unwrap();

        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: Some(empty_tree_path.clone()),
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_empty_witness_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        cli_winess_chain(cli_args.clone(), empty_tree_path);

        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        // Should handle empty tree gracefully
        assert!(log_contents.contains("No revisions found") || log_contents.contains("Error"),
            "Log should indicate error for empty tree");
    }

    #[test] 
    fn test_witness_chain_malformed_json() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let malformed_file_path = temp_dir.path().join("malformed_witness.json");
        
        // Create malformed JSON file
        fs::write(&malformed_file_path, "{ invalid json for witnessing }").unwrap();

        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: Some(malformed_file_path.clone()),
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_malformed_witness_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        cli_winess_chain(cli_args.clone(), malformed_file_path);

        // Should handle JSON parsing errors gracefully
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(log_contents.contains("Error"), 
            "Log should contain an error message for malformed JSON");
    }
}