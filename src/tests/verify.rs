#[cfg(test)]
pub mod tests {
    use std::{fs, path::{Path, PathBuf}};
    use tempfile::tempdir;
    use serde_json;
    
    use crate::{
        aqua::verify::cli_verify_chain,
        models::{CliArgs, AquaTree, Revision, FileRevision, BaseRevision, SignatureRevision},
        utils::{get_hash_sum, calculate_revision_hash}
    };

    /// Helper function to create a valid test AquaTree v3.2 file
    fn create_valid_test_aqua_tree(temp_dir: &Path) -> PathBuf {
        use std::collections::HashMap;
        use crate::models::{TreeMapping, HashingMethod, create_version_string, generate_timestamp, generate_nonce};
        
        // Create a file revision (genesis)
        let content = "Test file content for verification".to_string();
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

        // Create signature revision
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
        file_index.insert(file_revision_hash.clone(), "test_file.txt".to_string());
        file_index.insert(signature_revision_hash.clone(), "test_file.txt".to_string());

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
        let test_file_path = temp_dir.join("valid_aqua_tree.json");
        let json_data = serde_json::to_string_pretty(&aqua_tree).unwrap();
        fs::write(&test_file_path, json_data).unwrap();
        
        test_file_path
    }

    /// Helper function to create an invalid test AquaTree with hash mismatches
    fn create_invalid_test_aqua_tree(temp_dir: &Path) -> PathBuf {
        use std::collections::HashMap;
        use crate::models::{TreeMapping, HashingMethod, create_version_string, generate_timestamp, generate_nonce};
        
        // Create file revision with incorrect hash
        let file_revision = FileRevision {
            base: BaseRevision {
                previous_verification_hash: "".to_string(),
                local_timestamp: generate_timestamp(),
                version: create_version_string(HashingMethod::Scalar),
            },
            file_hash: "incorrect_hash".to_string(),
            file_nonce: generate_nonce(),
            content: Some("Test content".to_string()),
        };

        let revision = Revision::File(file_revision);
        let wrong_hash = "0xwronghash1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string();

        let mut revisions = HashMap::new();
        revisions.insert(wrong_hash.clone(), revision);

        let mut file_index = HashMap::new();
        file_index.insert(wrong_hash.clone(), "test_file.txt".to_string());

        let mut paths = HashMap::new();
        paths.insert(wrong_hash.clone(), vec![wrong_hash.clone()]);
        
        let tree_mapping = TreeMapping {
            paths,
            latest_hash: wrong_hash.clone(),
        };

        let aqua_tree = AquaTree {
            revisions,
            file_index: Some(file_index),
            tree_mapping: Some(tree_mapping),
        };

        let test_file_path = temp_dir.join("invalid_aqua_tree.json");
        let json_data = serde_json::to_string_pretty(&aqua_tree).unwrap();
        fs::write(&test_file_path, json_data).unwrap();
        
        test_file_path
    }

    #[test]
    fn test_verify_valid_chain_v3_2() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let aqua_tree_path = create_valid_test_aqua_tree(temp_dir.path());

        println!("Test valid AquaTree path: {}", aqua_tree_path.display());

        let cli_args = CliArgs {
            authenticate: Some(aqua_tree_path.clone()),
            sign: None,
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_verify_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        // Call the verification function
        cli_verify_chain(cli_args.clone(), aqua_tree_path);

        // Verify output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        // Read and check log contents
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(!log_contents.is_empty(), "Log file should not be empty");

        assert!(log_contents.contains("Success") || log_contents.contains("valid"), 
            "Log should indicate verification results");
    }

    #[test]
    fn test_verify_invalid_chain() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let aqua_tree_path = create_invalid_test_aqua_tree(temp_dir.path());

        println!("Test invalid AquaTree path: {}", aqua_tree_path.display());

    

        // Prepare CLI arguments for testing
        let cli_args = CliArgs {
            authenticate: Some(aqua_tree_path.clone()),
            sign: None,
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_verify_invalid_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        // Call the verification function
        cli_verify_chain(cli_args.clone(), aqua_tree_path);

        // Verify output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        // Read and check log contents
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(!log_contents.is_empty(), "Log file should not be empty");
        
        // Should contain error or failure messages for invalid chain
        assert!(log_contents.contains("Error") || log_contents.contains("not valid"), 
            "Log should indicate verification failures for invalid chain");
    }
    
    #[test]
    fn test_verify_chain_with_non_existent_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let non_existent_path = temp_dir.path().join("non_existent_file.json");

        println!("Test non-existent path: {}", non_existent_path.display());

        let cli_args = CliArgs {
            authenticate: Some(non_existent_path.clone()),
            sign: None,
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_verify_error_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        cli_verify_chain(cli_args.clone(), non_existent_path);

        // Verify error handling
        if cli_args.output.as_ref().unwrap().exists() {
            let log_contents = fs::read_to_string(cli_args.output.unwrap())
                .expect("Should be able to read the log file");
            
            assert!(log_contents.contains("Error"), 
                "Log should contain an error message for non-existent file");
        }
    }

    #[test]
    fn test_verify_malformed_json() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let malformed_file_path = temp_dir.path().join("malformed.json");
        
        // Create malformed JSON file
        fs::write(&malformed_file_path, "{ invalid json content }").unwrap();

        let cli_args = CliArgs {
            authenticate: Some(malformed_file_path.clone()),
            sign: None,
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_malformed_output.txt")),
            level: Some("2".to_string()),
            keys_file: None,
        };

        cli_verify_chain(cli_args.clone(), malformed_file_path);

        // Should handle JSON parsing errors gracefully
        if cli_args.output.as_ref().unwrap().exists() {
            let log_contents = fs::read_to_string(cli_args.output.unwrap())
                .expect("Should be able to read the log file");
            
            assert!(log_contents.contains("Error"), 
                "Log should contain an error message for malformed JSON");
        }
    }
}