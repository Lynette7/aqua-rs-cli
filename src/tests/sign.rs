#[cfg(test)]
pub mod tests {
    use std::{fs, path::{Path, PathBuf}};
    use tempfile::tempdir;
    use serde_json;
    
    use crate::{
        aqua::sign::cli_sign_chain,
        models::{CliArgs, AquaTree, Revision, FileRevision, BaseRevision}
    };

    /// Helper function to create a test AquaTree v3.2 file
    fn create_test_aqua_tree(temp_dir: &Path) -> PathBuf {
        use std::collections::HashMap;
        use crate::models::{TreeMapping, HashingMethod, create_version_string, generate_timestamp, generate_nonce};
        
        // Create a simple file revision (genesis)
        let file_revision = FileRevision {
            base: BaseRevision {
                previous_verification_hash: "".to_string(),
                local_timestamp: generate_timestamp(),
                version: create_version_string(HashingMethod::Scalar),
            },
            file_hash: "abc123def456".to_string(),
            file_nonce: generate_nonce(),
            content: Some("Test file content".to_string()),
        };

        let revision = Revision::File(file_revision);
        let revision_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();

        // Create revisions map
        let mut revisions = HashMap::new();
        revisions.insert(revision_hash.clone(), revision);

        // Create file index
        let mut file_index = HashMap::new();
        file_index.insert(revision_hash.clone(), "test_file.txt".to_string());

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
        let test_file_path = temp_dir.join("test_aqua_tree.json");
        let json_data = serde_json::to_string_pretty(&aqua_tree).unwrap();
        fs::write(&test_file_path, json_data).unwrap();
        
        test_file_path
    }

    /// Helper function to create test keys file
    fn create_test_keys_file(temp_dir: &Path) -> PathBuf {
        use crate::models::SecreatKeys;
        
        let keys = SecreatKeys {
            mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            nostr_sk: None,
            did_key: None,
        };

        let keys_path = temp_dir.join("test_keys.json");
        let json_data = serde_json::to_string_pretty(&keys).unwrap();
        fs::write(&keys_path, json_data).unwrap();
        
        keys_path
    }

    #[test]
    fn test_sign_chain_v3_2() {
        // Create a temporary directory for our test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create test files
        let aqua_tree_path = create_test_aqua_tree(temp_dir.path());
        let keys_path = create_test_keys_file(temp_dir.path());

        println!("Test AquaTree path: {}", aqua_tree_path.display());
        println!("Test keys path: {}", keys_path.display());

        // Prepare CLI arguments for testing
        let cli_args = CliArgs {
            authenticate: None,
            sign: Some(aqua_tree_path.clone()),
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_sign_output.txt")),
            level: Some("2".to_string()),
            keys_file: Some(keys_path.clone()),
        };

        // Call the signing function
        cli_sign_chain(cli_args.clone(), aqua_tree_path.clone(), Some(keys_path));

        // Verify output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        // Check if signed file was created
        let signed_file_path = aqua_tree_path.with_extension("signed.json");
        assert!(signed_file_path.exists(), 
            "Signed AquaTree file should have been created");

        // Verify the signed file contains a signature revision
        let signed_content = fs::read_to_string(&signed_file_path)
            .expect("Should be able to read signed file");
        
        let signed_aqua_tree: AquaTree = serde_json::from_str(&signed_content)
            .expect("Should be able to parse signed AquaTree");

        // Should have 2 revisions now (original file + signature)
        assert_eq!(signed_aqua_tree.revisions.len(), 2, 
            "Should have 2 revisions after signing");

        // Check that one revision is a signature
        let has_signature = signed_aqua_tree.revisions.values().any(|rev| {
            matches!(rev, Revision::Signature(_))
        });
        assert!(has_signature, "Should contain a signature revision");

        // Read and verify log contents
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        // Add more specific assertions based on your expected verification results
        // For example:
        assert!(!log_contents.is_empty(), "Log file should not be empty");
        assert!(log_contents.contains("Signature revision added successfully") || 
                log_contents.contains("Signing process completed successfully"), 
            "Log should indicate successful signing");
    }

    #[test]
    fn test_sign_chain_with_invalid_file() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Use a non-existent file path
        let invalid_path = temp_dir.path().join("non_existent_aqua_tree.json");
        let keys_path = create_test_keys_file(temp_dir.path());

        let cli_args = CliArgs {
            authenticate: None,
            sign: Some(invalid_path.clone()),
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_error_output.txt")),
            level: Some("2".to_string()),
            keys_file: Some(keys_path.clone()),
        };

        // This should handle the error gracefully
        cli_sign_chain(cli_args.clone(), invalid_path, Some(keys_path));

        // Verify error handling
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        assert!(log_contents.contains("Error"), 
            "Log should contain an error message for invalid file");
    }

    #[test]
    fn test_sign_chain_without_keys() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create test AquaTree but no keys file
        let aqua_tree_path = create_test_aqua_tree(temp_dir.path());

        let cli_args = CliArgs {
            authenticate: None,
            sign: Some(aqua_tree_path.clone()),
            witness: None,
            file: None,
            remove: None,
            remove_count: 0,
            verbose: true,
            output: Some(temp_dir.path().join("test_no_keys_output.txt")),
            level: Some("2".to_string()),
            keys_file: None, // No keys file provided
        };

        // This should use server signing instead of local signing
        cli_sign_chain(cli_args.clone(), aqua_tree_path, None);

        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        // Should indicate server signing was attempted
        assert!(!log_contents.is_empty(), "Log file should not be empty");
    }
}