#[cfg(test)]
pub mod tests {
    use std::{fs, path::{Path, PathBuf}};
    use tempfile::tempdir;
    // use tempfile::tempdir;
    // use super::*; // Import parent module's structs and functions
    use verifier::aqua_verifier::{AquaVerifier, VerificationOptions};
    use aqua_verifier_rs_types::models::page_data::PageData;

    use crate::{aqua::{sign::cli_sign_chain, verify::cli_verify_chain, witness::cli_winess_chain}, models::CliArgs};


    #[test]
    fn test_sign_chain() {
        // Create a temporary directory for our test files
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create a test aqua data file
        // let verify_path = create_test_aqua_data_file(temp_dir.path());

        let path = Path::new("src/test/data/logo.chain.json").to_path_buf();

        print!("Path is {}", path.display());

        let keys = Path::new("src/test/data/keys.sample.json").to_path_buf();

        print!("keys is {}", keys.display());

        

        // Prepare CLI arguments for testing
        let cli_args = CliArgs {
            authenticate: None,
            sign: None,
            witness: None,
            file: Some(path),
            remove: None,
            remove_count: 0,
            verbose: true, // Set to true to see detailed logs during test
            output: Some(temp_dir.path().join("test_output_logs.txt")),
            level: Some("2".to_string()), // Adjust as needed
            keys_file: Some(keys.clone()),
        };

       
    let option = VerificationOptions {
        version: 1.2,
        strict: false,
        allow_null: false,
        verification_platform: "none".to_string(),
        chain: "sepolia".to_string(),
        api_key: "".to_string(),
    };

    let aqua_verifier = AquaVerifier::new(Some(option));


        // Call the function being tested
        // This is a no-panic test to ensure the function runs without crashing
        cli_sign_chain(
            cli_args.clone(), 
            aqua_verifier, 
            cli_args.file.unwrap(),
            Some(keys),
        );

        // Optional: Add assertions to verify expected behavior
        // 1. Check if output file was created
        assert!(cli_args.output.as_ref().unwrap().exists(), 
            "Output log file should have been created");

        // 2. Read and optionally check the contents of the output log
        let log_contents = fs::read_to_string(cli_args.output.unwrap())
            .expect("Should be able to read the log file");
        
        // Add more specific assertions based on your expected verification results
        // For example:
        assert!(!log_contents.is_empty(), "Log file should not be empty");
        // You might want to add more specific checks based on your verification logic
    }

    

}