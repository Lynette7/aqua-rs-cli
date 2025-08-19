use crate::aqua::wallet::{create_ethereum_signature, get_wallet};
use crate::models::{
    CliArgs, AquaTree, Revision, SignatureRevision, BaseRevision, SignPayload,
    HashingMethod, create_version_string, generate_timestamp, DEFAULT_SIGNATURE_TYPE
};
use crate::servers::server_sign::sign_message_server;
use crate::utils::{
    read_aqua_data, read_secret_keys, save_logs_to_file, save_aqua_tree,
    get_latest_revision, calculate_revision_hash, build_tree_mapping
};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

/// Represents the result of extracting chain data
struct ChainExtractionResult {
    last_revision_hash: String,
    genesis_revision_filename: String,
}

/// Represents the result of signing operations
struct SigningResult {
    signature: String,
    public_key: String,
    wallet_address: String,
}

/// Main function to handle the CLI signing process
///
/// # Arguments
/// * `args` - CLI arguments
/// * `sign_path` - Path to the file to be signed
/// * `keys_file` - Optional path to the keys file
pub fn cli_sign_chain(
    args: CliArgs,
    sign_path: PathBuf,
    keys_file: Option<PathBuf>,
) {
    let mut logs_data: Vec<String> = Vec::new();
    logs_data.push(format!(
        "Starting signing process for file: {:?}",
        sign_path
    ));

    match process_signing_chain(&args, &sign_path, keys_file, &mut logs_data) {
        Ok(_) => {
            logs_data.push("Signing process completed successfully".to_string());
        }
        Err(e) => {
            logs_data.push(format!("Error in signing process: {}", e));
        }
    }

    output_results(&args, &logs_data);
}

/// Process the signing chain operation
fn process_signing_chain(
    args: &CliArgs,
    sign_path: &PathBuf,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
) -> Result<(), String> {
    let mut aqua_tree = read_and_validate_data(sign_path, logs_data)?;
    let chain_data = extract_chain_data(&aqua_tree, logs_data)?;
    let sign_result = perform_signing(&chain_data.last_revision_hash, keys_file, logs_data, args)?;

    // Create signature revision
    let signature_revision = SignatureRevision {
        base: BaseRevision {
            previous_verification_hash: chain_data.last_revision_hash,
            local_timestamp: generate_timestamp(),
            version: create_version_string(HashingMethod::Scalar),
        },
        signature: sign_result.signature,
        signature_public_key: sign_result.public_key,
        signature_wallet_address: sign_result.wallet_address,
        signature_type: DEFAULT_SIGNATURE_TYPE.to_string(),
    };

    let signature_revision_enum = Revision::Signature(signature_revision);
    
    // Calculate hash for the new signature revision
    let signature_hash = calculate_revision_hash(&signature_revision_enum, HashingMethod::Scalar)
        .map_err(|e| format!("Error calculating signature revision hash: {}", e))?;

    // Add signature revision to the tree
    aqua_tree.revisions.insert(signature_hash.clone(), signature_revision_enum);

    // Update file index if present
    if let Some(ref mut file_index) = aqua_tree.file_index {
        file_index.insert(signature_hash.clone(), chain_data.genesis_revision_filename);
    }

    // Rebuild tree mapping
    aqua_tree.tree_mapping = Some(build_tree_mapping(&aqua_tree.revisions));

    // Save the updated Aqua tree
    save_aqua_tree(&aqua_tree, sign_path, "signed.json".to_string())
        .map_err(|e| format!("Error saving signed Aqua tree: {}", e))?;

    logs_data.push("Signature revision added successfully".to_string());
    Ok(())
}

/// Read and validate the input data file
fn read_and_validate_data(
    sign_path: &PathBuf,
    logs_data: &mut Vec<String>,
) -> Result<AquaTree, String> {
    logs_data.push("Info : Reading and validating input data...".to_string());
    read_aqua_data(sign_path).map_err(|e| {
        logs_data.push(format!("Error : Error reading aqua data: {}", e));
        e
    })
}

/// Extract necessary chain data from the Aqua tree
fn extract_chain_data(
    aqua_tree: &AquaTree,
    logs_data: &mut Vec<String>,
) -> Result<ChainExtractionResult, String> {
    logs_data.push("Info : Extracting chain data...".to_string());

    // Get the latest revision
    let (latest_hash, latest_revision) = get_latest_revision(aqua_tree)
        .ok_or_else(|| {
            let error = "Error : No revisions found in Aqua tree".to_string();
            logs_data.push(error.clone());
            error
        })?;

    // Find genesis revision (the one with empty previous_verification_hash)
    let mut genesis_filename = "unknown".to_string();
    for (hash, revision) in &aqua_tree.revisions {
        let previous_hash = match revision {
            Revision::File(r) => &r.base.previous_verification_hash,
            Revision::Form(r) => &r.base.previous_verification_hash,
            Revision::Signature(r) => &r.base.previous_verification_hash,
            Revision::Witness(r) => &r.base.previous_verification_hash,
            Revision::Link(r) => &r.base.previous_verification_hash,
        };

        if previous_hash.is_empty() {
            // This is the genesis revision, try to get filename from file_index
            if let Some(file_index) = &aqua_tree.file_index {
                if let Some(filename) = file_index.get(hash) {
                    genesis_filename = filename.clone();
                }
            }
            break;
        }
    }

    Ok(ChainExtractionResult {
        last_revision_hash: latest_hash,
        genesis_revision_filename: genesis_filename,
    })
}

/// Perform the signing operation either through server or local keys
fn perform_signing(
    last_revision_hash: &str,
    keys_file: Option<PathBuf>,
    logs_data: &mut Vec<String>,
    args: &CliArgs,
) -> Result<SigningResult, String> {
    logs_data.push("Info : Starting signing process...".to_string());

    if let Some(keys_path) = keys_file {
        perform_local_signing(last_revision_hash, keys_path, logs_data, args)
    } else {
        perform_server_signing(last_revision_hash, logs_data)
    }
}

/// Perform signing using local keys
fn perform_local_signing(
    last_revision_hash: &str,
    keys_path: PathBuf,
    logs_data: &mut Vec<String>,
    args: &CliArgs,
) -> Result<SigningResult, String> {
    logs_data.push("Info : Performing local signing...".to_string());

    let secret_keys = read_secret_keys(&keys_path).map_err(|e| {
        let error = format!("Error :  error reading secret keys: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let mnemonic = secret_keys.mnemonic.ok_or_else(|| {
        let error = "Error : Mnemonic not found in secret keys".to_string();
        logs_data.push(error.clone());
        error
    })?;

    let gen_wallet_on_fail = if args.level.is_none() {
        true
    } else if args.level.as_ref().unwrap().trim() == "1" {
        false
    } else {
        true
    };

    let (address, public_key, private_key) =
        get_wallet(&mnemonic, gen_wallet_on_fail).map_err(|e| {
            let error = format!("Error : getting wallet: {}", e);
            logs_data.push(error.clone());
            error
        })?;

    let signature = create_ethereum_signature(&private_key, last_revision_hash).map_err(|e| {
        let error = format!("Error : creating signature: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    Ok(SigningResult {
        signature,
        public_key,
        wallet_address: address,
    })
}

/// Perform signing using the server
fn perform_server_signing(
    last_revision_hash: &str,
    logs_data: &mut Vec<String>,
) -> Result<SigningResult, String> {
    logs_data.push("Info : Performing server signing...".to_string());

    let runtime = tokio::runtime::Runtime::new().map_err(|e| {
        let error = format!("Error initializing tokio runtime: {}", e);
        logs_data.push(error.clone());
        error
    })?;

    let chain: String = env::var("chain").unwrap_or("sepolia".to_string());

    let sign_payload = runtime
        .block_on(async { sign_message_server(last_revision_hash.to_string(), chain).await })
        .map_err(|e| {
            let error = format!("Error in server signing: {}", e);
            logs_data.push(error.clone());
            error
        })?;

    Ok(SigningResult {
        signature: sign_payload.signature,
        public_key: sign_payload.public_key,
        wallet_address: sign_payload.wallet_address,
    })
}

/// Output the results based on CLI arguments
fn output_results(args: &CliArgs, logs_data: &Vec<String>) {
    if args.verbose {
        logs_data.iter().for_each(|log| println!("{}", log));
    } else if let Some(last_log) = logs_data.last() {
        println!("{}", last_log);
    }

    if let Some(output_path) = &args.output {
        if let Err(e) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", e);
        }
    }
}
