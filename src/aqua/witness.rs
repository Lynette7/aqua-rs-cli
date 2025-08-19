use std::env;
use std::path::PathBuf;

use crate::models::{
    CliArgs, AquaTree, Revision, WitnessRevision, BaseRevision, WitnessPayload,
    HashingMethod, create_version_string, generate_timestamp
};
use crate::servers::server_witness::witness_message_server;
use crate::utils::{
    read_aqua_data, save_logs_to_file, save_aqua_tree,
    get_latest_revision, get_hash_sum, calculate_revision_hash, build_tree_mapping
};

/// Generates a witness revision for an Aqua tree using the provided CLI arguments.
///
/// This function performs the following key steps:
/// 1. Reads Aqua data from the specified witness path
/// 2. Validates the Aqua tree and its revisions
/// 3. Generates a witness event verification hash
/// 4. Interacts with a witness message server to obtain authentication
/// 5. Creates a witness revision and adds it to the Aqua tree
///
/// # Arguments
///
/// * `args` - Command-line arguments containing configuration for the witnessing process
/// * `witness_path` - Path to the file to be witnessed
///
/// # Behavior
///
/// - Validates the input Aqua tree
/// - Generates a witness event verification hash
/// - Obtains authentication from a witness message server
/// - Creates and adds a witness revision to the tree
/// - Handles logging and output based on CLI arguments
///
/// # Errors
///
/// - Returns early if:
///   - Unable to read the Aqua data file
///   - No revisions are found in the tree
///   - Unable to initialize Tokio runtime
///   - Witnessing process fails
///
/// # Logging
///
/// - Supports verbose and non-verbose logging
/// - Can save logs to a file if an output path is specified
// Fixed witness hash generation in cli_witness_chain function

pub fn cli_winess_chain(args: CliArgs, witness_path: PathBuf) {
    let mut logs_data: Vec<String> = Vec::new();

    println!("Witnessing file: {:?}", witness_path);

    // Read Aqua data from the specified file
    let mut aqua_tree = match read_aqua_data(&witness_path) {
        Ok(data) => data,
        Err(error) => {
            logs_data.push(error);
            handle_error_output(&args, &logs_data);
            return;
        }
    };

    // Validate that we have revisions
    if aqua_tree.revisions.is_empty() {
        logs_data.push("No revisions found in Aqua tree".to_string());
        handle_error_output(&args, &logs_data);
        return;
    }

    // Get the latest revision hash
    let (latest_hash, _) = match get_latest_revision(&aqua_tree) {
        Some(data) => data,
        None => {
            logs_data.push("Error: Unable to determine latest revision".to_string());
            handle_error_output(&args, &logs_data);
            return;
        }
    };

    // Initialize Tokio runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            logs_data.push(format!("Error initializing tokio runtime: {}", e));
            handle_error_output(&args, &logs_data);
            return;
        }
    };

    // Generate witness event verification hash properly
    let empty_hash = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    
    // Clean the latest hash (remove 0x prefix if present)
    let clean_latest_hash = latest_hash.strip_prefix("0x").unwrap_or(&latest_hash);
    
    // Ensure proper concatenation
    let witness_event_verification_string = format!("{}{}", empty_hash, clean_latest_hash);
    let witness_event_verification_hash = get_hash_sum(&witness_event_verification_string);
    
    // Clean the resulting hash for server communication
    let clean_witness_hash = witness_event_verification_hash.strip_prefix("0x").unwrap_or(&witness_event_verification_hash);
    
    logs_data.push(format!("Latest hash: {}", latest_hash));
    logs_data.push(format!("Clean latest hash: {}", clean_latest_hash));
    logs_data.push(format!("Witness verification string: {}", witness_event_verification_string));
    logs_data.push(format!("Witness verification hash: {}", witness_event_verification_hash));
    logs_data.push(format!("Clean witness hash for server: {}", clean_witness_hash));

    let chain: String = env::var("chain").unwrap_or("sepolia".to_string());

    // Obtain witness authentication via message server
    let auth_payload = match runtime.block_on(async {
        witness_message_server(clean_witness_hash.to_string(), chain).await
    }) {
        Ok(payload) => payload,
        Err(e) => {
            logs_data.push(format!("Witnessing failed: {}", e));
            handle_error_output(&args, &logs_data);
            return;
        }
    };

    // Print witnessing details
    println!("Witnessing successful!");
    println!("Network: {}", auth_payload.network);
    println!("Tx hash: {}", auth_payload.tx_hash);
    println!("Wallet Address: {}", auth_payload.wallet_address);

    // Create witness revision
    let witness_revision = WitnessRevision {
        base: BaseRevision {
            previous_verification_hash: latest_hash.clone(),
            local_timestamp: generate_timestamp(),
            version: create_version_string(HashingMethod::Scalar),
        },
        witness_merkle_root: latest_hash.clone(),
        witness_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        witness_network: auth_payload.network,
        witness_smart_contract_address: "0x45f59310ADD88E6d23ca58A0Fa7A55BEE6d2a611".to_string(),
        witness_transaction_hash: auth_payload.tx_hash,
        witness_sender_account_address: auth_payload.wallet_address,
        witness_merkle_proof: vec![latest_hash.clone()],
    };

    let witness_revision_enum = Revision::Witness(witness_revision);

    // Calculate hash for the new witness revision
    match calculate_revision_hash(&witness_revision_enum, HashingMethod::Scalar) {
        Ok(witness_hash) => {
            // Add witness revision to the tree
            aqua_tree.revisions.insert(witness_hash.clone(), witness_revision_enum);

            // Find genesis filename for file index
            let genesis_filename = find_genesis_filename(&aqua_tree);

            // Update file index if present
            if let Some(ref mut file_index) = aqua_tree.file_index {
                file_index.insert(witness_hash.clone(), genesis_filename);
            }

            // Rebuild tree mapping
            aqua_tree.tree_mapping = Some(build_tree_mapping(&aqua_tree.revisions));

            logs_data.push("Witness revision created successfully".to_string());
            
            // Save the updated Aqua tree
            match save_aqua_tree(&aqua_tree, &witness_path, "witnessed.json".to_string()) {
                Ok(_) => {
                    logs_data.push("Success: Witnessing Aqua tree is successful".to_string());
                }
                Err(e) => {
                    logs_data.push(format!("Error saving witnessed Aqua tree: {}", e));
                }
            }
        }
        Err(e) => {
            logs_data.push(format!("Error calculating witness revision hash: {}", e));
        }
    }

    // Handle logging based on verbosity
    if args.verbose {
        for item in logs_data.clone() {
            println!("{}", item);
        }
    } else {
        println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
    }

    // Save logs to file if output path is specified
    if let Some(output_path) = args.output {
        if let Err(e) = save_logs_to_file(&logs_data, output_path) {
            eprintln!("Error saving logs: {}", e);
        }
    }
}

/// Find the genesis filename from the Aqua tree
fn find_genesis_filename(aqua_tree: &AquaTree) -> String {
    // Find genesis revision
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
                    return filename.clone();
                }
            }
            return "genesis_file".to_string();
        }
    }
    "unknown".to_string()
}

/// Handle error output based on CLI arguments
fn handle_error_output(args: &CliArgs, logs_data: &Vec<String>) {
    if args.verbose {
        for item in logs_data {
            println!("{}", item);
        }
    } else if let Some(last_log) = logs_data.last() {
        println!("{}", last_log);
    }

    if let Some(output_path) = &args.output {
        if let Err(e) = save_logs_to_file(logs_data, output_path.clone()) {
            eprintln!("Error saving logs: {}", e);
        }
    }
}