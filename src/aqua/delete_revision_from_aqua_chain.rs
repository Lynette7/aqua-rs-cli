use std::path::PathBuf;
use std::collections::HashMap;

use crate::models::{CliArgs, AquaTree, Revision};
use crate::utils::{read_aqua_data, save_logs_to_file, save_aqua_tree, build_tree_mapping};

/// Result structure for revision deletion operations
pub struct DeletionResult {
    pub aqua_tree: AquaTree,
    pub logs: Vec<String>,
}

/// AquaRevisionRemover implementation for v3.2
pub struct AquaRevisionRemover {
    pub version: f32,
}

impl AquaRevisionRemover {
    pub fn new(version: f32) -> Self {
        Self { version }
    }

    /// Delete a specified number of revisions from the end of an Aqua chain
    pub fn delete_revision_in_aqua_chain(
        &self,
        mut aqua_tree: AquaTree,
        revision_count: i32,
    ) -> Result<(AquaTree, Vec<String>), Vec<String>> {
        let mut logs = Vec::new();
        logs.push(format!("Starting deletion of {} revision(s)", revision_count));

        if revision_count <= 0 {
            logs.push("Error: Revision count must be greater than 0".to_string());
            return Err(logs);
        }

        if aqua_tree.revisions.is_empty() {
            logs.push("Error: No revisions found in Aqua tree".to_string());
            return Err(logs);
        }

        // Find the chain order by following previous_verification_hash references
        let chain_order = self.build_revision_chain(&aqua_tree, &mut logs)?;
        
        if chain_order.len() <= 1 {
            logs.push("Error: Cannot remove genesis revision - at least one revision must remain".to_string());
            return Err(logs);
        }

        let revisions_to_remove = std::cmp::min(revision_count as usize, chain_order.len() - 1);
        logs.push(format!("Will remove {} revision(s)", revisions_to_remove));

        // Remove revisions from the end (most recent first)
        let mut removed_count = 0;
        for i in 0..revisions_to_remove {
            let revision_index = chain_order.len() - 1 - i;
            if let Some(hash_to_remove) = chain_order.get(revision_index) {
                if let Some(removed_revision) = aqua_tree.revisions.remove(hash_to_remove) {
                    logs.push(format!("Removed revision: {}", hash_to_remove));
                    
                    // Also remove from file_index if present
                    if let Some(ref mut file_index) = aqua_tree.file_index {
                        file_index.remove(hash_to_remove);
                    }
                    
                    removed_count += 1;
                } else {
                    logs.push(format!("Warning: Revision {} not found in tree", hash_to_remove));
                }
            }
        }

        if removed_count == 0 {
            logs.push("Error: No revisions were removed".to_string());
            return Err(logs);
        }

        // Rebuild tree mapping after deletion
        aqua_tree.tree_mapping = Some(build_tree_mapping(&aqua_tree.revisions));
        
        logs.push(format!("Successfully removed {} revision(s)", removed_count));
        logs.push("Tree mapping rebuilt successfully".to_string());

        Ok((aqua_tree, logs))
    }

    /// Build the revision chain in chronological order
    fn build_revision_chain(&self, aqua_tree: &AquaTree, logs: &mut Vec<String>) -> Result<Vec<String>, Vec<String>> {
        let mut chain = Vec::new();
        let mut visited = std::collections::HashSet::new();

        // Find genesis revision (one with empty previous_verification_hash)
        let mut genesis_hash = None;
        for (hash, revision) in &aqua_tree.revisions {
            let previous_hash = self.get_previous_hash(revision);
            if previous_hash.is_empty() {
                if genesis_hash.is_some() {
                    logs.push("Error: Multiple genesis revisions found".to_string());
                    return Err(logs.clone());
                }
                genesis_hash = Some(hash.clone());
            }
        }

        let genesis = match genesis_hash {
            Some(hash) => hash,
            None => {
                logs.push("Error: No genesis revision found".to_string());
                return Err(logs.clone());
            }
        };

        // Build chain starting from genesis
        let mut current_hash = genesis;
        loop {
            if visited.contains(&current_hash) {
                logs.push("Error: Circular reference detected in revision chain".to_string());
                return Err(logs.clone());
            }

            chain.push(current_hash.clone());
            visited.insert(current_hash.clone());

            // Find next revision that has current_hash as its previous_verification_hash
            let mut next_hash = None;
            for (hash, revision) in &aqua_tree.revisions {
                let previous_hash = self.get_previous_hash(revision);
                if previous_hash == current_hash {
                    if next_hash.is_some() {
                        logs.push(format!("Warning: Multiple revisions reference {} as previous", current_hash));
                    }
                    next_hash = Some(hash.clone());
                }
            }

            match next_hash {
                Some(hash) => current_hash = hash,
                None => break, // End of chain
            }
        }

        logs.push(format!("Built revision chain with {} revisions", chain.len()));
        Ok(chain)
    }

    /// Extract previous_verification_hash from any revision type
    fn get_previous_hash<'a>(&self, revision: &'a Revision) -> &'a str {
        match revision {
            Revision::File(r) => &r.base.previous_verification_hash,
            Revision::Form(r) => &r.base.previous_verification_hash,
            Revision::Signature(r) => &r.base.previous_verification_hash,
            Revision::Witness(r) => &r.base.previous_verification_hash,
            Revision::Link(r) => &r.base.previous_verification_hash,
        }
    }
}

/// Removes a specified number of revisions from an Aqua chain file.
///
/// This function performs the following key operations:
/// 1. Reads the Aqua chain data from a specified file
/// 2. Attempts to delete a specified number of revisions using an AquaRevisionRemover
/// 3. Saves the modified page data to a new file
/// 4. Handles logging and output based on CLI arguments
///
/// # Arguments
/// * `args` - Command-line arguments specifying removal parameters
/// * `aqua_chain_file_path` - Path to the Aqua chain file to be processed
///
/// # Behavior
/// - Reads the Aqua chain file
/// - Attempts to remove the specified number of revisions
/// - Saves modified data to a new file with '.modified.json' suffix
/// - Logs operations and potential errors
/// - Optionally prints logs based on verbosity setting
/// - Optionally saves logs to a specified output file
///
/// # Errors
/// - Handles and logs errors during file reading, revision removal, and log saving
/// - Does not panic, instead logs and returns from the function on errors
pub fn cli_remove_revisions_from_aqua_chain(
    args: CliArgs, 
    aqua_chain_file_path: PathBuf
) {
    // Number of revisions to remove
    let revision_count_for_deletion = args.remove_count;

    // Vector to store log messages
    let mut logs_data: Vec<String> = Vec::new();

    // Print the file being processed
    println!("Processing file: {:?}", aqua_chain_file_path);
    logs_data.push(format!("Processing file: {:?}", aqua_chain_file_path));

    // Read Aqua data from the file
    let aqua_tree = match read_aqua_data(&aqua_chain_file_path) {
        Ok(data) => data,
        Err(error) => {
            logs_data.push(format!("Error reading Aqua data: {}", error));
            handle_error_output(&args, &logs_data);
            return;
        }
    };

    // Create revision remover
    let revision_remover = AquaRevisionRemover::new(3.2);

    // Attempt to delete revisions from the Aqua chain
    match revision_remover.delete_revision_in_aqua_chain(aqua_tree, revision_count_for_deletion) {
        Ok((modified_aqua_tree, logs)) => {
            // Collect logs with indentation
            for log in logs {
                logs_data.push(format!("\t\t {}", log));
            }

            // Add success message
            logs_data.push(
                "Success: Removing revision from Aqua chain is successful".to_string(),
            );

            // Save modified Aqua tree data to a new file
            match save_aqua_tree(
                &modified_aqua_tree,
                &aqua_chain_file_path,
                "chain.modified.json".to_string(),
            ) {
                Ok(_) => {
                    logs_data.push("Modified Aqua tree saved successfully".to_string());
                }
                Err(e) => {
                    logs_data.push(format!("Error saving modified Aqua tree: {}", e));
                }
            }

            // Print logs based on verbosity setting
            if args.verbose {
                for item in &logs_data {
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
        Err(error_logs) => {
            // Collect error logs with indentation
            for log in error_logs {
                logs_data.push(format!("\t\t {}", log));
            }

            // Add error message
            logs_data.push("Error: Failed to remove revisions from Aqua chain".to_string());

            // Save logs to file if output path is specified
            if let Some(output_path) = args.output {
                if let Err(e) = save_logs_to_file(&logs_data, output_path) {
                    eprintln!("Error saving logs: {}", e);
                }
            }

            // Print logs based on verbosity setting
            if args.verbose {
                for item in &logs_data {
                    println!("{}", item);
                }
            } else {
                println!("{}", logs_data.last().unwrap_or(&"Result".to_string()))
            }
        }
    }
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