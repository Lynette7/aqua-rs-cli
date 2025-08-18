use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecreatKeys {

    pub mnemonic: Option<String>,
    pub nostr_sk: Option<String>,
    #[serde(rename = "did:key")]
    pub did_key: Option<String>,

}
#[derive(Debug, Clone)]
pub struct CliArgs {
    pub authenticate: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub witness: Option<PathBuf>,
    pub file: Option<PathBuf>,
    pub remove: Option<PathBuf>,
    pub remove_count: i32,
    pub verbose: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub keys_file: Option<PathBuf>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignPayload {
   pub signature: String,
   pub  public_key: String,
   pub  wallet_address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WitnessPayload {
   pub tx_hash: String,
   pub  network: String,
   pub  wallet_address: String,
}

#[derive(Debug, Serialize)]
pub struct SignOrWitnessNetwork {
    pub network: String,
    
}

#[derive(Debug, Serialize)]
pub struct SignMessage {
    pub message: String,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct ResponseMessage {
    pub status: String,
}

/// Main Aqua Tree structure according to v3.2 schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AquaTree {
    pub revisions: HashMap<String, Revision>,
    pub file_index: Option<HashMap<String, String>>,
    #[serde(rename = "treeMapping")]
    pub tree_mapping: Option<TreeMapping>,
}

/// Base revision structure, all revisions share these properties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "revision_type")]
pub enum Revision {
    #[serde(rename = "file")]
    File(FileRevision),
    #[serde(rename = "form")]
    Form(FormRevision),
    #[serde(rename = "signature")]
    Signature(SignatureRevision),
    #[serde(rename = "witness")]
    Witness(WitnessRevision),
    #[serde(rename = "link")]
    Link(LinkRevision),
}

/// Common properties shared by all revisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseRevision {
    pub previous_verification_hash: String,
    pub local_timestamp: String,
    pub version: String,
}

/// File revision (Content revision)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub file_hash: String,
    pub file_nonce: String,
    pub content: Option<String>, // Optional file content
}

/// Form revision (special type of content revision for layer 2 applications)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub file_hash: String,
    pub file_nonce: String,
    pub forms_type: String,
    pub forms_name: Option<String>,
    pub forms_surname: Option<String>,
    pub forms_email: Option<String>,
    pub forms_date_of_birth: Option<String>,
    pub forms_wallet_address: Option<String>,
    pub leaves: Option<Vec<String>>, // For tree method verification
}

/// Signature revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub signature: String,
    pub signature_public_key: String,
    pub signature_wallet_address: String,
    pub signature_type: String,
}

/// Witness revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub witness_merkle_root: String,
    pub witness_timestamp: u64,
    pub witness_network: String,
    pub witness_smart_contract_address: String,
    pub witness_transaction_hash: String,
    pub witness_sender_account_address: String,
    pub witness_merkle_proof: Vec<String>,
}

/// Link revision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRevision {
    #[serde(flatten)]
    pub base: BaseRevision,
    pub link_type: String,
    pub link_verification_hashes: Vec<String>,
    pub link_file_hashes: Vec<String>,
}

/// Tree mapping structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeMapping {
    pub paths: HashMap<String, Vec<String>>,
    #[serde(rename = "latestHash")]
    pub latest_hash: String,
}

/// Tree node structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub hash: String,
    pub children: Vec<TreeNode>,
}

/// Verification result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub successful: bool,
    pub revision_results: Vec<RevisionResult>,
}

/// Individual revision verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionResult {
    pub hash: String,
    pub successful: bool,
    pub file_verification: VerificationStatus,
    pub content_verification: VerificationStatus,
    pub metadata_verification: VerificationStatus,
    pub witness_verification: VerificationStatus,
    pub signature_verification: VerificationStatus,
}

/// Verification status for different aspects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStatus {
    pub status: ResultStatusEnum,
    pub successful: bool,
    pub logs: Vec<String>,
}

/// Result status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResultStatusEnum {
    AVAILABLE,
    NOT_AVAILABLE,
}

/// Hashing method enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashingMethod {
    Scalar,
    Tree,
}

/// Version string constants
pub const SCHEMA_VERSION: &str = "https://aqua-protocol.org/docs/v3/schema_2";
pub const HASH_ALGORITHM: &str = "SHA256";
pub const DEFAULT_SIGNATURE_TYPE: &str = "ethereum:eip-191";

/// Utility function to create version string
pub fn create_version_string(method: HashingMethod) -> String {
    match method {
        HashingMethod::Scalar => format!("{} | {} | Method: scalar", SCHEMA_VERSION, HASH_ALGORITHM),
        HashingMethod::Tree => format!("{} | {} | Method: tree", SCHEMA_VERSION, HASH_ALGORITHM),
    }
}

/// Utility function to generate timestamp in required format (YYYYMMDDHHMMSS)
pub fn generate_timestamp() -> String {
    use chrono::Utc;
    Utc::now().format("%Y%m%d%H%M%S").to_string()
}

/// Utility function to generate nonce
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..64).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}