pub mod aqua;
pub mod models;
pub mod servers;
pub mod utils;
pub mod tests;

use crate::models::CliArgs;
use aqua::sign::cli_sign_chain;
use aqua::verify::cli_verify_chain;
use aqua::witness::cli_winess_chain;
use aqua::{
    delete_revision_from_aqua_chain::cli_remove_revisions_from_aqua_chain,
    generate_aqua_chain_from_file::cli_generate_aqua_chain,
};
use clap::{Arg, ArgAction, ArgGroup, Command};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, path::PathBuf};
use utils::{is_valid_file, is_valid_json_file, is_valid_output_file};
// use aqua_verifier::aqua_verifier::{AquaVerifier, VerificationOptions};

const LONG_ABOUT: &str = r#"🔐 Aqua CLI TOOL

========================================================

This tool validates files using the Aqua Protocol v3.2. It can:
  • Verify Aqua tree JSON files
  • Generate Aqua trees
  • Sign Aqua trees
  • Witness Aqua trees
  • Generate validation reports

COMMANDS: 
   • -a  or --authenticate  to verify an aqua json file.
   • -s or --sign to sign an aqua json file.
   • -w or --witness to witness an aqua json file.
   • -f or --file to generate an aqua json file.
   • -v or --verbose  to provide logs about the  process when using  -v,-s,-w or -f command (verbose option).
   • -o or --output to save the output to a file (json, html or pdf).
   • -l  or --level  define how strict the validation should be 1 or 2
        1: Strict validation (does look up, if local wallet mnemonic fails it panic)
        2: Standard validation (create a new mnemonic if one in keys.json faile)
   • -h or --help to show usage, about aqua-cli.
   • -i or --info to show the cli version.
   • -k or --key-file to specify the file containings  (this can also be set in the env  )
   • -d or --delete remove revision from an aqua json file, bydefault removes last revsion but can be used with -c or --count parameter to specifiy the number of revisions
   • -c or --count to specify the number of revisions to remove (note a genesis revision cannot be removed)

EXAMPLES:
    aqua-cli -a chain.json
    aqua-cli -s chain.json --output report.json
    aqua-cli -w chain.json --output report.json

    aqua-cli -f document.pdf
    aqua-cli --file image.png --verbose
    aqua-cli -f document.json --output report.json


SUMMARY
   * aqua-cli expects at least parameter -s,-a,-w or -f.
   * in your environment set the
    1. aqua_domain="random_alphanumeric"
    2. aqua_network="sepolia" or  "holesky" or "mainnet"
    3. verification_platform="alchemy" or "infura" or "none"  for witnessing (default "none")
    4. aqua_alchemy_look_up=  false or true

For more information, visit: https://github.com/inblockio/aqua-verifier-cli"#;

pub fn parse_args() -> Result<CliArgs, String> {
    let matches = Command::new("aqua-cli")
        .version("3.2.0")
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .long_about(LONG_ABOUT)
        .about("🔐 Aqua CLI Tool v3.2 - Validates, Verifies, Signs, Witness Aqua tree files and generates Aqua tree files using Aqua Protocol v3.2")
        .arg(Arg::new("authenticate")
            .short('a')
            .long("authenticate")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("authenticate (verify) an aqua json file"))
        .arg(Arg::new("sign")
            .short('s')
            .long("sign")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Sign an aqua json file"))
        .arg(Arg::new("witness")
            .short('w')
            .long("witness")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("Witness an aqua json file"))
        .arg(Arg::new("count")
                    .short('c')
                    .long("count")
                    .value_parser(clap::value_parser!(i32)) // Ensures it's a valid unsigned integer
                    .help("Sets a count value")           )
        .arg(Arg::new("delete")
            .short('d')
            .long("delete")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("delete/remove revision from an aqua json file, bydefault removes last revsion but can be used with -c or --count parameter to specifiy the number of revisions"))
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_file))
            .help("Generate an aqua json file")
            .conflicts_with_all(["authenticate", "sign", "witness"]))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .action(ArgAction::SetTrue)
            .help("Provide additional details")
            .long_help("to provide logs about the  process when using  -v,-s,-w or -f command (verbose option)"))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_output_file))
            .help("Save the output to a file (json, html or pdf)"))
        .arg(Arg::new("level")
            .short('l')
            .long("level")
            .help("Define how strict the validation should be")
            .long_help("Define how strict the validation should be:\n 1: Strict validation\n 2: Standard validation")
            .value_parser(["1", "2"])
            .default_value("2")
            .action(ArgAction::Set))
        .arg(Arg::new("keys_file")
            .short('k')
            .long("keys_file")
            .action(ArgAction::Set)
            .value_parser(clap::builder::ValueParser::new(is_valid_json_file))
            .help("keys file json containing nounce, nostr_sk and did:key"))
        .group(ArgGroup::new("operation")
            .args(["authenticate", "sign", "witness", "file", "delete"])
            .required(true))
        .get_matches();

    let authenticate = matches
        .get_one::<String>("authenticate")
        .map(|p| PathBuf::from(p));
    let remove = matches
        .get_one::<String>("delete")
        .map(|p| PathBuf::from(p));
    let sign = matches.get_one::<String>("sign").map(|p| PathBuf::from(p));
    let witness = matches
        .get_one::<String>("witness")
        .map(|p| PathBuf::from(p));
    let file = matches.get_one::<String>("file").map(|p| PathBuf::from(p));
    let verbose = matches.get_flag("verbose");
    let output = matches
        .get_one::<String>("output")
        .map(|o| PathBuf::from(o));
    let level = matches.get_one::<String>("level").cloned();
    let keys_file = matches
        .get_one::<String>("keys_file")
        .map(|p| PathBuf::from(p));
    let remove_count_string = matches.get_one::<i32>("count").cloned();

    // Ensure only one of -v, -s, or -w is selected
    let operations_selected = [authenticate.is_some(), sign.is_some(), witness.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();

    if operations_selected > 1 {
        return Err(
            "Error: You can only use one of --authenticate, --sign, or --witness independently."
                .to_string(),
        );
    }
    let mut remove_count = 1;
    if remove_count_string.is_some() {
       
        remove_count = remove_count_string.unwrap_or(1);
    }

    Ok(CliArgs {
        authenticate,
        sign,
        witness,
        file,
        remove,
        remove_count,
        verbose,
        output,
        level,
        keys_file,
    })
}

fn main() {
    dotenv::dotenv().ok();

    // Generate a random alphanumeric string
    let random_domain: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    // Check if API_DOMAIN is set
    let aqua_domain = env::var("aqua_domain").unwrap_or(random_domain);
    // let aqua_network = env::var("aqua_network").unwrap_or("sepolia".to_string());
    let verification_platform: String = env::var("verification_platform").unwrap_or("none".to_string());
    let chain: String = env::var("chain").unwrap_or("sepolia".to_string());
    let api_key = env::var("api_key").unwrap_or("".to_string());
    let keys_file_env = env::var("keys_file").unwrap_or("".to_string());

    println!("🔐 Aqua CLI v3.2 - verification_platform: {} | api_key: [{}]", 
        verification_platform, 
        if api_key.is_empty() { "not set" } else { "set" }
    );

    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });

    // validation of combined flags
    if args.authenticate.is_some() || args.sign.is_some() || args.witness.is_some() {
        if args.file.is_some() {
            eprintln!("Error: -f/--file cannot be used with -a, -s, or -w");
            std::process::exit(1);
        }
    }

    let mut keys_file: Option<PathBuf> = None;
    // attempt to read aregiument keys , if none attempt to rread from environment variables
    if args.clone().keys_file.is_none() {
        if !keys_file_env.is_empty() {
            let res = is_valid_json_file(&keys_file_env);
            if res.is_ok() {
                println!("Reading keys file from env");
                keys_file = Some(PathBuf::from(keys_file_env))
            } else {
                panic!("Error with key file provided in the env {:#?}", res.err())
            }
        }
    } else {
        println!("Reading keys file from arguments");
        keys_file = args.clone().keys_file;
    }
    // Process the arguments based on the combination
    match (
        args.clone().authenticate,
        args.clone().sign,
        args.clone().witness,
        args.clone().file.is_some(),
        args.clone().remove.is_some(),
    ) {
        (Some(verify_path), _, _, _, _) => cli_verify_chain(args, verify_path),
        (_, Some(sign_path), _, _, _) => cli_sign_chain(args, sign_path, keys_file),
        (_, _, Some(witness_path), _, _) => {
            cli_winess_chain(args.clone(), witness_path)
        }
        (_, _, _, true, _) => cli_generate_aqua_chain(args.clone(), aqua_domain),
        (_, _, _, _, true) => cli_remove_revisions_from_aqua_chain(
            args.clone(),
            args.clone()
                .remove
                .expect("aqua tree file to delete revision"),
        ),
        _ => unreachable!(
            "Unable to determin course of action **Clap ensures at least one operation is selected"
        ),
    }
}
