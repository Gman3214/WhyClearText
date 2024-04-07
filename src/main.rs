use std::ffi::c_void;
use std::fs::{self, File};
use std::io::Write;
use std::fs::OpenOptions;
use std::ops::Index;
use std::path::Path;
use std::collections::HashMap;
use std::process::exit;
use std::env::{self, Args};
use std::ptr::null;
use regex::Regex;
use walkdir::WalkDir;

fn calculate_entropy(s: &str) -> f64 {
    let mut counts = HashMap::new();
    let total = s.len() as f64;

    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }

    counts.iter().fold(0.0, |acc, (_, &count)| {
        let probability = count as f64 / total;
        acc - (probability * probability.log2())
    })
}

fn has_high_entropy(s: &str) -> bool {
    if let Some(pos) = s.find('=') {
        let (_, right) = s.split_at(pos + 1);
        let entropy = calculate_entropy(right.trim());
        entropy > 2.9 
    } else {
        false
    }
}

fn PrintHelp () {
    println!("help");
    exit(0);
}

fn CheckPath (path : &str , is_verbose : bool) -> Vec<String> {

    if !Path::new(&path).exists(){
        println!("Path doesnt exist");
        exit(0);
    }

    let mut file_vec: Vec<String> = Vec::new();

    let mut sensitive_info: Vec<String> = Vec::new();

    println!("Starting Check from : {}", &path);
    println!("Fetching all files.");
    for entry in WalkDir::new(path).min_depth(1).into_iter().filter_map(|e| e.ok()){
        if entry.file_type().is_file() {
            file_vec.push(entry.path().to_str().unwrap().to_string())
        }
    }

    println!("Found {} Files", file_vec.len());
    println!("Starting Filtering Process..");
    
    // let file_extension_filter = Regex::new(r"\.(txt|docx?|xlsx?|pptx?|odt|ods|odp|pdf|key|pub|pem|p12|pfx|crt|cer|cfg|config|ini|json|yaml|yml|xml|sql|db|sqlite|mdb|accdb|kdbx|env|properties|htpasswd|log|bak|backup|csv|rtf|md|markdown|conf|toml|gpg|asc|jks|der|sh|bat|ps1|vbs|rb|py|php|java|class|cpp|c|h|hpp|js|ts|go|lua|pl|groovy|scala|swift|sass|scss|less|css|htm|html|jsp|asp|aspx|cgi|apk|ipa|war|jar|ear|sqlitedb|sqlitedb-wal|sqlitedb-shm|pst|ost|msg|eml|mlx|notebook|nb|sav|spv|por|dta|sas7bdat|sas7bcat|xlsb|xlsm|pptm|dotx|dotm|docm|xlam|prn|dif|slk|xla|xlw|xlr|xlshtml|xlthtml|dbf|mdbhtml|accdbhtml|qpj|mdf|ldf|bak|trn|dbx|mny|qdf|qel|qph|qsd)$").unwrap();
    let file_extension_filter = Regex::new(r"\.(txt|docx?|xlsx?|pptx?|odt|ods|odp|pdf|key|pub|pem|p12|pfx|crt|cer|cfg|config|ini|json|yaml|yml|xml|sql|db|sqlite|mdb|accdb|kdbx|env|properties|htpasswd|log|bak|backup|csv|rtf|md|markdown|conf|toml|gpg|asc|jks|der|sh|bat|ps1|vbs|rb|php|md|java|h|go|groovy|sqlitedb|sqlitedb-wal|sqlitedb-shm|pst|ost|msg|eml|mlx|notebook|nb|sav|spv|por|dta|sas7bdat|sas7bcat|xlsb|xlsm|pptm|dotx|dotm|docm|xlam|prn|dif|slk|xla|xlw|xlr|xlshtml|xlthtml|dbf|mdbhtml|accdbhtml|qpj|mdf|ldf|bak|trn|dbx|mny|qdf|qel|qph|qsd)$").unwrap();
    
    file_vec.retain(|path| file_extension_filter.is_match(path));
    
    
    println!("Found {} relevant files...", file_vec.len());
    
    println!("Checking File Permissions");

    file_vec.retain(|path| File::open(path).is_ok());
    
    println!("You have Permission to {} relevant files...", file_vec.len());
    
    // let sensitive_keywords = Regex::new(r"\b(?:password|passwd|pwd|passphrase|passcode|username|user_name|user_id|login|logon|userlogin|admin|administrator|access_token|refresh_token|auth_token|bearer_token|api_key|secret|secret_key|private_key|public_key|encryption_key|cert|certificate|pin|id|identification|serial|serial_no|license_key|auth|bearer|session|session_id|session_token|token|config|configuration|credentials|cred|ssh|vpn_key|oauth|saml|signature|symmetric_key|asymmetric_key|salt|hash|encrypted|decrypted|secure|security|cipher|algorithm|auth_code|recovery_code|unlock_code|keypair|keystore|truststore|access_code|authenticator|challenge|response|otp|two_factor|2fa|tfa|backup_code|root|sudo|privilege|confidential|sensitive)\b").unwrap();
    let sensitive_keywords = Regex::new(r"(password|passwd|pwd|passphrase|secret|private_key|workspace\_key)\s*(==|===|eq|ne|<-|=>|<=|>=|:=|=|:)\s*\S+").unwrap();
    //let sensitive_keywords = Regex::new(r"(password|passwd|pwd|passphrase|secret|private_key|workspace\_key)\s*[:=][>]{0,1}\s*\S+").unwrap();

    file_vec.retain(|path| {
        match fs::read(path) {
            Ok(contents) => {  

                let string_contents = String::from_utf8_lossy(&contents).to_string();

                let matches: Vec<_> = sensitive_keywords.find_iter(&string_contents.as_str()).collect();
                
                if matches.is_empty(){
                    return false
                }

                let mut pass_test = false;
                
                for str in matches{
                    if has_high_entropy(str.as_str()){
                        pass_test = true;
                        println!("{} found in file : {}", path, str.as_str());
                        sensitive_info.push( "".to_string() + &path.to_string() + &" found in file : ".to_string() +  &str.as_str().to_string());
                    }
                }

                pass_test
                
            },
            Err(_) => false,
        }
    });

    println!("found {} files with sensitive keywords...", file_vec.len());
    
    {sensitive_info}

}

fn main() {

    let args: Vec<String> = env::args().collect();

    let mut sensitive_info: Vec<String> = Vec::new();
    
    let mut verbose : bool = false;

    let mut output_path = "./sensitiveInfo.txt";

    for index in 0..args.len() {

        match args[index].as_str() {

            "-h" => PrintHelp(),
            "-v" => verbose = true,
            "-o" => {
                if index + 1 < args.len(){
                    output_path = args[index + 1 ].as_str();
                }
            }
            &_ => {}
            
        }    
    }

    for index in 1..args.len() {
        if args[index] == "-c"{
            if index + 1 < args.len(){

                match args[index + 1].as_str() {
                    "all" | "All" => {sensitive_info = CheckPath("/", verbose)},
                    _ => {sensitive_info = CheckPath(args[index + 1].as_str(), verbose)},
                }
                break;
            }

            
        }else {
            PrintHelp();
        }      
    }

    if !sensitive_info.is_empty(){

        println!("saving results");
    
        fs::write(output_path, "").expect("failed to write data");
      
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open("./sensitiveInfo.txt")
            .unwrap();
    
        for info in sensitive_info{
    
            if let Err(e) = writeln!(file, "{}", info) {
                eprintln!("Couldn't write to file: {}", e);
                exit(0)
            }
        }
    }

}

