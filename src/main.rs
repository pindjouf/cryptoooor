use cryptoooor::*;
use config::*;
use patharg::InputArg;
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use indicatif::ProgressBar;
use std::thread::sleep;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(required = true)]
    file: InputArg,

    #[arg(short, long)]
    decrypt: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let bar = ProgressBar::new(100);
    let config_path = get_config_path().expect("Couldn't find your config");
    let config = load_config().expect("Couldn't load your config");

    let key = if config.key { config.key } else { derive_key(config.hash, config.salt) };

    let file_path = args.file.to_string();

    match fs::read(&file_path) {
        Ok(content) => {
            match args.decrypt {
                true => {
                    println!("Decrypting your file...");
                    for _ in 0..100 {
                        bar.inc(1);
                        sleep(Duration::from_millis(10));
                    }
                    let encrypted_content = fs::read(&file_path)?;
                    let decrypted_content = decrypt(encrypted_content, &key)?;

                    let path = Path::new(&file_path);
                    let mut output_path = PathBuf::from(path);
                    output_path.set_extension("dec");

                    fs::write(output_path, decrypted_content)?;
                    bar.finish();

                    println!("File successfully decrypted!");
                },
                false => {
                    println!("Encrypting your file...");
                    for _ in 0..100 {
                        bar.inc(1);
                        sleep(Duration::from_millis(10));
                    }
                    let (ciphertext, nonce) = encrypt(content.into(), &key).map_err(|e| format!("Encryption failed: {}", e))?;

                    let path = Path::new(&file_path);
                    let mut output_path = PathBuf::from(path);
                    output_path.set_extension("bin");

                    let nonce_vec: Vec<u8> = nonce.as_slice().to_vec();

                    let encrypted_data = (ciphertext, nonce_vec);

                    fs::write(output_path, bincode::serialize(&encrypted_data)?)?;
                    bar.finish();

                    println!("File successfully encrypted!");
                },
            }
        }
        Err(e) => println!("Error reading file: {}", e),
    }
    Ok(())
}
