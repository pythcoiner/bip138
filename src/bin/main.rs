use bip138::miniscript;

use clap::{Parser, Subcommand};

use bip138::{Decrypted, EncryptedBackup, ToPayload};
use miniscript::{Descriptor, DescriptorPublicKey, descriptor::DescriptorKeyParseError};

use std::{
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug)]
pub enum CliError {
    CantConvertToDescriptor(miniscript::Error),
    CantConvertToXpub(DescriptorKeyParseError),
    EmptyDescriptor,
    CwdError(std::io::Error),
    CreateError(std::io::Error),
    OpenError(std::io::Error),
    WriteError(std::io::Error),
    ReadError(std::io::Error),
    FailedToEncrypt(bip138::Error),
    FailedToDecrypt(bip138::Error),
    Content,
    NoKeys,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::CantConvertToDescriptor(err) => {
                write!(f, "Can't convert to a descriptor: {err:?}")
            }
            CliError::CantConvertToXpub(err) => {
                write!(f, "Can't  convert to master public key: {err:?}")
            }
            CliError::EmptyDescriptor => write!(f, "Empty descriptor"),
            CliError::CwdError(err) => write!(f, "Cant find current working directiory: {err:?}"),
            CliError::CreateError(err) => write!(f, "Cannot create file: {err:?}"),
            CliError::OpenError(err) => write!(f, "Cannot open file: {err:?}"),
            CliError::WriteError(err) => write!(f, "Cannot write file: {err:?}"),
            CliError::ReadError(err) => write!(f, "Cannot read file: {err:?}"),
            CliError::FailedToEncrypt(err) => write!(f, "Cannot encrypt: {err:?}"),
            CliError::FailedToDecrypt(err) => write!(f, "Cannot decrypt: {err:?}"),
            CliError::Content => write!(f, "Decryption succeed but content is not a descriptor"),
            CliError::NoKeys => write!(f, "No decryption key found"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encrypt some descriptor
    Encrypt {
        /// Input file containing the descriptor
        #[arg(short, long)]
        file: Option<String>,

        /// Optional output to encrypted descriptor
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Decrypt an encrypted descriptor with a given xpub
    Decrypt {
        /// Input file to be decrypted
        #[arg(short, long)]
        file: Option<String>,

        /// The key containing a xpub
        #[arg(short, long)]
        key: Option<String>,

        /// Optional decrypted descriptor
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle the specific subcommand
    match &cli.command {
        Commands::Encrypt { file, output } => {
            let input_path = match file {
                Some(path) => {
                    let mut descriptor_path = PathBuf::new();
                    descriptor_path.push(path);
                    descriptor_path
                }
                None => {
                    let mut descriptor_path = env::current_dir().map_err(CliError::CwdError)?;
                    descriptor_path.push("descriptor.txt");
                    descriptor_path
                }
            };

            let output_path = match output {
                Some(path) => {
                    let mut output_path = PathBuf::new();
                    output_path.push(path);
                    output_path
                }
                None => {
                    let mut output_path = env::current_dir().map_err(CliError::CwdError)?;
                    output_path.push("descriptor.bin");
                    output_path
                }
            };

            let data = fs::read_to_string(&input_path).map_err(CliError::ReadError)?;

            // The read descritor need to be readed with a trimmed white space
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(data.trim())
                .map_err(CliError::CantConvertToDescriptor)?;

            // encrypt the descriptor
            let encrypted = EncryptedBackup::new()
                .set_payload(&descriptor)
                .map_err(CliError::FailedToEncrypt)?
                .encrypt()
                .map_err(CliError::FailedToEncrypt)?;

            for w in &encrypted.warnings {
                match w {
                    bip138::Warning::DisallowedKeyExpression(k) => {
                        eprintln!(
                            "warning: disallowed key expression excluded from encryption-key set: {k}; the cosigner holding this key cannot decrypt the backup with their key"
                        );
                    }
                    bip138::Warning::NumsKey(k) => {
                        eprintln!("warning: BIP341 NUMS key excluded from encryption-key set: {k}");
                    }
                }
            }

            // pass the byte vector to a file
            let mut output = File::create(&output_path).map_err(CliError::CreateError)?;
            output
                .write_all(&encrypted.bytes)
                .map_err(CliError::WriteError)?;
            println!("descriptor written to {output_path:?}");
        }
        Commands::Decrypt { file, key, output } => {
            let input_path = match file {
                Some(path) => {
                    let mut descriptor_path = PathBuf::new();
                    descriptor_path.push(path);
                    descriptor_path
                }
                None => {
                    let mut descriptor_path = env::current_dir().map_err(CliError::CwdError)?;
                    descriptor_path.push("descriptor.txt");
                    descriptor_path
                }
            };

            let output_path = match output {
                Some(path) => {
                    let mut output_path = PathBuf::new();
                    output_path.push(path);
                    output_path
                }
                None => {
                    let mut output_path = env::current_dir().map_err(CliError::CwdError)?;
                    output_path.push("descriptor.txt");
                    output_path
                }
            };

            let key_path = match key {
                Some(path) => {
                    let mut xpub_path = PathBuf::new();
                    xpub_path.push(path);
                    xpub_path
                }
                None => {
                    let mut xpub_path = env::current_dir().map_err(CliError::CwdError)?;
                    xpub_path.push("xpub.txt");
                    xpub_path
                }
            };
            let key = if let Ok(k) = fs::read_to_string(key_path) {
                DescriptorPublicKey::from_str(k.trim()).ok()
            } else {
                None
            };

            let data = fs::read(&input_path).map_err(CliError::ReadError)?;

            let backup = EncryptedBackup::new()
                .set_encrypted_payload(&data)
                .map_err(CliError::FailedToDecrypt)?;

            #[cfg(feature = "devices")]
            let mut keys = {
                let deriv_paths = backup.get_derivation_paths();
                bip138::signing_devices::collect_xpubs(deriv_paths).await
            };

            #[cfg(not(feature = "devices"))]
            let mut keys = vec![];

            if let Some(k) = key {
                keys.push(k);
            }

            if keys.is_empty() {
                return Err(CliError::NoKeys);
            }

            let (pks, _) = bip138::descriptor::dpks_to_derivation_keys_paths(&keys);

            let decrypted = backup
                .set_keys(pks)
                .decrypt()
                .map_err(CliError::FailedToDecrypt)?;

            let document = match decrypted.into_iter().next() {
                Some(Decrypted::Descriptor(descr)) => descr.to_string().into_bytes(),
                Some(Decrypted::DescriptorBackup(backup)) => {
                    backup.to_payload().map_err(CliError::FailedToDecrypt)?
                }
                Some(Decrypted::PolicyBackup(backup)) => {
                    backup.to_payload().map_err(CliError::FailedToDecrypt)?
                }
                _ => return Err(CliError::Content),
            };
            fs::write(&output_path, &document).map_err(CliError::WriteError)?;
            println!("descriptor written to {output_path:?}");
        }
    }
    Ok(())
}
