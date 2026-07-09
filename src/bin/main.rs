use bip138::miniscript;

use clap::{Parser, Subcommand};

use bip138::{Decrypted, EncryptedBackup, EncryptedMetadata, ToPayload};
#[cfg(feature = "devices")]
use miniscript::bitcoin::{Network, bip32::DerivationPath, secp256k1::PublicKey};
use miniscript::{Descriptor, DescriptorPublicKey, descriptor::DescriptorKeyParseError};

use std::{
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

#[cfg(feature = "devices")]
const HARDENED_BIT: u32 = 1 << 31;

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
    FailedToInspect(bip138::Error),
    JsonError(serde_json::Error),
    #[cfg(feature = "devices")]
    FailedToFetchXpub(bip138::signing_devices::FetchFailed),
    #[cfg(feature = "devices")]
    InvalidDeviceDerivationPath(String),
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
            CliError::FailedToInspect(err) => write!(f, "Cannot inspect: {err:?}"),
            CliError::JsonError(err) => write!(f, "Cannot format JSON: {err:?}"),
            #[cfg(feature = "devices")]
            CliError::FailedToFetchXpub(err) => write!(f, "Cannot fetch xpub: {err}"),
            #[cfg(feature = "devices")]
            CliError::InvalidDeviceDerivationPath(err) => {
                write!(f, "Invalid device derivation path: {err}")
            }
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

        /// Add a signing-device key to the encryption key set
        #[cfg(feature = "devices")]
        #[arg(long, num_args = 0..=1, value_name = "PATH")]
        device: Option<Option<String>>,
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

        /// Fetch keys from a testnet signing device
        #[cfg(feature = "devices")]
        #[arg(long)]
        testnet: bool,

        /// Prompt on fallible signing-device paths
        #[cfg(feature = "devices")]
        #[arg(long)]
        prompt: bool,
    },

    /// Inspect an encrypted descriptor without decrypting it
    Inspect {
        /// Input file to inspect
        #[arg(short, long)]
        file: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle the specific subcommand
    match &cli.command {
        Commands::Encrypt {
            file,
            output,
            #[cfg(feature = "devices")]
            device,
        } => {
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
            let backup = EncryptedBackup::new()
                .set_payload(&descriptor)
                .map_err(CliError::FailedToEncrypt)?;
            #[cfg(feature = "devices")]
            let mut used_deriv_paths = backup.get_derivation_paths();
            #[cfg(not(feature = "devices"))]
            let used_deriv_paths = backup.get_derivation_paths();

            #[cfg(feature = "devices")]
            let backup = match device {
                Some(path) => {
                    let mut deriv_paths = backup.get_derivation_paths();
                    let mut keys = backup.get_keys();
                    let path = device_path(path)?;
                    let (key, device_path) =
                        fetch_encryption_device_key(deriv_paths.clone(), path).await?;
                    if !used_deriv_paths.contains(&device_path) {
                        used_deriv_paths.push(device_path.clone());
                    }
                    if !deriv_paths.contains(&device_path) {
                        deriv_paths.push(device_path);
                    }
                    keys.push(key);
                    backup.set_derivation_paths(deriv_paths).set_keys(keys)
                }
                None => backup,
            };

            for path in used_deriv_paths {
                println!("using derivation path {path}");
            }

            let encrypted = backup.encrypt().map_err(CliError::FailedToEncrypt)?;

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
        Commands::Decrypt {
            file,
            key,
            output,
            #[cfg(feature = "devices")]
            testnet,
            #[cfg(feature = "devices")]
            prompt,
        } => {
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
            let document = {
                use std::sync::{
                    Arc,
                    atomic::{AtomicBool, Ordering},
                    mpsc,
                };

                let deriv_paths = backup.get_derivation_paths();
                let (key_tx, key_rx) = mpsc::channel::<PublicKey>();
                let (document_tx, document_rx) = mpsc::channel::<Result<Vec<u8>, CliError>>();
                let stop = Arc::new(AtomicBool::new(false));

                let decrypt_backup = backup.clone();
                let decrypt_stop = stop.clone();
                let decrypt_document_tx = document_tx.clone();
                let _ = std::thread::spawn(move || {
                    let mut saw_key = false;
                    for key in key_rx {
                        if decrypt_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        saw_key = true;
                        match decrypt_backup.clone().set_keys(vec![key]).decrypt() {
                            Ok(decrypted) => {
                                decrypt_stop.store(true, Ordering::SeqCst);
                                let _ = decrypt_document_tx.send(decrypted_to_document(decrypted));
                                return;
                            }
                            Err(bip138::Error::WrongKey | bip138::Error::NoKey) => {}
                            Err(err) => {
                                decrypt_stop.store(true, Ordering::SeqCst);
                                let _ =
                                    decrypt_document_tx.send(Err(CliError::FailedToDecrypt(err)));
                                return;
                            }
                        }
                    }
                    let err = if saw_key {
                        CliError::FailedToDecrypt(bip138::Error::WrongKey)
                    } else {
                        CliError::NoKeys
                    };
                    if !decrypt_stop.load(Ordering::SeqCst) {
                        let _ = decrypt_document_tx.send(Err(err));
                    }
                });

                if let Some(k) = key {
                    let (pks, _) = bip138::descriptor::dpks_to_derivation_keys_paths(&vec![k]);
                    if pks.is_empty() || key_tx.send(pks[0]).is_err() {
                        stop.store(true, Ordering::SeqCst);
                    }
                }

                let fetch_stop = stop.clone();
                let fetch_key_tx = key_tx.clone();
                let fetch_document_tx = document_tx.clone();
                let network = if *testnet {
                    Network::Testnet
                } else {
                    Network::Bitcoin
                };
                let fetch = async move {
                    if !fetch_stop.load(Ordering::SeqCst) {
                        let key_tx = fetch_key_tx.clone();
                        let send_stop = fetch_stop.clone();
                        let stop = fetch_stop.clone();
                        match bip138::signing_devices::XpubCollector::new(deriv_paths, network)
                            .ordering([48, 84, 86])
                            .prompt(*prompt)
                            .collect_until(
                                |msg| {
                                    println!("{msg}");
                                    if let Err(err) = std::io::stdout().flush() {
                                        eprintln!("warning: cannot flush stdout: {err:?}");
                                    }
                                },
                                move |_, xpub| {
                                    if key_tx.send(xpub.public_key).is_err() {
                                        send_stop.store(true, Ordering::SeqCst);
                                    }
                                },
                                move || stop.load(Ordering::SeqCst),
                            )
                            .await
                        {
                            Ok(xpubs) => {
                                for warning in xpubs.warnings {
                                    print_xpub_warning(warning);
                                }
                            }
                            Err(err) => {
                                fetch_stop.store(true, Ordering::SeqCst);
                                let _ =
                                    fetch_document_tx.send(Err(CliError::FailedToFetchXpub(err)));
                            }
                        }
                    }
                };

                drop(key_tx);
                drop(document_tx);
                let document = tokio::task::spawn_blocking(move || document_rx.recv());
                tokio::pin!(document);
                tokio::pin!(fetch);
                tokio::select! {
                    document = &mut document => {
                        stop.store(true, Ordering::SeqCst);
                        document
                            .map_err(|_| CliError::NoKeys)?
                            .map_err(|_| CliError::NoKeys)??
                    }
                    _ = &mut fetch => {
                        document
                            .await
                            .map_err(|_| CliError::NoKeys)?
                            .map_err(|_| CliError::NoKeys)??
                    }
                }
            };

            #[cfg(not(feature = "devices"))]
            let document = {
                let Some(k) = key else {
                    return Err(CliError::NoKeys);
                };
                let (pks, _) = bip138::descriptor::dpks_to_derivation_keys_paths(&vec![k]);
                let decrypted = backup
                    .set_keys(pks)
                    .decrypt()
                    .map_err(CliError::FailedToDecrypt)?;
                match decrypted.into_iter().next() {
                    Some(Decrypted::Descriptor(descr)) => descr.to_string().into_bytes(),
                    Some(Decrypted::DescriptorBackup(backup)) => {
                        backup.to_payload().map_err(CliError::FailedToDecrypt)?
                    }
                    Some(Decrypted::PolicyBackup(backup)) => {
                        backup.to_payload().map_err(CliError::FailedToDecrypt)?
                    }
                    _ => return Err(CliError::Content),
                }
            };
            fs::write(&output_path, &document).map_err(CliError::WriteError)?;
            println!("descriptor written to {output_path:?}");
        }
        Commands::Inspect { file } => {
            let input_path = match file {
                Some(path) => {
                    let mut descriptor_path = PathBuf::new();
                    descriptor_path.push(path);
                    descriptor_path
                }
                None => {
                    let mut descriptor_path = env::current_dir().map_err(CliError::CwdError)?;
                    descriptor_path.push("descriptor.bin");
                    descriptor_path
                }
            };

            let data = fs::read(&input_path).map_err(CliError::ReadError)?;
            let metadata = EncryptedMetadata::from_encrypted_payload(&data)
                .map_err(CliError::FailedToInspect)?;
            let derivation_paths: Vec<String> = metadata
                .derivation_paths
                .iter()
                .map(|path| path.to_string())
                .collect();
            let individual_secrets: Vec<String> = metadata
                .individual_secrets
                .iter()
                .map(|secret| hex_encode(secret))
                .collect();
            let json = serde_json::json!({
                "version": format!("{:?}", metadata.version),
                "encryption": format!("{:?}", metadata.encryption),
                "derivation_paths": derivation_paths,
                "individual_secrets": individual_secrets,
                "nonce": hex_encode(&metadata.nonce),
                "ciphertext_bytes": metadata.ciphertext_lens,
            });
            let json = serde_json::to_string_pretty(&json).map_err(CliError::JsonError)?;
            println!("{json}");
        }
    }
    Ok(())
}

#[cfg(feature = "devices")]
async fn fetch_encryption_device_key(
    deriv_paths: Vec<DerivationPath>,
    path: Option<DerivationPath>,
) -> Result<(PublicKey, DerivationPath), CliError> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    let network = path
        .as_ref()
        .map(|path| device_network(core::slice::from_ref(path)))
        .unwrap_or_else(|| device_network(&deriv_paths));
    if let Some(path) = path {
        return bip138::signing_devices::fetch_first_xpub_at_path(path.clone(), network, |msg| {
            println!("{msg}");
            if let Err(err) = std::io::stdout().flush() {
                eprintln!("warning: cannot flush stdout: {err:?}");
            }
        })
        .await
        .map_err(CliError::FailedToFetchXpub)?
        .map(|xpub| (xpub.public_key, path))
        .ok_or(CliError::NoKeys);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let (key_tx, key_rx) = mpsc::channel::<(PublicKey, DerivationPath)>();

    let send_stop = stop.clone();
    let read_stop = stop.clone();
    let xpubs = bip138::signing_devices::XpubCollector::new(deriv_paths, network)
        .ordering([48, 84, 86])
        .collect_until(
            |msg| {
                println!("{msg}");
                if let Err(err) = std::io::stdout().flush() {
                    eprintln!("warning: cannot flush stdout: {err:?}");
                }
            },
            move |path, xpub| {
                if key_tx.send((xpub.public_key, path)).is_ok() {
                    send_stop.store(true, Ordering::SeqCst);
                }
            },
            move || read_stop.load(Ordering::SeqCst),
        )
        .await
        .map_err(CliError::FailedToFetchXpub)?;

    for warning in xpubs.warnings {
        print_xpub_warning(warning);
    }

    key_rx.try_recv().map_err(|_| CliError::NoKeys)
}

#[cfg(feature = "devices")]
fn device_path(path: &Option<String>) -> Result<Option<DerivationPath>, CliError> {
    path.as_ref()
        .map(|path| {
            DerivationPath::from_str(path.trim())
                .map_err(|err| CliError::InvalidDeviceDerivationPath(err.to_string()))
        })
        .transpose()
}

#[cfg(feature = "devices")]
fn device_network(deriv_paths: &[DerivationPath]) -> Network {
    if deriv_paths
        .iter()
        .any(|path| path.to_u32_vec().get(1).map(|index| index & !HARDENED_BIT) == Some(1))
    {
        Network::Testnet
    } else {
        Network::Bitcoin
    }
}

#[cfg(feature = "devices")]
fn decrypted_to_document(decrypted: Vec<Decrypted>) -> Result<Vec<u8>, CliError> {
    match decrypted.into_iter().next() {
        Some(Decrypted::Descriptor(descr)) => Ok(descr.to_string().into_bytes()),
        Some(Decrypted::DescriptorBackup(backup)) => {
            backup.to_payload().map_err(CliError::FailedToDecrypt)
        }
        Some(Decrypted::PolicyBackup(backup)) => {
            backup.to_payload().map_err(CliError::FailedToDecrypt)
        }
        _ => Err(CliError::Content),
    }
}

#[cfg(feature = "devices")]
fn print_xpub_warning(warning: bip138::signing_devices::XpubWarning) {
    match warning {
        bip138::signing_devices::XpubWarning::Failed(err) => {
            eprintln!("warning: {err}");
        }
        bip138::signing_devices::XpubWarning::TimedOut { device, path } => {
            eprintln!("warning: timed out fetching xpub from {device} at {path}");
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to string must not fail");
    }
    out
}
