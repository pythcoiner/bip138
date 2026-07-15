use bip138::miniscript;

use clap::{Parser, Subcommand};

use bip138::{Bip138, Decrypted, EncryptedBackup, EncryptedMetadata, ToPayload};
#[cfg(feature = "devices")]
use miniscript::bitcoin::Network;
use miniscript::bitcoin::bip32::DerivationPath;
#[cfg(feature = "devices")]
use miniscript::bitcoin::bip32::Fingerprint;
use miniscript::bitcoin::secp256k1::PublicKey;
use miniscript::{Descriptor, DescriptorPublicKey, descriptor::DescriptorKeyParseError};

use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
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
    WrapKeys,
    DeviceWithKeys,
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
            CliError::WrapKeys => write!(f, "Invalid wrap keys file"),
            CliError::DeviceWithKeys => write!(f, "Cannot use --device with --keys"),
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

        /// Message to add before the descriptor payload
        #[arg(long)]
        msg: Option<String>,

        /// File listing outer-to-inner wrapping key levels
        ///
        /// One level per line, outermost first: each level encrypts the one
        /// below it, and the last line encrypts the descriptor itself.
        ///
        /// A line is one key, several keys separated by `|`, or a note and its
        /// keys separated by `||`:
        ///
        ///     [48bfdc46/48h/1h/10h/2h]tpubDF6MC...
        ///     [c658b283/48h/1h/10h/2h]tpubDFHe6... | [748f7513/48h/1h/10h/2h]tpubDEwiF...
        ///     backup 2026 || [c658b283/48h/1h/10h/2h]tpubDFHe6...
        ///
        /// Each key must carry its origin, as `[fingerprint/derivation]xpub`,
        /// and any one key of a level decrypts that level.
        ///
        /// A note is stored encrypted at its level and shows up when that level
        /// is decrypted. Blank lines and lines starting with `#` are ignored.
        /// Cannot be used with --device.
        ///
        /// Example:
        ///
        ///     # outer level, either signer can unwrap it
        ///     backup 2026 || [c658b283/48h/1h/10h/2h]tpubDFHe6... | [748f7513/48h/1h/10h/2h]tpubDEwiF...
        ///     # inner level, holds the descriptor
        ///     [48bfdc46/48h/1h/10h/2h]tpubDF6MC...
        #[arg(long, verbatim_doc_comment)]
        keys: Option<String>,

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

        /// File containing a xpub
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

    /// Fetch an xpub from a signing device at a derivation path
    #[cfg(feature = "devices")]
    Fetch {
        /// Derivation path to fetch
        derivation: String,

        /// File to append the xpub to
        #[arg(short, long)]
        file: Option<String>,

        /// Fetch from a testnet signing device
        #[arg(long)]
        testnet: bool,
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
            msg,
            keys,
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
            let wrap_levels = match keys {
                Some(path) => {
                    parse_wrap_keys(&fs::read_to_string(path).map_err(CliError::ReadError)?)?
                }
                None => vec![],
            };

            // The read descritor need to be readed with a trimmed white space
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(data.trim())
                .map_err(CliError::CantConvertToDescriptor)?;

            if !wrap_levels.is_empty() {
                #[cfg(feature = "devices")]
                if device.is_some() {
                    return Err(CliError::DeviceWithKeys);
                }

                let Some((inner_level, outer_levels)) = wrap_levels.split_last() else {
                    return Err(CliError::WrapKeys);
                };
                let mut encrypted =
                    encrypt_descriptor_level(inner_level, msg.as_ref(), &descriptor)?;
                for level in outer_levels.iter().rev() {
                    encrypted = encrypt_wrap_level(level, encrypted.bytes)?;
                }
                let mut output = File::create(&output_path).map_err(CliError::CreateError)?;
                output
                    .write_all(&encrypted.bytes)
                    .map_err(CliError::WriteError)?;
                println!("descriptor written to {output_path:?}");
                return Ok(());
            }

            let backup = descriptor_backup(msg.as_ref(), &descriptor)?;
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
            let warnings = encrypted.warnings.clone();

            for w in &warnings {
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

            let key_given = key.is_some();
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
            let key = read_key_file(&key_path, key_given)?;

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
                    let pk = bip138::descriptor::dpk_to_root_pk(&k)
                        .map_err(CliError::FailedToDecrypt)?;
                    if key_tx.send(pk).is_err() {
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
                let pk =
                    bip138::descriptor::dpk_to_root_pk(&k).map_err(CliError::FailedToDecrypt)?;
                let decrypted = backup
                    .set_keys(vec![pk])
                    .decrypt()
                    .map_err(CliError::FailedToDecrypt)?;
                decrypted_to_document(decrypted)?
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
        #[cfg(feature = "devices")]
        Commands::Fetch {
            derivation,
            file,
            testnet,
        } => {
            let path = DerivationPath::from_str(derivation.trim())
                .map_err(|err| CliError::InvalidDeviceDerivationPath(err.to_string()))?;
            let network = if *testnet {
                Network::Testnet
            } else {
                device_network(core::slice::from_ref(&path))
            };
            let fetched = bip138::signing_devices::fetch_first_origin_xpub_at_path(
                path.clone(),
                network,
                fetch_log_to_stderr,
            )
            .await
            .map_err(CliError::FailedToFetchXpub)?
            .ok_or(CliError::NoKeys)?;

            let xpub = origin_xpub(fetched.fingerprint, &path, &fetched.xpub);
            match file {
                Some(path) => append_line(path, &xpub)?,
                None => println!("{xpub}"),
            }
        }
    }
    Ok(())
}

#[cfg(feature = "devices")]
fn fetch_log_to_stderr(msg: String) {
    eprintln!("{msg}");
    if let Err(err) = std::io::stderr().flush() {
        eprintln!("warning: cannot flush stderr: {err:?}");
    }
}

/// Read the decryption xpub from `path`. A missing file is an error only when the user
/// asked for that path: the default one is a convenience, and falls back to a device.
fn read_key_file(path: &Path, requested: bool) -> Result<Option<DescriptorPublicKey>, CliError> {
    match fs::read_to_string(path) {
        Ok(data) => Ok(Some(
            DescriptorPublicKey::from_str(data.trim()).map_err(CliError::CantConvertToXpub)?,
        )),
        Err(err) if requested => Err(CliError::ReadError(err)),
        Err(_) => Ok(None),
    }
}

#[cfg(feature = "devices")]
fn append_line(path: &str, line: &str) -> Result<(), CliError> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(CliError::OpenError)?;
    writeln!(file, "{line}").map_err(CliError::WriteError)
}

#[cfg(feature = "devices")]
fn origin_xpub(
    fingerprint: Fingerprint,
    path: &DerivationPath,
    xpub: &miniscript::bitcoin::bip32::Xpub,
) -> String {
    format!("[{fingerprint}/{path}]{xpub}")
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

fn decrypted_to_document(decrypted: Vec<Decrypted>) -> Result<Vec<u8>, CliError> {
    let mut document = Vec::new();
    for decrypted in decrypted {
        if !document.is_empty() {
            document.push(b'\n');
        }
        document.extend(decrypted_to_bytes(decrypted)?);
    }
    Ok(document)
}

fn decrypted_to_bytes(decrypted: Decrypted) -> Result<Vec<u8>, CliError> {
    match decrypted {
        Decrypted::Descriptor(descr) => Ok(descr.to_string().into_bytes()),
        Decrypted::DescriptorBackup(backup) => {
            backup.to_payload().map_err(CliError::FailedToDecrypt)
        }
        Decrypted::PolicyBackup(backup) => backup.to_payload().map_err(CliError::FailedToDecrypt),
        Decrypted::String(msg) => Ok(msg.into_bytes()),
        Decrypted::Bip138(bytes) => Ok(bytes),
        _ => Err(CliError::Content),
    }
}

fn descriptor_backup(
    msg: Option<&String>,
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<EncryptedBackup, CliError> {
    match msg {
        Some(msg) => {
            let payloads: [&dyn ToPayload; 2] = [msg, descriptor];
            EncryptedBackup::new()
                .set_payloads(&payloads)
                .map_err(CliError::FailedToEncrypt)
        }
        None => EncryptedBackup::new()
            .set_payload(descriptor)
            .map_err(CliError::FailedToEncrypt),
    }
}

#[derive(Debug)]
struct WrapLevel {
    msg: Option<String>,
    keys: Vec<DescriptorPublicKey>,
}

fn parse_wrap_keys(data: &str) -> Result<Vec<WrapLevel>, CliError> {
    let mut levels = vec![];
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (msg, keys) = match line.split_once("||") {
            Some((msg, keys)) => {
                let msg = msg.trim();
                let msg = (!msg.is_empty()).then(|| msg.to_string());
                (msg, keys)
            }
            None => (None, line),
        };
        let keys = keys
            .split('|')
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .map(|key| {
                let key =
                    DescriptorPublicKey::from_str(key).map_err(CliError::CantConvertToXpub)?;
                key_has_origin(&key)
                    .then_some(key)
                    .ok_or(CliError::WrapKeys)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err(CliError::WrapKeys);
        }
        levels.push(WrapLevel { msg, keys });
    }
    Ok(levels)
}

fn key_has_origin(key: &DescriptorPublicKey) -> bool {
    match key {
        DescriptorPublicKey::XPub(key) => key.origin.is_some(),
        DescriptorPublicKey::MultiXPub(key) => key.origin.is_some(),
        DescriptorPublicKey::Single(_) => false,
    }
}

fn encrypt_descriptor_level(
    level: &WrapLevel,
    msg: Option<&String>,
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<bip138::Encrypted, CliError> {
    let mut payloads: Vec<&dyn ToPayload> = vec![];
    if let Some(msg) = &level.msg {
        payloads.push(msg);
    }
    if let Some(msg) = msg {
        payloads.push(msg);
    }
    payloads.push(descriptor);
    encrypt_to_level_keys(level, &payloads)
}

fn encrypt_wrap_level(level: &WrapLevel, bytes: Vec<u8>) -> Result<bip138::Encrypted, CliError> {
    let bip138 = Bip138(bytes);
    let mut payloads: Vec<&dyn ToPayload> = vec![];
    if let Some(msg) = &level.msg {
        payloads.push(msg);
    }
    payloads.push(&bip138);
    encrypt_to_level_keys(level, &payloads)
}

fn encrypt_to_level_keys(
    level: &WrapLevel,
    payloads: &[&dyn ToPayload],
) -> Result<bip138::Encrypted, CliError> {
    let keys = wrap_level_public_keys(level);
    let paths = wrap_level_derivation_paths(level);
    if keys.is_empty() {
        return Err(CliError::NoKeys);
    }
    EncryptedBackup::new()
        .set_payloads(&payloads)
        .map_err(CliError::FailedToEncrypt)?
        .set_derivation_paths(paths)
        .set_keys(keys)
        .encrypt()
        .map_err(CliError::FailedToEncrypt)
}

fn wrap_level_public_keys(level: &WrapLevel) -> Vec<PublicKey> {
    let mut keys = BTreeSet::new();
    for key in &level.keys {
        if let Ok(key) = bip138::descriptor::dpk_to_pk(key) {
            keys.insert(key);
            continue;
        }
        match key {
            DescriptorPublicKey::XPub(key) => {
                keys.insert(key.xkey.public_key);
            }
            DescriptorPublicKey::MultiXPub(key) => {
                keys.insert(key.xkey.public_key);
            }
            DescriptorPublicKey::Single(_) => {}
        }
    }
    keys.into_iter().collect()
}

fn wrap_level_derivation_paths(level: &WrapLevel) -> Vec<DerivationPath> {
    let mut paths = BTreeSet::new();
    for key in &level.keys {
        match key {
            DescriptorPublicKey::XPub(key) => {
                if let Some((_, path)) = &key.origin {
                    paths.insert(path.clone());
                }
            }
            DescriptorPublicKey::MultiXPub(key) => {
                if let Some((_, path)) = &key.origin {
                    paths.insert(path.clone());
                }
            }
            DescriptorPublicKey::Single(_) => {}
        }
    }
    paths.into_iter().collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "[6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt/<0;1>/*";
    const OTHER_KEY: &str = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*";
    const BARE_TPUB: &str = "tpubDC5FSnBiZDMmkoat4aZFfbJdEthnPqJ1jXZcKWJNKC4yJanLA55dRW5qKJRRvAo1SwaXeUx2ayUQyVJ6eCbABbBB8Wn3T7dAuVJRnZgntVC";

    #[test]
    fn decrypted_to_document_joins_payloads_with_newline() {
        let document = decrypted_to_document(vec![
            Decrypted::String("first".to_string()),
            Decrypted::String("second".to_string()),
        ])
        .unwrap();

        assert_eq!(document, b"first\nsecond");
    }

    #[test]
    fn decrypted_to_document_outputs_bip138_bytes() {
        let document = decrypted_to_document(vec![
            Decrypted::String("next".to_string()),
            Decrypted::Bip138(vec![1, 2, 3]),
        ])
        .unwrap();

        assert_eq!(document, b"next\n\x01\x02\x03");
    }

    #[test]
    fn parse_wrap_keys_skips_empty_and_comment_lines() {
        let levels =
            parse_wrap_keys(&format!("\n# comment\nouter || {KEY}\n|| {KEY} | {KEY}\n")).unwrap();

        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0].msg, Some("outer".to_string()));
        assert_eq!(levels[0].keys.len(), 1);
        assert_eq!(levels[1].msg, None);
        assert_eq!(levels[1].keys.len(), 2);
    }

    #[test]
    fn parse_wrap_keys_rejects_line_without_keys() {
        let err = parse_wrap_keys("message || ").unwrap_err();

        assert!(matches!(err, CliError::WrapKeys));
    }

    #[test]
    fn parse_wrap_keys_rejects_xpub_without_origin() {
        let err = parse_wrap_keys(&format!("Alice || {BARE_TPUB}")).unwrap_err();

        assert!(matches!(err, CliError::WrapKeys));
    }

    #[cfg(feature = "devices")]
    #[test]
    fn origin_xpub_prefixes_fingerprint_and_path() {
        let xpub = miniscript::bitcoin::bip32::Xpub::from_str(BARE_TPUB).unwrap();
        let path = DerivationPath::from_str("48h/1h/0h").unwrap();
        let fingerprint = Fingerprint::from_str("aabbccdd").unwrap();

        assert_eq!(
            origin_xpub(fingerprint, &path, &xpub),
            format!("[aabbccdd/48'/1'/0']{BARE_TPUB}")
        );
    }

    #[test]
    fn encrypt_descriptor_level_uses_file_keys_only() {
        let level = WrapLevel {
            msg: None,
            keys: vec![DescriptorPublicKey::from_str(KEY).unwrap()],
        };
        let descriptor =
            Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({OTHER_KEY})")).unwrap();

        let encrypted = encrypt_descriptor_level(&level, None, &descriptor).unwrap();
        let file_keys = wrap_level_public_keys(&level);
        let descriptor_key = DescriptorPublicKey::from_str(OTHER_KEY).unwrap();
        let (descriptor_keys, _) =
            bip138::descriptor::dpks_to_derivation_keys_paths(&vec![descriptor_key]);

        EncryptedBackup::new()
            .set_encrypted_payload(&encrypted.bytes)
            .unwrap()
            .set_keys(file_keys)
            .decrypt()
            .unwrap();
        let err = EncryptedBackup::new()
            .set_encrypted_payload(&encrypted.bytes)
            .unwrap()
            .set_keys(descriptor_keys)
            .decrypt()
            .unwrap_err();

        assert_eq!(err, bip138::Error::WrongKey);
    }

    #[test]
    fn encrypt_level_stores_keys_file_origin_paths() {
        let key = format!("[748f7513/48'/1'/0']{BARE_TPUB}");
        let level = WrapLevel {
            msg: None,
            keys: vec![DescriptorPublicKey::from_str(&key).unwrap()],
        };
        let descriptor =
            Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({OTHER_KEY})")).unwrap();

        let encrypted = encrypt_descriptor_level(&level, None, &descriptor).unwrap();
        let metadata = EncryptedMetadata::from_encrypted_payload(&encrypted.bytes).unwrap();

        assert_eq!(
            metadata.derivation_paths,
            vec![DerivationPath::from_str("48'/1'/0'").unwrap()]
        );
    }

    #[test]
    fn read_key_file_reads_key() {
        let path = env::temp_dir().join(format!("bip138-read-key-{}.txt", std::process::id()));
        fs::write(&path, format!("{KEY}\n")).unwrap();

        let key = read_key_file(&path, true).unwrap();

        assert_eq!(key, Some(DescriptorPublicKey::from_str(KEY).unwrap()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn read_key_file_reports_missing_requested_file() {
        let path =
            env::temp_dir().join(format!("bip138-read-key-absent-{}.txt", std::process::id()));
        let _ = fs::remove_file(&path);

        let err = read_key_file(&path, true).unwrap_err();

        assert!(matches!(err, CliError::ReadError(_)), "got {err:?}");
    }

    #[test]
    fn read_key_file_ignores_missing_default_file() {
        let path = env::temp_dir().join(format!(
            "bip138-read-key-default-{}.txt",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        assert_eq!(read_key_file(&path, false).unwrap(), None);
    }

    #[test]
    fn read_key_file_rejects_unparsable_key() {
        let path = env::temp_dir().join(format!("bip138-read-key-bad-{}.txt", std::process::id()));
        fs::write(&path, "not-a-key").unwrap();

        let err = read_key_file(&path, true).unwrap_err();

        assert!(matches!(err, CliError::CantConvertToXpub(_)), "got {err:?}");
        fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "devices")]
    #[test]
    fn append_line_appends_new_line() {
        let path = env::temp_dir().join(format!("bip138-fetch-append-{}.txt", std::process::id()));
        let _ = fs::remove_file(&path);

        append_line(path.to_str().unwrap(), "first").unwrap();
        append_line(path.to_str().unwrap(), "second").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "first\nsecond\n");
        fs::remove_file(path).unwrap();
    }
}
