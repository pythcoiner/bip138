use crate::miniscript::bitcoin::{
    Network,
    bip32::{self, DerivationPath, Fingerprint},
};
use async_hwi::{
    DeviceKind, HWI,
    bitbox::{BitBox02, PairingBitbox02, api::runtime},
    coldcard,
    jade::{self, Jade},
    ledger::{HidApi, Ledger, LedgerSimulator, TransportHID},
    specter::{Specter, SpecterSimulator},
};
use core::fmt::Display;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error as StdError,
    fs,
    path::PathBuf,
};
use tokio::time::{Duration, timeout};

const HARDENED_BIT: u32 = 1 << 31;
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XpubWarning {
    Failed(FetchFailed),
    TimedOut {
        device: DeviceKind,
        path: DerivationPath,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchFailed {
    device: DeviceKind,
    path: DerivationPath,
    expect: Expect,
    error: String,
}

impl Display for FetchFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl StdError for FetchFailed {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    // If fetching at this path fails, user must be notified,
    // as this path is cleraly specified in the encryption envelope
    PromptUser,
    // This is a common path that all signing devices allow to fetch
    MustFetch,
    // Fecth xpub at this derivation path can fails on some devices/versions
    CanFail,
}

pub fn device_timeout(kind: DeviceKind) -> Duration {
    Duration::from_millis(match kind {
        DeviceKind::Ledger | DeviceKind::SpecterSimulator | DeviceKind::LedgerSimulator => 500,
        DeviceKind::BitBox02 => 1000,
        DeviceKind::Coldcard | DeviceKind::Specter | DeviceKind::Jade => 3000,
    })
}

fn xpub_timeout(kind: DeviceKind, expect: Expect, prompt: bool) -> Duration {
    match (expect, prompt) {
        (Expect::CanFail, true) => PROMPT_TIMEOUT,
        (Expect::PromptUser, _) => PROMPT_TIMEOUT,
        (Expect::MustFetch | Expect::CanFail, _) => device_timeout(kind),
    }
}

fn display_xpub(kind: DeviceKind, expect: Expect) -> bool {
    matches!(kind, DeviceKind::Ledger | DeviceKind::LedgerSimulator)
        && matches!(expect, Expect::PromptUser | Expect::CanFail)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XpubCollection {
    pub xpubs: Vec<bip32::Xpub>,
    pub warnings: Vec<XpubWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedXpub {
    pub fingerprint: Fingerprint,
    pub xpub: bip32::Xpub,
}

pub struct XpubCollector {
    deriv_paths: Vec<DerivationPath>,
    network: Network,
    ordering: Vec<u32>,
    prompt: bool,
}

impl XpubCollector {
    pub fn new(deriv_paths: Vec<DerivationPath>, network: Network) -> Self {
        Self {
            deriv_paths,
            network,
            ordering: vec![],
            prompt: false,
        }
    }

    pub fn ordering<I>(mut self, ordering: I) -> Self
    where
        I: IntoIterator<Item = u32>,
    {
        self.ordering = ordering.into_iter().collect();
        self
    }

    pub fn prompt(mut self, prompt: bool) -> Self {
        self.prompt = prompt;
        self
    }

    pub async fn collect<L, X>(self, log: L, on_xpub: X) -> Result<XpubCollection, FetchFailed>
    where
        L: FnMut(String) + Send,
        X: FnMut(DerivationPath, bip32::Xpub) + Send,
    {
        self.collect_until(log, on_xpub, || false).await
    }

    pub async fn collect_until<L, X, S>(
        self,
        mut log: L,
        mut on_xpub: X,
        mut should_stop: S,
    ) -> Result<XpubCollection, FetchFailed>
    where
        L: FnMut(String) + Send,
        X: FnMut(DerivationPath, bip32::Xpub) + Send,
        S: FnMut() -> bool + Send,
    {
        let mut xpubs = BTreeSet::new();
        let mut warnings = vec![];
        if let Ok(devices) = list(self.network).await {
            if let Some(device) = devices.into_iter().next() {
                let device_kind = device.device_kind();
                let paths = self.paths(device_kind);
                log(format!("Fetching xpubs on {device_kind:?}"));
                unlock_bitbox(&*device, self.network, &mut log).await?;
                for (path, expect) in &paths {
                    if should_stop() {
                        break;
                    }
                    let fetch_timeout = xpub_timeout(device_kind, *expect, self.prompt);
                    log(format!(
                        "Fetching {path} on {device_kind:?} with {expect:?} timeout {fetch_timeout:?}"
                    ));
                    device.display(display_xpub(device_kind, *expect));
                    match timeout(fetch_timeout, device.get_extended_pubkey(path)).await {
                        Ok(Ok(xpub)) => {
                            xpubs.insert(xpub);
                            on_xpub(path.clone(), xpub);
                        }
                        Ok(Err(e)) => {
                            log(format!("Fail {path:?}"));
                            let failed = FetchFailed {
                                device: device_kind,
                                path: path.clone(),
                                expect: *expect,
                                error: e.to_string(),
                            };
                            match expect {
                                Expect::MustFetch => {
                                    return Err(failed);
                                }
                                Expect::PromptUser | Expect::CanFail => {
                                    warnings.push(XpubWarning::Failed(failed));
                                }
                            }
                        }
                        Err(_) => {
                            log(format!("Timed out {path:?}"));
                            let failed = FetchFailed {
                                device: device_kind,
                                path: path.clone(),
                                expect: *expect,
                                error: "Timed out".to_string(),
                            };
                            match expect {
                                Expect::MustFetch => {
                                    return Err(failed);
                                }
                                Expect::PromptUser | Expect::CanFail => {
                                    warnings.push(XpubWarning::TimedOut {
                                        device: device_kind,
                                        path: path.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(XpubCollection {
            xpubs: xpubs.into_iter().collect(),
            warnings,
        })
    }

    fn paths(&self, kind: DeviceKind) -> Vec<(DerivationPath, Expect)> {
        let mut paths: BTreeMap<_, _> = crate::ll::common_derivation_paths(kind, self.network)
            .into_iter()
            .collect();

        for path in &self.deriv_paths {
            paths.entry(path.clone()).or_insert(Expect::PromptUser);
        }

        let mut paths = paths.into_iter().collect::<Vec<_>>();
        paths.sort_by_key(|(path, expect)| {
            (
                self.envelope_priority(path),
                expect.priority(),
                self.priority(path),
            )
        });
        paths
    }

    fn envelope_priority(&self, path: &DerivationPath) -> usize {
        self.deriv_paths
            .iter()
            .position(|deriv_path| deriv_path == path)
            .unwrap_or(self.deriv_paths.len())
    }

    fn priority(&self, path: &DerivationPath) -> usize {
        match path_purpose(path) {
            Some(purpose) => self
                .ordering
                .iter()
                .position(|ordered| *ordered == purpose)
                .unwrap_or(self.ordering.len()),
            None => self.ordering.len(),
        }
    }
}

impl Expect {
    fn priority(self) -> usize {
        match self {
            Expect::MustFetch => 0,
            Expect::PromptUser => 1,
            Expect::CanFail => 2,
        }
    }
}

pub async fn collect_xpubs<F>(
    deriv_paths: Vec<DerivationPath>,
    network: Network,
    mut log: F,
) -> Result<XpubCollection, FetchFailed>
where
    F: FnMut(String) + Send,
{
    XpubCollector::new(deriv_paths, network)
        .collect(&mut log, |_, _| {})
        .await
}

pub async fn fetch_first_xpub_at_path<F>(
    path: DerivationPath,
    network: Network,
    log: F,
) -> Result<Option<bip32::Xpub>, FetchFailed>
where
    F: FnMut(String) + Send,
{
    Ok(fetch_first_origin_xpub_at_path(path, network, log)
        .await?
        .map(|fetched| fetched.xpub))
}

pub async fn fetch_first_origin_xpub_at_path<F>(
    path: DerivationPath,
    network: Network,
    mut log: F,
) -> Result<Option<FetchedXpub>, FetchFailed>
where
    F: FnMut(String) + Send,
{
    if let Ok(devices) = list(network).await {
        if let Some(device) = devices.into_iter().next() {
            let device_kind = device.device_kind();
            let expect = fetch_path_expect(device_kind, network, &path);
            log(format!("Fetching xpubs on {device_kind:?}"));
            unlock_bitbox(&*device, network, &mut log).await?;
            let fingerprint = device
                .get_master_fingerprint()
                .await
                .map_err(|e| FetchFailed {
                    device: device_kind,
                    path: path.clone(),
                    expect,
                    error: e.to_string(),
                })?;
            log(format!(
                "Fetching {path} on {device_kind:?} with {expect:?} timeout {PROMPT_TIMEOUT:?}"
            ));
            device.display(display_xpub(device_kind, expect));
            return match timeout(PROMPT_TIMEOUT, device.get_extended_pubkey(&path)).await {
                Ok(Ok(xpub)) => Ok(Some(FetchedXpub { fingerprint, xpub })),
                Ok(Err(e)) => Err(FetchFailed {
                    device: device_kind,
                    path,
                    expect,
                    error: e.to_string(),
                }),
                Err(_) => Err(FetchFailed {
                    device: device_kind,
                    path,
                    expect,
                    error: "Timed out".to_string(),
                }),
            };
        }
    }

    Ok(None)
}

fn fetch_path_expect(kind: DeviceKind, network: Network, path: &DerivationPath) -> Expect {
    let common = crate::ll::common_derivation_paths(kind, network)
        .into_iter()
        .any(|(common_path, _)| common_path == *path);
    match (kind, common) {
        (DeviceKind::Ledger | DeviceKind::LedgerSimulator | DeviceKind::BitBox02, false) => {
            Expect::PromptUser
        }
        _ => crate::ll::common_derivation_path_expect(kind, path),
    }
}

async fn unlock_bitbox<L>(
    device: &(dyn HWI + Send),
    network: Network,
    log: &mut L,
) -> Result<(), FetchFailed>
where
    L: FnMut(String) + Send,
{
    if device.device_kind() != DeviceKind::BitBox02 {
        return Ok(());
    }

    let path = bitbox_unlock_path(network);
    log(format!(
        "Unlocking BitBox02 with {path} timeout {PROMPT_TIMEOUT:?}"
    ));
    match timeout(PROMPT_TIMEOUT, device.get_extended_pubkey(&path)).await {
        Ok(Ok(_)) => {
            log("BitBox02 unlocked".to_string());
            Ok(())
        }
        Ok(Err(e)) => Err(FetchFailed {
            device: DeviceKind::BitBox02,
            path,
            expect: Expect::PromptUser,
            error: e.to_string(),
        }),
        Err(_) => Err(FetchFailed {
            device: DeviceKind::BitBox02,
            path,
            expect: Expect::PromptUser,
            error: "Timed out".to_string(),
        }),
    }
}

fn bitbox_unlock_path(network: Network) -> DerivationPath {
    crate::ll::common_derivation_paths(DeviceKind::BitBox02, network)
        .into_iter()
        .map(|(path, _)| path)
        .find(|path| path_purpose(path) == Some(48))
        .expect("common derivation paths include purpose 48")
}

fn path_purpose(path: &DerivationPath) -> Option<u32> {
    path.to_u32_vec().first().map(|index| index & !HARDENED_BIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn xpub_collector_orders_paths_by_purpose() {
        let paths = XpubCollector::new(vec![], Network::Bitcoin)
            .ordering([84, 48])
            .paths(DeviceKind::Ledger);

        let first_44 = paths
            .iter()
            .position(|(path, _)| path_purpose(path) == Some(44))
            .unwrap();
        let first_48 = paths
            .iter()
            .position(|(path, _)| path_purpose(path) == Some(48))
            .unwrap();
        let first_84 = paths
            .iter()
            .position(|(path, _)| path_purpose(path) == Some(84))
            .unwrap();

        assert!(first_84 < first_48);
        assert!(first_48 < first_44);
    }

    #[test]
    fn xpub_collector_keeps_envelope_path() {
        let path = DerivationPath::from_str("99h/0h/0h").unwrap();
        let paths =
            XpubCollector::new(vec![path.clone()], Network::Bitcoin).paths(DeviceKind::Ledger);

        assert!(paths.contains(&(path, Expect::PromptUser)));
    }

    #[test]
    fn xpub_collector_tries_envelope_paths_first() {
        let path = DerivationPath::from_str("86h/0h/0h").unwrap();
        let paths = XpubCollector::new(vec![path.clone()], Network::Bitcoin)
            .ordering([48, 84, 86])
            .paths(DeviceKind::Ledger);

        assert_eq!(paths[0], (path, Expect::MustFetch));
    }

    #[test]
    fn ledger_can_fail_only_on_purpose_87() {
        let paths = XpubCollector::new(vec![], Network::Bitcoin).paths(DeviceKind::Ledger);

        assert!(paths.contains(&(
            DerivationPath::from_str("44h/0h/0h").unwrap(),
            Expect::MustFetch
        )));
        assert!(paths.contains(&(
            DerivationPath::from_str("87h/0h/0h").unwrap(),
            Expect::CanFail
        )));
    }

    #[test]
    fn bitbox_can_fail_on_purpose_44_and_87() {
        let paths = XpubCollector::new(vec![], Network::Bitcoin).paths(DeviceKind::BitBox02);

        for path in ["44h/0h/0h", "87h/0h/0h"] {
            assert!(paths.contains(&(DerivationPath::from_str(path).unwrap(), Expect::CanFail)));
        }

        for path in ["48h/0h/0h/1h", "49h/0h/0h", "84h/0h/0h", "86h/0h/0h"] {
            assert!(paths.contains(&(DerivationPath::from_str(path).unwrap(), Expect::MustFetch)));
        }
    }

    #[test]
    fn xpub_collector_orders_paths_by_expectation() {
        let path = DerivationPath::from_str("99h/0h/0h").unwrap();
        let paths = XpubCollector::new(vec![path], Network::Bitcoin).paths(DeviceKind::BitBox02);

        let first_must_fetch = paths
            .iter()
            .position(|(_, expect)| *expect == Expect::MustFetch)
            .unwrap();
        let first_prompt = paths
            .iter()
            .position(|(_, expect)| *expect == Expect::PromptUser)
            .unwrap();
        let first_can_fail = paths
            .iter()
            .position(|(_, expect)| *expect == Expect::CanFail)
            .unwrap();

        assert_eq!(first_prompt, 0);
        assert!(first_must_fetch < first_can_fail);
    }

    #[test]
    fn prompt_uses_prompt_timeout_on_can_fail() {
        assert_eq!(
            xpub_timeout(DeviceKind::Ledger, Expect::CanFail, false),
            device_timeout(DeviceKind::Ledger)
        );
        assert_eq!(
            xpub_timeout(DeviceKind::Ledger, Expect::CanFail, true),
            PROMPT_TIMEOUT
        );
    }

    #[test]
    fn ledger_prompt_user_and_can_fail_display_xpub() {
        assert!(display_xpub(DeviceKind::Ledger, Expect::PromptUser));
        assert!(display_xpub(DeviceKind::Ledger, Expect::CanFail));
        assert!(display_xpub(
            DeviceKind::LedgerSimulator,
            Expect::PromptUser
        ));
        assert!(display_xpub(DeviceKind::LedgerSimulator, Expect::CanFail));
        assert!(!display_xpub(DeviceKind::Ledger, Expect::MustFetch));
        assert!(!display_xpub(DeviceKind::BitBox02, Expect::CanFail));
    }

    #[test]
    fn ledger_explicit_fetch_prompts_for_non_common_path() {
        let path = DerivationPath::from_str("48h/1h/0h").unwrap();

        assert_eq!(
            fetch_path_expect(DeviceKind::Ledger, Network::Testnet, &path),
            Expect::PromptUser
        );
        assert!(display_xpub(DeviceKind::Ledger, Expect::PromptUser));
    }

    #[test]
    fn ledger_explicit_fetch_keeps_common_path_expectation() {
        let path = DerivationPath::from_str("48h/1h/0h/1h").unwrap();

        assert_eq!(
            fetch_path_expect(DeviceKind::Ledger, Network::Testnet, &path),
            Expect::MustFetch
        );
    }

    #[test]
    fn bitbox_explicit_fetch_prompts_for_non_common_path() {
        let path = DerivationPath::from_str("48h/1h/0h").unwrap();

        assert_eq!(
            fetch_path_expect(DeviceKind::BitBox02, Network::Testnet, &path),
            Expect::PromptUser
        );
    }

    #[test]
    fn bitbox_explicit_fetch_keeps_common_path_expectation() {
        let path = DerivationPath::from_str("48h/1h/0h/1h").unwrap();

        assert_eq!(
            fetch_path_expect(DeviceKind::BitBox02, Network::Testnet, &path),
            Expect::MustFetch
        );
    }

    #[test]
    fn bitbox_unlock_uses_common_purpose_48_path() {
        let path = bitbox_unlock_path(Network::Bitcoin);

        assert_eq!(path, DerivationPath::from_str("48h/0h/0h/1h").unwrap());
    }
}

pub async fn list(network: Network) -> Result<Vec<Box<dyn HWI + Send>>, Box<dyn StdError>> {
    let mut hws = Vec::new();

    if let Ok(device) = SpecterSimulator::try_connect().await {
        hws.push(device.into());
    }

    if let Ok(devices) = Specter::enumerate().await {
        for device in devices {
            hws.push(device.into());
        }
    }

    match Jade::enumerate().await {
        Err(e) => println!("{e:?}"),
        Ok(devices) => {
            for device in devices {
                let device = device.with_network(network);
                if let Ok(info) = device.get_info().await {
                    if info.jade_state == jade::api::JadeState::Locked {
                        if let Err(e) = device.auth().await {
                            eprintln!("auth {e:?}");
                            continue;
                        }
                    }

                    hws.push(device.into());
                }
            }
        }
    }

    if let Ok(device) = LedgerSimulator::try_connect().await {
        hws.push(device.into());
    }

    let api = Box::new(HidApi::new().unwrap());

    for device_info in api.device_list() {
        if async_hwi::bitbox::is_bitbox02(device_info) {
            if let Ok(device) = device_info.open_device(&api) {
                let cache_dir = bitbox_pairing_cache_dir()?;
                fs::create_dir_all(&cache_dir)?;
                let cache_dir = cache_dir
                    .to_str()
                    .ok_or("BitBox02 pairing cache path is not UTF-8")?;
                let cache = Box::new(async_hwi::bitbox::api::PersistedNoiseConfig::new(cache_dir));
                if let Ok(device) =
                    PairingBitbox02::<runtime::TokioRuntime>::connect(device, Some(cache)).await
                {
                    if let Ok(device) = device.wait_confirm().await {
                        let bb02 = BitBox02::from(device).with_network(network);
                        hws.push(bb02.into());
                    }
                }
            }
        }
        if device_info.vendor_id() == coldcard::api::COINKITE_VID
            && device_info.product_id() == coldcard::api::CKCC_PID
        {
            if let Some(sn) = device_info.serial_number() {
                if let Ok((cc, _)) = coldcard::api::Coldcard::open(&api, sn, None) {
                    let hw = coldcard::Coldcard::from(cc);
                    hws.push(hw.into())
                }
            }
        }
    }

    for detected in Ledger::<TransportHID>::enumerate(&api) {
        if let Ok(device) = Ledger::<TransportHID>::connect(&api, detected) {
            hws.push(device.into());
        }
    }

    Ok(hws)
}

#[cfg(target_os = "macos")]
fn bitbox_pairing_cache_dir() -> Result<PathBuf, Box<dyn StdError>> {
    Ok(PathBuf::from(home_dir()?)
        .join("Library")
        .join("Application Support")
        .join("bip138"))
}

#[cfg(target_os = "windows")]
fn bitbox_pairing_cache_dir() -> Result<PathBuf, Box<dyn StdError>> {
    Ok(PathBuf::from(env::var_os("APPDATA").ok_or("APPDATA is not set")?).join("bip138"))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn bitbox_pairing_cache_dir() -> Result<PathBuf, Box<dyn StdError>> {
    Ok(PathBuf::from(home_dir()?).join(".bip138"))
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Result<std::ffi::OsString, Box<dyn StdError>> {
    env::var_os("HOME").ok_or_else(|| "HOME is not set".into())
}
