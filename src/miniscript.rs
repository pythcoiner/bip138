//! Re-export of the selected `miniscript` version. The crate can be built
//! against one of several semver-incompatible `miniscript` releases, each
//! pulled in under its own renamed dependency and gated by a feature flag.
//! Exactly one must be selected; the rest of the crate uses `crate::miniscript`.

#[cfg(all(feature = "miniscript_12_0", feature = "miniscript_12_3_5"))]
compile_error!("A single miniscript version must be selected");

#[cfg(not(any(feature = "miniscript_12_0", feature = "miniscript_12_3_5")))]
compile_error!("A miniscript version must be selected with feature flag");

#[cfg(feature = "miniscript_12_0")]
pub use mscript_12_0::*;
#[cfg(feature = "miniscript_12_3_5")]
pub use mscript_12_3_5::*;
