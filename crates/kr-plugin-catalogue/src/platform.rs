//! Which platform this host is, in the words a package's manifest names platforms with.
//!
//! A package lists the operating systems it supports and, for each, the architectures. A host
//! admits a package only where both its operating system and its architecture are listed, and says
//! which of the two was missing when one is: an unsupported architecture on a supported operating
//! system is a different thing to tell a person than an operating system the package never named.

use kr_plugin_sdk::matching::{Architecture, OperatingSystem, PlatformSupport};

/// The platform one host is, where the package format can name it.
///
/// A host the format has no word for (another operating system, another processor) is `None`
/// there, and supports no package: nothing a package lists can be shown to be it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPlatform {
    /// The operating system.
    pub os: Option<OperatingSystem>,
    /// The processor architecture.
    pub architecture: Option<Architecture>,
}

/// Why a package does not support a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// The package lists no build for this host's operating system.
    OperatingSystem,
    /// The package supports this host's operating system, and not its architecture there.
    Architecture,
}

impl HostPlatform {
    /// Checks a package's platforms against this host.
    ///
    /// A manifest may name one operating system in several entries, and any of them supports the
    /// host.
    ///
    /// # Errors
    ///
    /// Returns which of the two the package does not support: the operating system first, since
    /// an architecture means nothing on an operating system the package never named.
    pub fn check(&self, platforms: &[PlatformSupport]) -> Result<(), Unsupported> {
        let Some(os) = self.os else {
            return Err(Unsupported::OperatingSystem);
        };
        let mut listed = platforms
            .iter()
            .filter(|platform| platform.os == os)
            .peekable();
        if listed.peek().is_none() {
            return Err(Unsupported::OperatingSystem);
        }
        match self.architecture {
            Some(architecture)
                if listed.any(|platform| platform.architectures.contains(&architecture)) =>
            {
                Ok(())
            }
            _ => Err(Unsupported::Architecture),
        }
    }

    /// Names this host's platform for a person.
    #[must_use]
    pub fn name(&self) -> String {
        format!(
            "{} {}",
            self.os
                .map_or("an unknown operating system", OperatingSystem::as_str),
            self.architecture
                .map_or("an unknown architecture", Architecture::as_str)
        )
    }
}

/// Returns the platform this build of the host runs on.
#[must_use]
pub const fn this_host() -> HostPlatform {
    let os = if cfg!(target_os = "linux") {
        Some(OperatingSystem::Linux)
    } else if cfg!(target_os = "macos") {
        Some(OperatingSystem::MacOs)
    } else if cfg!(target_os = "windows") {
        Some(OperatingSystem::Windows)
    } else {
        None
    };
    let architecture = if cfg!(target_arch = "x86_64") {
        Some(Architecture::X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(Architecture::Aarch64)
    } else {
        None
    };
    HostPlatform { os, architecture }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_on(architectures: &[Architecture]) -> Vec<PlatformSupport> {
        vec![PlatformSupport {
            os: OperatingSystem::Linux,
            architectures: architectures.to_vec(),
        }]
    }

    #[test]
    fn a_host_is_supported_only_where_its_os_and_its_architecture_are_both_listed() {
        let host = HostPlatform {
            os: Some(OperatingSystem::Linux),
            architecture: Some(Architecture::Aarch64),
        };
        assert_eq!(host.check(&linux_on(&[Architecture::Aarch64])), Ok(()));
        assert_eq!(
            host.check(&linux_on(&[Architecture::X86_64])),
            Err(Unsupported::Architecture)
        );
        let mac = HostPlatform {
            os: Some(OperatingSystem::MacOs),
            architecture: Some(Architecture::Aarch64),
        };
        assert_eq!(
            mac.check(&linux_on(&[Architecture::Aarch64])),
            Err(Unsupported::OperatingSystem)
        );
        let unknown = HostPlatform {
            os: None,
            architecture: None,
        };
        assert_eq!(
            unknown.check(&linux_on(&[Architecture::Aarch64])),
            Err(Unsupported::OperatingSystem)
        );
    }

    /// A manifest may name one operating system in several entries, one per architecture, and a
    /// host is supported by any of them, in either order.
    #[test]
    fn every_entry_for_the_operating_system_is_considered() {
        let split = |first: Architecture, second: Architecture| {
            vec![
                PlatformSupport {
                    os: OperatingSystem::Linux,
                    architectures: vec![first],
                },
                PlatformSupport {
                    os: OperatingSystem::Linux,
                    architectures: vec![second],
                },
            ]
        };
        for architecture in [Architecture::X86_64, Architecture::Aarch64] {
            let host = HostPlatform {
                os: Some(OperatingSystem::Linux),
                architecture: Some(architecture),
            };
            for platforms in [
                split(Architecture::X86_64, Architecture::Aarch64),
                split(Architecture::Aarch64, Architecture::X86_64),
            ] {
                assert_eq!(host.check(&platforms), Ok(()), "{architecture:?}");
            }
        }
        let unknown = HostPlatform {
            os: Some(OperatingSystem::Linux),
            architecture: None,
        };
        assert_eq!(
            unknown.check(&split(Architecture::X86_64, Architecture::Aarch64)),
            Err(Unsupported::Architecture)
        );
    }

    #[test]
    fn this_host_is_one_the_format_names() {
        let host = this_host();
        assert!(host.os.is_some() && host.architecture.is_some(), "{host:?}");
    }
}
