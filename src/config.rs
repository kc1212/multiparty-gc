//! Configuration and identity files used by the command line tool.

use itertools::Itertools;
use multiparty_gc::{
    error::GcError,
    net::{
        NetError,
        quic::{Identity, certificate_from_pem},
    },
};
use std::{io::Write, net::SocketAddr, path::Path};

fn write_new(path: &Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    options.open(path)?.write_all(bytes)
}

/// Write a certificate and key for every party and a configuration listing
/// `<party id> <address> <certificate file>` per line.
pub(crate) fn gen_config(
    num_parties: u16,
    dir: &Path,
    host: &str,
    base_port: u16,
) -> Result<(), GcError> {
    let io = |e: std::io::Error| GcError::Net(NetError::Config(e.to_string()));
    if num_parties < 2 || base_port.checked_add(num_parties - 1).is_none() {
        return Err(GcError::Net(NetError::Config(
            "invalid party count or port range".into(),
        )));
    }
    // Refuse to rotate an existing identity or partially replace a configuration.
    let paths = (0..num_parties)
        .flat_map(|i| {
            [
                dir.join(format!("party{i}.cert.pem")),
                dir.join(format!("party{i}.key.pem")),
            ]
        })
        .chain(std::iter::once(dir.join("parties.conf")));
    for path in paths {
        if path.try_exists().map_err(io)? {
            return Err(GcError::Net(NetError::Config(format!(
                "refusing to overwrite {}",
                path.display()
            ))));
        }
    }
    let mut directory = std::fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(dir).map_err(io)?;
    let mut config = String::from("# party address certificate\n");
    for i in 0..num_parties {
        let (cert, key) = Identity::generate_pem()?;
        let cert_file = format!("party{i}.cert.pem");
        write_new(&dir.join(&cert_file), cert.as_bytes(), false).map_err(io)?;
        write_new(&dir.join(format!("party{i}.key.pem")), key.as_bytes(), true).map_err(io)?;
        let port = base_port + i; // The entire range was validated before writing files.
        config.push_str(&format!("{i} {host}:{port} {cert_file}\n"));
    }
    // Publish the configuration only after every identity has been written.
    write_new(&dir.join("parties.conf"), config.as_bytes(), false).map_err(io)?;
    Ok(())
}

/// Parse the configuration written by [gen_config], certificate paths are relative to it.
pub(crate) fn read_config(
    path: &Path,
) -> Result<Vec<(SocketAddr, rustls::pki_types::CertificateDer<'static>)>, GcError> {
    let err = |msg: String| GcError::Net(NetError::Config(msg));
    let text = std::fs::read_to_string(path).map_err(|e| err(e.to_string()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    let mut parties = vec![];
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_whitespace().collect_vec();
        let [id, addr, cert] = fields[..] else {
            return Err(err(format!("invalid line: {line}")));
        };
        let id: usize = id
            .parse()
            .map_err(|_| err(format!("invalid party: {id}")))?;
        if id != parties.len() {
            return Err(err("parties must be listed in order starting from 0".into()));
        }
        let addr = addr
            .parse()
            .map_err(|_| err(format!("invalid address: {addr}")))?;
        let pem = std::fs::read(base.join(cert)).map_err(|e| err(format!("{cert}: {e}")))?;
        parties.push((addr, certificate_from_pem(&pem)?));
    }
    Ok(parties)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "mgc-config-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn identities_are_private_and_not_overwritten() {
        let dir = Directory::new();
        gen_config(2, &dir.0, "127.0.0.1", 7000).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for party in 0..2 {
                assert_eq!(
                    std::fs::metadata(dir.0.join(format!("party{party}.key.pem")))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        let before = std::fs::read(dir.0.join("party0.key.pem")).unwrap();
        assert!(gen_config(2, &dir.0, "127.0.0.1", 8000).is_err());
        assert_eq!(std::fs::read(dir.0.join("party0.key.pem")).unwrap(), before);
        let peers = read_config(&dir.0.join("parties.conf")).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].0.port(), 7000);
    }

    #[test]
    fn invalid_port_range_creates_no_files() {
        let dir = Directory::new();
        assert!(gen_config(2, &dir.0, "127.0.0.1", u16::MAX).is_err());
        assert!(!dir.0.exists());
    }
}
