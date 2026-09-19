use std::{
    future::Future,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use super::MAX_SEGMENT_BYTES;

pub type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Immediate child name, relative to the requested List prefix.
    pub name: String,
    /// Some(empty) is an inline empty object; None requires a Get call.
    pub inline: Option<Vec<u8>>,
}

/// Logical object storage used by the compatible WAL/session layer.
///
/// Put must publish a complete object atomically. List returns immediate child
/// names, including directories where appropriate. Get uses ErrorKind::NotFound
/// for a missing/eventually-consistent object; Delete is recursive and idempotent.
/// Cloud implementations should bound HTTP operations and cancel on future drop.
pub trait Storage: Send + Sync + 'static {
    fn put<'a>(&'a self, name: &'a str, data: Vec<u8>) -> StorageFuture<'a, ()>;
    fn get<'a>(&'a self, name: &'a str) -> StorageFuture<'a, Vec<u8>>;
    fn delete<'a>(&'a self, name: &'a str) -> StorageFuture<'a, ()>;
    fn list<'a>(&'a self, prefix: &'a str) -> StorageFuture<'a, Vec<Entry>>;
    fn close(&self) -> StorageFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

const TEMP_PREFIX: &str = ".xdrive-tmp-";

#[derive(Clone)]
pub struct LocalStorage {
    root: Arc<PathBuf>,
}

impl LocalStorage {
    pub async fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        if root.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XDRIVE remoteFolder is empty",
            ));
        }
        let root = tokio::task::spawn_blocking(move || {
            create_private_dir(&root)?;
            std::fs::canonicalize(root)
        })
        .await
        .map_err(io::Error::other)??;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        if name.is_empty() || name.bytes().any(|byte| matches!(byte, b'\\' | b':' | 0)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid local XDRIVE object name",
            ));
        }
        let mut parts = Vec::new();
        for component in name.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                parts.pop();
                continue;
            }
            let device = component
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            let device = matches!(device.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
                || ((device.starts_with("COM") || device.starts_with("LPT"))
                    && device.len() == 4
                    && matches!(device.as_bytes()[3], b'1'..=b'9'));
            if device || component.starts_with(TEMP_PREFIX) || component.ends_with([' ', '.']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsafe or reserved local XDRIVE object name",
                ));
            }
            parts.push(component);
        }
        if parts.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XDRIVE object may not name the storage root",
            ));
        }
        let mut result = (*self.root).clone();
        for component in parts {
            result.push(component);
        }
        Ok(result)
    }
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Refuse symbolic-link/reparse redirection anywhere below the chosen root.
/// This does not make hostile concurrent filesystem mutation a sandbox; callers
/// must own/control remoteFolder, as they must for the original local backend.
fn check_descendants(root: &Path, target: &Path) -> io::Result<()> {
    let relative = target.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "XDRIVE path escaped its storage root",
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "XDRIVE refuses reparse-point object paths",
                        ));
                    }
                }
                if metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "XDRIVE refuses symbolic-link object paths",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Storage for LocalStorage {
    fn put<'a>(&'a self, name: &'a str, data: Vec<u8>) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            if data.len() > MAX_SEGMENT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "XDRIVE object exceeds maximum segment size",
                ));
            }
            let full = self.resolve(name)?;
            let root = self.root.clone();
            tokio::task::spawn_blocking(move || {
                check_descendants(&root, &full)?;
                let parent = full.parent().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "XDRIVE object has no parent")
                })?;
                create_private_dir(parent)?;
                check_descendants(&root, &full)?;
                let temporary =
                    parent.join(format!("{TEMP_PREFIX}{}", super::wire::new_session_id()?));
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&temporary)?;
                let result = (|| {
                    file.write_all(&data)?;
                    drop(file);
                    std::fs::rename(&temporary, &full)
                })();
                if result.is_err() {
                    let _ = std::fs::remove_file(&temporary);
                }
                result
            })
            .await
            .map_err(io::Error::other)?
        })
    }

    fn get<'a>(&'a self, name: &'a str) -> StorageFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let full = self.resolve(name)?;
            let root = self.root.clone();
            tokio::task::spawn_blocking(move || {
                check_descendants(&root, &full)?;
                let mut result = Vec::new();
                std::fs::File::open(full)?
                    .take((MAX_SEGMENT_BYTES + 1) as u64)
                    .read_to_end(&mut result)?;
                if result.len() > MAX_SEGMENT_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "XDRIVE object exceeds maximum segment size",
                    ));
                }
                Ok(result)
            })
            .await
            .map_err(io::Error::other)?
        })
    }

    fn delete<'a>(&'a self, name: &'a str) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            let full = self.resolve(name)?;
            let root = self.root.clone();
            tokio::task::spawn_blocking(move || {
                check_descendants(&root, &full)?;
                match std::fs::symlink_metadata(&full) {
                    Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(full),
                    Ok(_) => std::fs::remove_file(full),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            })
            .await
            .map_err(io::Error::other)?
        })
    }

    fn list<'a>(&'a self, prefix: &'a str) -> StorageFuture<'a, Vec<Entry>> {
        Box::pin(async move {
            let full = self.resolve(prefix)?;
            let root = self.root.clone();
            tokio::task::spawn_blocking(move || {
                check_descendants(&root, &full)?;
                let entries = match std::fs::read_dir(full) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(error) => return Err(error),
                };
                let mut result = Vec::new();
                for entry in entries {
                    let entry = entry?;
                    // Invalid UTF-8 cannot name a protocol object. Ignore
                    // unrelated files instead of failing every session poll.
                    let Ok(name) = entry.file_name().into_string() else {
                        continue;
                    };
                    if !name.starts_with(TEMP_PREFIX) {
                        result.push(Entry { name, inline: None });
                    }
                }
                result.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(result)
            })
            .await
            .map_err(io::Error::other)?
        })
    }
}
