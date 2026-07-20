use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    pub(crate) fn create(parent: &Path, purpose: &str) -> Result<Self> {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create temporary parent {}", parent.display()))?;

        for _ in 0..128 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let name = format!(".polytope-{purpose}-{}-{id}", std::process::id());
            let path = parent.join(name);
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to create temporary directory {}", path.display())
                    });
                }
            }
        }

        bail!(
            "could not allocate a unique temporary directory under {}",
            parent.display()
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
