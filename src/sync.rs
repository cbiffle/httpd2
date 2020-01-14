//! Synchronization primitive add-ons.

use std::sync::Arc;

use tokio::sync::Semaphore;

/// A counting semaphore that can be shared between tasks using reference
/// counting.
///
/// This is essentially equivalent to `tokio::sync::Semaphore`, but uses
/// reference counting instead of borrowing for permits, so that a permit can be
/// acquired in one task and transferred through `spawn`.
#[derive(Clone)]
pub struct SharedSemaphore {
    inner: Arc<Semaphore>,
}

impl SharedSemaphore {
    /// Creates a semaphore initialized with the given number of permits.
    pub fn new(permits: usize) -> Self {
        Self {
            inner: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Acquires one permit, resolving when it's acquired.
    pub async fn acquire(&self) -> SharedPermit {
        self.inner.acquire().await.forget();
        SharedPermit {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// RAII representation of a single permit from a semaphore.
pub struct SharedPermit {
    inner: Arc<Semaphore>,
}

impl Drop for SharedPermit {
    fn drop(&mut self) {
        self.inner.add_permits(1);
    }
}
