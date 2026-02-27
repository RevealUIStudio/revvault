use std::sync::Mutex;

use revault_core::{Config, PassageStore};

/// Managed Tauri state wrapping the PassageStore.
pub struct AppState {
    pub store: Mutex<Option<PassageStore>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(None),
        }
    }

    /// Initialize the store from resolved config.
    pub fn init(&self) -> Result<(), String> {
        let config = Config::resolve().map_err(|e| e.to_string())?;
        let store = PassageStore::open(config).map_err(|e| e.to_string())?;
        let mut guard = self.store.lock().map_err(|e| e.to_string())?;
        *guard = Some(store);
        Ok(())
    }
}
