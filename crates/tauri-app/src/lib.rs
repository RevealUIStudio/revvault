mod state;

use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use secrecy::ExposeSecret;
use tauri::State;

use state::AppState;

#[tauri::command]
fn init_store(state: State<AppState>) -> Result<(), String> {
    state.init()
}

#[tauri::command]
fn list_secrets(state: State<AppState>, prefix: Option<String>) -> Result<Vec<SecretInfo>, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let entries = store.list(prefix.as_deref()).map_err(|e| e.to_string())?;

    Ok(entries
        .into_iter()
        .map(|e| SecretInfo {
            path: e.path,
            namespace: e.namespace.to_string(),
        })
        .collect())
}

#[tauri::command]
fn get_secret(state: State<AppState>, path: String) -> Result<String, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let secret = store.get(&path).map_err(|e| e.to_string())?;
    Ok(secret.expose_secret().to_string())
}

#[tauri::command]
fn set_secret(state: State<AppState>, path: String, value: String, force: bool) -> Result<(), String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;

    if force {
        store.upsert(&path, value.as_bytes()).map_err(|e| e.to_string())
    } else {
        store.set(&path, value.as_bytes()).map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn delete_secret(state: State<AppState>, path: String) -> Result<(), String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    store.delete(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn search_secrets(state: State<AppState>, query: String) -> Result<Vec<SecretInfo>, String> {
    let guard = state.store.lock().map_err(|e| e.to_string())?;
    let store = guard.as_ref().ok_or("Store not initialized")?;
    let entries = store.search(&query).map_err(|e| e.to_string())?;

    Ok(entries
        .into_iter()
        .map(|e| SecretInfo {
            path: e.path,
            namespace: e.namespace.to_string(),
        })
        .collect())
}

#[tauri::command]
fn copy_to_clipboard(value: String) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(&value).map_err(|e| e.to_string())?;

    // Auto-clear after 45 seconds
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(45));
        if let Ok(mut cb) = Clipboard::new() {
            let _ = cb.set_text("");
        }
    });

    Ok(())
}

#[derive(serde::Serialize)]
struct SecretInfo {
    path: String,
    namespace: String,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            init_store,
            list_secrets,
            get_secret,
            set_secret,
            delete_secret,
            search_secrets,
            copy_to_clipboard,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
