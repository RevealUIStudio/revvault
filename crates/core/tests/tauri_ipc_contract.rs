//! Desktop IPC contract: decrypted secret material must stay in native code.
//!
//! CI runs `cargo test -p revvault-core` and excludes `revvault-tauri` (gtk /
//! webkit). These `include_str!` checks are the strongest compile-time proof
//! that `get_secret` is gone and no sibling command serializes
//! `expose_secret()` back to the webview.

const TAURI_LIB: &str = include_str!("../../tauri-app/src/lib.rs");
const SECRET_DETAIL: &str = include_str!("../../../frontend/src/components/SecretDetail.tsx");

#[test]
fn get_secret_command_is_not_defined() {
    assert!(
        !TAURI_LIB.contains("fn get_secret"),
        "get_secret returned expose_secret().to_string() over Tauri IPC"
    );
    assert!(
        !TAURI_LIB.contains("get_secret,"),
        "get_secret must not be registered in generate_handler"
    );
}

#[test]
fn no_command_returns_expose_secret_to_ipc() {
    assert!(
        !TAURI_LIB.contains("Ok(secret.expose_secret().to_string())"),
        "IPC handlers must not serialize decrypted secrets to the webview"
    );
}

#[test]
fn copy_secret_returns_unit_and_stays_registered() {
    assert!(
        TAURI_LIB.contains("fn copy_secret"),
        "copy_secret is the native disclosure path"
    );
    assert!(
        TAURI_LIB.contains("copy_secret,"),
        "copy_secret must remain in generate_handler"
    );
    let copy_fn = TAURI_LIB
        .split("fn copy_secret")
        .nth(1)
        .expect("copy_secret body");
    let signature = copy_fn.split('{').next().expect("signature");
    assert!(
        signature.contains("Result<(), String>"),
        "copy_secret must return () so the value never crosses IPC: {signature}"
    );
}

#[test]
fn list_and_search_dtos_have_no_value_field() {
    let start = TAURI_LIB.find("struct SecretInfo").expect("SecretInfo DTO");
    let body = &TAURI_LIB[start..];
    let end = body.find('}').expect("SecretInfo closing brace");
    let secret_info = &body[..=end];
    assert!(
        !secret_info.contains("value"),
        "SecretInfo must not grow a value field: {secret_info}"
    );
}

#[test]
fn frontend_detail_never_invokes_get_secret() {
    assert!(
        !SECRET_DETAIL.contains("get_secret"),
        "SecretDetail must not call get_secret"
    );
    assert!(
        SECRET_DETAIL.contains("copy_secret"),
        "SecretDetail must keep the Rust copy path"
    );
}
