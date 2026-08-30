//! Desktop IPC contract: decrypted secret material must stay in native code.
//!
//! CI runs `cargo test -p revvault-core` and excludes `revvault-tauri` (gtk /
//! webkit). These `include_str!` checks prove `get_secret` is gone, that no
//! `#[tauri::command]` returns a `String` Ok payload, and that reveal/copy
//! return `()`.

const TAURI_LIB: &str = include_str!("../../tauri-app/src/lib.rs");
const SECRET_DETAIL: &str = include_str!("../../../frontend/src/components/SecretDetail.tsx");

fn command_signature<'a>(src: &'a str, name: &str) -> &'a str {
    let after = src
        .split(&format!("fn {name}"))
        .nth(1)
        .unwrap_or_else(|| panic!("{name} must be defined"));
    after.split('{').next().expect("signature")
}

fn tauri_command_signatures(src: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = src;
    const MARKER: &str = "#[tauri::command]";
    while let Some(idx) = rest.find(MARKER) {
        rest = &rest[idx + MARKER.len()..];
        let Some(fn_rel) = rest.find("fn ") else {
            break;
        };
        let from_fn = &rest[fn_rel..];
        let Some(end) = from_fn.find('{') else {
            break;
        };
        out.push(&from_fn[..end]);
        rest = &from_fn[end + 1..];
    }
    out
}

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
fn no_tauri_command_returns_string_ok_payload() {
    let leaked: Vec<&str> = tauri_command_signatures(TAURI_LIB)
        .into_iter()
        .filter(|sig| sig.contains("Result<String"))
        .collect();
    assert!(
        leaked.is_empty(),
        "tauri commands must not return Result<String, _>: {leaked:?}"
    );
}

#[test]
fn reveal_secret_returns_unit_and_stays_registered() {
    assert!(
        TAURI_LIB.contains("fn reveal_secret"),
        "reveal_secret is the native dialog path"
    );
    assert!(
        TAURI_LIB.contains("reveal_secret,"),
        "reveal_secret must remain in generate_handler"
    );
    let signature = command_signature(TAURI_LIB, "reveal_secret");
    assert!(
        signature.contains("Result<(), String>"),
        "reveal_secret must return () so the value never crosses IPC: {signature}"
    );
}

#[test]
fn copy_secret_returns_unit_and_stays_registered() {
    assert!(
        TAURI_LIB.contains("fn copy_secret"),
        "copy_secret is the native clipboard path"
    );
    assert!(
        TAURI_LIB.contains("copy_secret,"),
        "copy_secret must remain in generate_handler"
    );
    let signature = command_signature(TAURI_LIB, "copy_secret");
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
        SECRET_DETAIL.contains("reveal_secret"),
        "SecretDetail must keep the Rust reveal path"
    );
    assert!(
        SECRET_DETAIL.contains("copy_secret"),
        "SecretDetail must keep the Rust copy path"
    );
}
