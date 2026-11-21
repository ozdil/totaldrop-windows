// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Thin C ABI FFI boundary for TotalDrop on Windows 11 (ADR 0016).
//!
//! This crate isolates all `extern "C"` FFI exports into a minimal `cdylib` +
//! `rlib` boundary (`totaldrop_windows_ffi.dll`) so that `totaldrop-crypto`,
//! `totaldrop-proto`, `totaldrop-core`, `totaldrop-l10n`, and
//! `totaldrop-windows-bridge` remain strictly `#![forbid(unsafe_code)]`.
//!
//! # Memory Ownership & Safety Invariants
//!
//! - Every function returning `*mut c_char` allocates a NUL-terminated UTF-8
//!   JSON string using Rust's allocator. Callers MUST free every non-null
//!   pointer via [`totaldrop_win_string_free`].
//! - Every `extern "C"` entry point wraps its body in
//!   [`std::panic::catch_unwind`] so a Rust panic can never unwind across the
//!   C ABI boundary.
//! - Interior NUL bytes are stripped before constructing [`CString`] buffers so
//!   serialization never fails or truncates mid-payload.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use serde::Serialize;
use totaldrop_windows_bridge::{
    UriValidationError, ValidatedCode, WindowsLocalizer, format_regional_percent,
};

/// Independent SemVer of the TotalDrop for Windows 11 application.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the synced pure-Rust TotalDrop core workspace crates.
pub const CORE_VERSION: &str = "0.2.0-beta.5";

/// Four-part Windows MSIX / PE package version (`Revision == 0`).
pub const MSIX_VERSION: &str = "0.1.1.0";

const FALLBACK_PANIC_JSON: &str = r#"{"ok":false,"error":{"kind":"internal","l10n_key":"errorOther","message":"internal FFI panic"}}"#;
const FALLBACK_SERIALIZE_JSON: &str = r#"{"ok":false,"error":{"kind":"internal","l10n_key":"errorOther","message":"internal JSON serialization failure"}}"#;

#[derive(Serialize)]
struct VersionInfo {
    app_version: &'static str,
    core_version: &'static str,
    msix_version: &'static str,
}

#[derive(Serialize)]
struct FfiErrorEnvelope<'a> {
    ok: bool,
    error: FfiErrorBody<'a>,
}

#[derive(Serialize)]
struct FfiErrorBody<'a> {
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    l10n_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'a str>,
    message: String,
}

fn into_c_string_ptr(mut text: String) -> *mut c_char {
    if text.as_bytes().contains(&0) {
        text.retain(|ch| ch != '\0');
    }
    match CString::new(text) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn serialize_or_error<T: Serialize>(value: &T) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(json) => into_c_string_ptr(json),
        Err(_) => into_c_string_ptr(FALLBACK_SERIALIZE_JSON.to_owned()),
    }
}

fn error_json(
    kind: &str,
    l10n_key: Option<&str>,
    cause: Option<&str>,
    message: impl Into<String>,
) -> *mut c_char {
    let envelope = FfiErrorEnvelope {
        ok: false,
        error: FfiErrorBody {
            kind,
            l10n_key,
            cause,
            message: message.into(),
        },
    };
    serialize_or_error(&envelope)
}

fn guard_ffi_json<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> *mut c_char,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(ptr) => ptr,
        Err(_) => into_c_string_ptr(FALLBACK_PANIC_JSON.to_owned()),
    }
}

/// Reads an optional NUL-terminated UTF-8 C string pointer.
///
/// # Safety
///
/// If `ptr` is non-null, it must point to a valid, readable NUL-terminated C
/// string that remains alive for the duration of `'a`.
unsafe fn read_optional_c_str<'a>(ptr: *const c_char) -> Result<Option<&'a str>, &'static str> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: Caller guarantees non-null `ptr` points to a readable
    // NUL-terminated C string valid for lifetime `'a`.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    match cstr.to_str() {
        Ok(valid) => Ok(Some(valid)),
        Err(_) => Err("input string is not valid UTF-8"),
    }
}

fn parse_lang_tags(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[')
        && let Ok(parsed) = serde_json::from_str::<Vec<String>>(trimmed)
    {
        return parsed
            .into_iter()
            .map(|tag| tag.trim().to_owned())
            .filter(|tag| !tag.is_empty())
            .collect();
    }
    trimmed
        .split([',', ';'])
        .map(|tag| tag.trim().to_owned())
        .filter(|tag| !tag.is_empty())
        .collect()
}

const fn uri_error_kind(err: &UriValidationError) -> &'static str {
    match err {
        UriValidationError::Empty => "empty",
        UriValidationError::LinkTooLong { .. } => "link_too_long",
        UriValidationError::InvalidActivationLink => "invalid_activation_link",
        UriValidationError::BadNameplate => "bad_nameplate",
        UriValidationError::WrongWordCount => "wrong_word_count",
        UriValidationError::UnknownWord { .. } => "unknown_word",
        UriValidationError::NoCodeFoundInText => "no_code_found_in_text",
    }
}

/// Frees a UTF-8 JSON string previously returned by any `totaldrop_win_*`
/// function in this library.
///
/// Passing a null pointer is a safe no-op.
///
/// # Safety
///
/// `ptr` must either be null or a pointer previously returned by a
/// `totaldrop_win_*` export from this library that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Caller guarantees `ptr` is a live pointer allocated via
        // `CString::into_raw` by this library and freed at most once.
        let owned = unsafe { CString::from_raw(ptr) };
        drop(owned);
    }));
}

/// Returns the version metadata of the Windows app, synced core workspace, and
/// MSIX package as a JSON object.
///
/// The returned pointer must be released with [`totaldrop_win_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_version_json() -> *mut c_char {
    guard_ffi_json(|| {
        let info = VersionInfo {
            app_version: APP_VERSION,
            core_version: CORE_VERSION,
            msix_version: MSIX_VERSION,
        };
        serialize_or_error(&info)
    })
}

/// Validates a `totaldrop://r/<code>` or `https://totaldrop.app/r#<code>`
/// activation URI via [`ValidatedCode::from_activation_uri`].
///
/// On success, returns the JSON-serialized [`ValidatedCode`] object. On
/// failure, returns a structured error envelope (`{"ok":false,"error":{...}}`).
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// `raw_uri` must either be null (which yields a `null_pointer` error JSON) or
/// point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_validate_uri_json(raw_uri: *const c_char) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let uri_opt = match unsafe { read_optional_c_str(raw_uri) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorInvalidCode"), None, msg);
            }
        };
        let Some(uri) = uri_opt else {
            return error_json(
                "null_pointer",
                Some("errorInvalidCode"),
                None,
                "raw_uri pointer must not be null",
            );
        };
        match ValidatedCode::from_activation_uri(uri) {
            Ok(validated) => serialize_or_error(&validated),
            Err(err) => error_json(
                uri_error_kind(&err),
                Some(err.l10n_key()),
                None,
                err.to_string(),
            ),
        }
    })
}

/// Validates interactive transfer code input from WinUI 3 via
/// [`ValidatedCode::from_user_input`].
///
/// On success, returns the JSON-serialized [`ValidatedCode`] object. On
/// failure, returns a structured error envelope (`{"ok":false,"error":{...}}`).
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// `raw_input` must either be null (which yields a `null_pointer` error JSON)
/// or point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_validate_input_json(
    raw_input: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let input_opt = match unsafe { read_optional_c_str(raw_input) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("receiveCodeInvalid"), None, msg);
            }
        };
        let Some(input) = input_opt else {
            return error_json(
                "null_pointer",
                Some("receiveCodeInvalid"),
                None,
                "raw_input pointer must not be null",
            );
        };
        match ValidatedCode::from_user_input(input) {
            Ok(validated) => serialize_or_error(&validated),
            Err(err) => error_json(
                uri_error_kind(&err),
                Some(err.l10n_key()),
                None,
                err.to_string(),
            ),
        }
    })
}

/// Formats floor-rounded regional transfer progress (`#483`) using
/// [`format_regional_percent`].
///
/// Passing a null or whitespace-only `region_tag` defaults to `"en-US"`.
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// `region_tag` must either be null or point to a valid NUL-terminated C
/// string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_format_percent_json(
    done: u64,
    total: u64,
    region_tag: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let region_opt = match unsafe { read_optional_c_str(region_tag) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        let region = region_opt
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .unwrap_or("en-US");
        let percent = format_regional_percent(done, total, region);
        serialize_or_error(&percent)
    })
}

/// Resolves the localized 35-language [`totaldrop_windows_bridge::WindowsUiBundle`]
/// snapshot for the requested BCP 47 language preference list and regional
/// formatting locale.
///
/// `lang_tags` accepts either a comma/semicolon-separated list
/// (`"tr-TR,en-US"`) or a JSON array of strings (`["tr-TR","en-US"]`). Passing
/// null or empty falls back to English (`"en"`). Passing null or empty
/// `app_version` defaults to [`APP_VERSION`].
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// Each non-null pointer (`lang_tags`, `region_tag`, `app_version`) must point
/// to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_ui_bundle_json(
    lang_tags: *const c_char,
    region_tag: *const c_char,
    app_version: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let langs_opt = match unsafe { read_optional_c_str(lang_tags) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        // SAFETY: Forwarded from this function's safety contract.
        let region_opt = match unsafe { read_optional_c_str(region_tag) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        // SAFETY: Forwarded from this function's safety contract.
        let version_opt = match unsafe { read_optional_c_str(app_version) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };

        let tags = langs_opt.map(parse_lang_tags).unwrap_or_default();
        let region = region_opt.map(str::trim).filter(|tag| !tag.is_empty());
        let version = version_opt
            .map(str::trim)
            .filter(|ver| !ver.is_empty())
            .unwrap_or(APP_VERSION);

        let localizer = WindowsLocalizer::new(tags, region);
        let bundle = localizer.ui_bundle(version);
        serialize_or_error(&bundle)
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::ffi::CStr;

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    fn take_and_free(ptr: *mut c_char) -> Result<String, Box<dyn StdError>> {
        if ptr.is_null() {
            return Err("unexpected null pointer returned by FFI helper".into());
        }
        // SAFETY: `ptr` was just allocated by `into_c_string_ptr` in this crate.
        let text = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
        // SAFETY: `ptr` was allocated by this crate and is freed exactly once.
        unsafe { totaldrop_win_string_free(ptr) };
        Ok(text)
    }

    #[test]
    fn interior_nul_bytes_are_stripped_before_c_string_allocation() -> TestResult {
        let ptr = into_c_string_ptr("hello\0world\0!".to_owned());
        let rendered = take_and_free(ptr)?;
        assert_eq!(rendered, "helloworld!");
        Ok(())
    }

    #[test]
    fn guard_ffi_json_contains_panics_into_structured_error_envelope() -> TestResult {
        let ptr = guard_ffi_json(|| -> *mut c_char {
            std::panic::resume_unwind(Box::new("synthetic panic for boundary test"));
        });
        let raw = take_and_free(ptr)?;
        let parsed: serde_json::Value = serde_json::from_str(&raw)?;
        assert_eq!(
            parsed.get("ok").and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("kind"))
                .and_then(serde_json::Value::as_str),
            Some("internal")
        );
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("l10n_key"))
                .and_then(serde_json::Value::as_str),
            Some("errorOther")
        );
        Ok(())
    }

    #[test]
    fn parse_lang_tags_handles_csv_semicolon_json_array_and_empty() {
        assert!(parse_lang_tags("").is_empty());
        assert!(parse_lang_tags("   ").is_empty());
        assert_eq!(
            parse_lang_tags("tr-TR, en-US , , de-DE"),
            vec!["tr-TR", "en-US", "de-DE"]
        );
        assert_eq!(parse_lang_tags("zh-HK; en-US"), vec!["zh-HK", "en-US"]);
        assert_eq!(
            parse_lang_tags(r#"["ar-SA", " en-US ", ""]"#),
            vec!["ar-SA", "en-US"]
        );
    }
}
