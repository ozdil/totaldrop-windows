// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Static 2-thread Tokio runtime, monotonic `u64` transfer session registry,
//! and NDJSON event stream engine for `totaldrop-windows-ffi`.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use totaldrop_core::{Error as CoreError, Event, IncomingOffer, MAX_TEXT, TEXT_FILE};
use totaldrop_windows_bridge::{
    BridgeNetworkConfig, LocalizedTransferError, RegionalPercent, SanitizedPeerText,
    TransferViewEvent, ValidatedCode, WindowsCancellationToken, WindowsLocalizer,
    check_windows_destination, connect_windows_receive, prepare_windows_send,
    prepare_windows_text_send, sanitize_peer_filename, sanitize_peer_text,
};

use crate::quit::{self, STOPPING, TRANSFERS};
use crate::{FFI_ERR_INVALID_HANDLE, FFI_ERR_INVALID_STATE, FFI_OK};

/// Static 2-thread Tokio runtime driving all async network, QUIC, crypto, and
/// disk I/O off the WinUI 3 UI thread (ADR 0016, Linux `runtime.rs` parity).
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("totaldrop-win")
        .build()
        .unwrap_or_else(|_| std::process::abort())
});

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

static SESSIONS: LazyLock<Mutex<HashMap<u64, Arc<SessionEntry>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// JSON-deserializable network config allowing omitted optional fields to fall
/// back to [`BridgeNetworkConfig::default`] while preserving explicit empty
/// strings (e.g. `"relay_server": ""`, `"stun_server": ""` in loopback tests).
#[derive(Debug, Deserialize)]
pub(crate) struct FfiNetworkConfig {
    rendezvous_server: Option<String>,
    relay_server: Option<String>,
    stun_server: Option<String>,
    #[serde(default)]
    privacy_relay_only: bool,
    #[serde(default)]
    stronger_three_word_code: bool,
}

impl FfiNetworkConfig {
    pub(crate) fn into_bridge_config(self) -> BridgeNetworkConfig {
        let defaults = BridgeNetworkConfig::default();
        BridgeNetworkConfig {
            rendezvous_server: self.rendezvous_server.unwrap_or(defaults.rendezvous_server),
            relay_server: self.relay_server.unwrap_or(defaults.relay_server),
            stun_server: self.stun_server.unwrap_or(defaults.stun_server),
            privacy_relay_only: self.privacy_relay_only,
            stronger_three_word_code: self.stronger_three_word_code,
        }
    }
}

/// NDJSON event emitted by `totaldrop_win_session_poll_events_ndjson`.
///
/// Tagged with `"event"` in `snake_case` and `is_text` uniformly across
/// `code_ready`, `offer_ready`, `done`, and `declined` for reflection-free
/// `.NET 10` source-generated deserialization.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum SessionEvent {
    CodeReady {
        code: ValidatedCode,
        share_text: String,
        files: usize,
        dirs: usize,
        total_bytes: u64,
        formatted_total: String,
        skipped: usize,
        is_text: bool,
    },
    Waiting {
        caption: String,
    },
    Connected {
        verification_words: Vec<String>,
        joined_words_ltr: String,
    },
    OfferReady {
        files: usize,
        dirs: usize,
        total_bytes: u64,
        formatted_total: String,
        is_text: bool,
        top_level: Vec<String>,
        top_level_sanitized: Vec<String>,
        more_count: usize,
        verification_words: Vec<String>,
        joined_words_ltr: String,
    },
    Progress {
        done_bytes: u64,
        total_bytes: u64,
        formatted_done: String,
        formatted_total: String,
        percent: RegionalPercent,
    },
    Done {
        files_ok: usize,
        files_failed: usize,
        bytes: u64,
        formatted_bytes: String,
        is_text: bool,
        saved_to: Option<String>,
        placed: Vec<String>,
        received_text: Option<String>,
        sanitized_text: Option<SanitizedPeerText>,
    },
    Declined {
        is_text: bool,
        summary: String,
    },
    Failed {
        kind: String,
        l10n_key: String,
        cause: String,
        summary: String,
        cause_detail: Option<String>,
        technical_english: String,
    },
}

impl SessionEvent {
    fn from_localized_error(err: LocalizedTransferError) -> Self {
        Self::Failed {
            kind: err.kind,
            l10n_key: err.l10n_key,
            cause: err.cause,
            summary: err.summary,
            cause_detail: err.cause_detail,
            technical_english: err.technical_english,
        }
    }

    fn from_view_event(event: TransferViewEvent) -> Self {
        match event {
            TransferViewEvent::Waiting { caption } => Self::Waiting { caption },
            TransferViewEvent::Connected {
                verification_words,
                joined_words_ltr,
            } => Self::Connected {
                verification_words,
                joined_words_ltr,
            },
            TransferViewEvent::Progress {
                done_bytes,
                total_bytes,
                formatted_done,
                formatted_total,
                percent,
            } => Self::Progress {
                done_bytes,
                total_bytes,
                formatted_done,
                formatted_total,
                percent,
            },
        }
    }
}

struct SessionInner {
    events: VecDeque<SessionEvent>,
    pending_offer: Option<IncomingOffer>,
    terminal: bool,
    destroyed: bool,
}

struct SessionEntry {
    cancel: WindowsCancellationToken,
    localizer: Arc<WindowsLocalizer>,
    state: Mutex<SessionInner>,
}

impl SessionEntry {
    fn new(localizer: WindowsLocalizer) -> Arc<Self> {
        Arc::new(Self {
            cancel: WindowsCancellationToken::new(),
            localizer: Arc::new(localizer),
            state: Mutex::new(SessionInner {
                events: VecDeque::new(),
                pending_offer: None,
                terminal: false,
                destroyed: false,
            }),
        })
    }

    fn push_event(&self, event: SessionEvent) {
        if let Ok(mut inner) = self.state.lock()
            && !inner.destroyed
            && !inner.terminal
        {
            inner.events.push_back(event);
        }
    }

    fn finish_with(&self, event: SessionEvent) {
        if let Ok(mut inner) = self.state.lock()
            && !inner.destroyed
            && !inner.terminal
        {
            inner.terminal = true;
            inner.events.push_back(event);
        }
    }

    fn is_destroyed(&self) -> bool {
        self.state.lock().is_ok_and(|inner| inner.destroyed)
    }

    fn make_core_events(self: &Arc<Self>) -> totaldrop_core::Events {
        let weak = Arc::downgrade(self);
        Arc::new(move |core_event: Event| {
            if let Some(entry) = weak.upgrade() {
                let view = TransferViewEvent::from_core_event(core_event, &entry.localizer);
                entry.push_event(SessionEvent::from_view_event(view));
            }
        })
    }
}

fn alloc_session(localizer: WindowsLocalizer) -> Option<(u64, Arc<SessionEntry>)> {
    let mut sid = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    if sid == 0 {
        sid = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    }
    let entry = SessionEntry::new(localizer);
    let mut table = SESSIONS.lock().ok()?;
    table.insert(sid, Arc::clone(&entry));
    Some((sid, entry))
}

fn lookup_session(session_id: u64) -> Option<Arc<SessionEntry>> {
    if session_id == 0 {
        return None;
    }
    SESSIONS.lock().ok()?.get(&session_id).cloned()
}

fn clean_display_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        raw
    }
}

fn resolve_send_paths(raw_paths: Vec<String>) -> Result<Vec<PathBuf>, String> {
    #[cfg(windows)]
    {
        let normalized = totaldrop_windows_bridge::validate_windows_paths(&raw_paths)
            .map_err(|e| e.to_string())?;
        Ok(normalized
            .into_iter()
            .map(|p| PathBuf::from(p.extended_path))
            .collect())
    }
    #[cfg(not(windows))]
    {
        let mut out = Vec::with_capacity(raw_paths.len());
        for raw in raw_paths {
            if raw.is_empty() {
                return Err("send path must not be empty".to_owned());
            }
            if raw.as_bytes().contains(&0) {
                return Err("send path must not contain a NUL byte".to_owned());
            }
            out.push(PathBuf::from(raw));
        }
        Ok(out)
    }
}

/// Starts an asynchronous file/folder send session and returns a non-zero
/// monotonic handle (`0` on internal registration failure).
pub(crate) fn start_send_files(
    cfg: BridgeNetworkConfig,
    raw_paths: Vec<String>,
    localizer: WindowsLocalizer,
) -> u64 {
    let Some((sid, entry)) = alloc_session(localizer) else {
        return 0;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let paths = match resolve_send_paths(raw_paths) {
            Ok(p) => p,
            Err(msg) => {
                entry.finish_with(SessionEvent::Failed {
                    kind: "storage".to_owned(),
                    l10n_key: "errorStorage".to_owned(),
                    cause: String::new(),
                    summary: entry.localizer.text("errorStorage"),
                    cause_detail: None,
                    technical_english: msg,
                });
                return;
            }
        };

        let prepared = match prepare_windows_send(&cfg, paths, &entry.cancel).await {
            Ok(p) => p,
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        let code = ValidatedCode::from_proto(prepared.code());
        let (files, total_bytes) = prepared.totals();
        let skipped = prepared.skipped();
        let share_text = entry.localizer.format_share_text(&code.display_english);
        let formatted_total = entry.localizer.format_bytes(total_bytes);

        entry.push_event(SessionEvent::CodeReady {
            code,
            share_text,
            files,
            dirs: 0,
            total_bytes,
            formatted_total,
            skipped,
            is_text: false,
        });

        let events = entry.make_core_events();
        let stop = entry.cancel.as_core_stop().clone();
        match prepared.run_with(events, stop).await {
            Ok(report) => {
                let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                entry.finish_with(SessionEvent::Done {
                    files_ok: report.files_ok,
                    files_failed: report.files_failed,
                    bytes: report.bytes,
                    formatted_bytes,
                    is_text: false,
                    saved_to: None,
                    placed: Vec::new(),
                    received_text: None,
                    sanitized_text: None,
                });
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    sid
}

/// Starts an asynchronous plain-text send session (`MAX_TEXT = 1_048_576` UTF-8
/// bytes) and returns a non-zero monotonic handle.
pub(crate) fn start_send_text(
    cfg: BridgeNetworkConfig,
    text: String,
    localizer: WindowsLocalizer,
) -> u64 {
    let Some((sid, entry)) = alloc_session(localizer) else {
        return 0;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_TEXT {
            let localized = LocalizedTransferError::text_too_long(&entry.localizer);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let prepared = match prepare_windows_text_send(&cfg, &text, TEXT_FILE, &entry.cancel).await
        {
            Ok(p) => p,
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        let code = ValidatedCode::from_proto(prepared.code());
        let (files, total_bytes) = prepared.totals();
        let share_text = entry.localizer.format_share_text(&code.display_english);
        let formatted_total = entry.localizer.format_bytes(total_bytes);

        entry.push_event(SessionEvent::CodeReady {
            code,
            share_text,
            files,
            dirs: 0,
            total_bytes,
            formatted_total,
            skipped: 0,
            is_text: true,
        });

        let events = entry.make_core_events();
        let stop = entry.cancel.as_core_stop().clone();
        match prepared.run_with(events, stop).await {
            Ok(report) => {
                if report.files_failed > 0 {
                    let localized = LocalizedTransferError::text_damaged(&entry.localizer);
                    entry.finish_with(SessionEvent::from_localized_error(localized));
                } else {
                    let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                    entry.finish_with(SessionEvent::Done {
                        files_ok: report.files_ok,
                        files_failed: report.files_failed,
                        bytes: report.bytes,
                        formatted_bytes,
                        is_text: true,
                        saved_to: None,
                        placed: Vec::new(),
                        received_text: None,
                        sanitized_text: None,
                    });
                }
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    sid
}

/// Starts an asynchronous receive connection and emits `offer_ready` or
/// `failed`.
pub(crate) fn start_receive_connect(
    cfg: BridgeNetworkConfig,
    code_or_uri: String,
    localizer: WindowsLocalizer,
) -> u64 {
    let Some((sid, entry)) = alloc_session(localizer) else {
        return 0;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let offer = match connect_windows_receive(&cfg, &code_or_uri, &entry.cancel).await {
            Ok(o) => o,
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        if entry.cancel.is_cancelled() || entry.is_destroyed() {
            let err = offer.stop().await;
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let summary = offer.summary();
        let top_level = summary.top_level.clone();
        let top_level_sanitized: Vec<String> = top_level
            .iter()
            .map(|name| sanitize_peer_filename(name))
            .collect();
        let more_count = top_level.len().saturating_sub(5);
        let verification_words = offer.words().to_vec();
        let joined_words_ltr = verification_words.join("  ");
        let formatted_total = entry.localizer.format_bytes(summary.total_size);
        let offer_event = SessionEvent::OfferReady {
            files: summary.files,
            dirs: summary.dirs,
            total_bytes: summary.total_size,
            formatted_total,
            is_text: summary.text,
            top_level,
            top_level_sanitized,
            more_count,
            verification_words,
            joined_words_ltr,
        };

        let mut should_stop = None;
        if let Ok(mut inner) = entry.state.lock() {
            if inner.destroyed || inner.terminal || entry.cancel.is_cancelled() {
                should_stop = Some(offer);
            } else {
                inner.pending_offer = Some(offer);
                inner.events.push_back(offer_event);
            }
        } else {
            should_stop = Some(offer);
        }

        if let Some(unwanted) = should_stop {
            let _ = unwanted.stop().await;
        }
    });

    sid
}

/// Accepts a pending file/folder offer and writes verified files under
/// `dest_dir`.
pub(crate) fn accept_receive_files(session_id: u64, dest_dir: String) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed || inner.terminal {
            return FFI_ERR_INVALID_STATE;
        }
        let Some(ref pending) = inner.pending_offer else {
            return FFI_ERR_INVALID_STATE;
        };
        if pending.summary().text {
            return FFI_ERR_INVALID_STATE;
        }
        inner.pending_offer.take()
    };

    let Some(offer) = offer else {
        return FFI_ERR_INVALID_STATE;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let dest = PathBuf::from(&dest_dir);
        if std::fs::symlink_metadata(&dest).is_err()
            && let Err(io_err) = std::fs::create_dir_all(&dest)
        {
            let _ = offer.stop().await;
            let core_err = CoreError::Io(io_err);
            let localized =
                LocalizedTransferError::from_core_error(&core_err, &entry.localizer, false);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let checked_dest = match check_windows_destination(&dest) {
            Ok(canonical) => canonical,
            Err(err) => {
                let _ = offer.stop().await;
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        let events = entry.make_core_events();
        let stop = entry.cancel.as_core_stop().clone();
        match offer.accept_with(&checked_dest, events, &stop).await {
            Ok(report) => {
                let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                let placed = report
                    .placed
                    .iter()
                    .map(|p| clean_display_path(p))
                    .collect();
                entry.finish_with(SessionEvent::Done {
                    files_ok: report.files_ok,
                    files_failed: report.files_failed,
                    bytes: report.bytes,
                    formatted_bytes,
                    is_text: false,
                    saved_to: Some(clean_display_path(&checked_dest)),
                    placed,
                    received_text: None,
                    sanitized_text: None,
                });
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    FFI_OK
}

/// Accepts a pending plain-text offer strictly in memory (zero disk writes),
/// mapping `report.text == None` to `TextDamaged` (`errorTextDamaged`).
pub(crate) fn accept_receive_text(session_id: u64) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed || inner.terminal {
            return FFI_ERR_INVALID_STATE;
        }
        let Some(ref pending) = inner.pending_offer else {
            return FFI_ERR_INVALID_STATE;
        };
        if !pending.summary().text {
            return FFI_ERR_INVALID_STATE;
        }
        inner.pending_offer.take()
    };

    let Some(offer) = offer else {
        return FFI_ERR_INVALID_STATE;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let stop = entry.cancel.as_core_stop().clone();
        match offer.accept_text_with(&stop).await {
            Ok(report) => {
                if let Some(raw_text) = report.text {
                    let sanitized = sanitize_peer_text(&raw_text);
                    let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                    entry.finish_with(SessionEvent::Done {
                        files_ok: report.files_ok,
                        files_failed: report.files_failed,
                        bytes: report.bytes,
                        formatted_bytes,
                        is_text: true,
                        saved_to: None,
                        placed: Vec::new(),
                        received_text: Some(raw_text),
                        sanitized_text: Some(sanitized),
                    });
                } else {
                    let localized = LocalizedTransferError::text_damaged(&entry.localizer);
                    entry.finish_with(SessionEvent::from_localized_error(localized));
                }
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    FFI_OK
}

/// Declines a pending incoming offer cleanly and emits `declined`.
pub(crate) fn decline_receive(session_id: u64) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed || inner.terminal {
            return FFI_ERR_INVALID_STATE;
        }
        let Some(offer) = inner.pending_offer.take() else {
            return FFI_ERR_INVALID_STATE;
        };
        let is_text = offer.summary().text;
        let summary_key = if is_text {
            "receiveTextDeclined"
        } else {
            "receiveDeclined"
        };
        inner.terminal = true;
        inner.events.push_back(SessionEvent::Declined {
            is_text,
            summary: entry.localizer.text(summary_key),
        });
        offer
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let _ = offer.decline().await;
    });

    FFI_OK
}

/// Drains queued events for `session_id` in FIFO order into `\n`-terminated
/// NDJSON. Returns `None` if `session_id` is unknown or destroyed.
pub(crate) fn poll_session_events_ndjson(session_id: u64) -> Option<String> {
    let entry = lookup_session(session_id)?;
    let drained: Vec<SessionEvent> = {
        let mut inner = entry.state.lock().ok()?;
        if inner.destroyed {
            return None;
        }
        inner.events.drain(..).collect()
    };

    let mut out = String::new();
    for ev in drained {
        if let Ok(line) = serde_json::to_string(&ev) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    Some(out)
}

/// Cancels an active session cooperatively. Idempotent (`0`) if the session
/// already reached a terminal state (`Done`, `Declined`, `Failed`).
pub(crate) fn cancel_session(session_id: u64) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let pending_offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed {
            return FFI_ERR_INVALID_HANDLE;
        }
        if inner.terminal {
            return FFI_OK;
        }
        entry.cancel.cancel();
        let taken = inner.pending_offer.take();
        if taken.is_some() {
            inner.terminal = true;
            let localized = LocalizedTransferError::from_core_error(
                &CoreError::Stopped,
                &entry.localizer,
                false,
            );
            inner
                .events
                .push_back(SessionEvent::from_localized_error(localized));
        }
        taken
    };

    if let Some(offer) = pending_offer {
        TRANSFERS.spawn(&RUNTIME, async move {
            let _ = offer.stop().await;
        });
    }

    FFI_OK
}

/// Removes a session from the handle table, cancels any active task, stops any
/// pending offer, and releases all queued events.
pub(crate) fn destroy_session(session_id: u64) -> i32 {
    if session_id == 0 {
        return FFI_ERR_INVALID_HANDLE;
    }
    let removed = match SESSIONS.lock() {
        Ok(mut table) => table.remove(&session_id),
        Err(_) => return crate::FFI_ERR_INTERNAL,
    };
    let Some(entry) = removed else {
        return FFI_ERR_INVALID_HANDLE;
    };

    entry.cancel.cancel();
    let pending_offer = if let Ok(mut inner) = entry.state.lock() {
        inner.destroyed = true;
        inner.terminal = true;
        inner.events.clear();
        inner.pending_offer.take()
    } else {
        None
    };

    if let Some(offer) = pending_offer {
        TRANSFERS.spawn(&RUNTIME, async move {
            let _ = offer.stop().await;
        });
    }

    FFI_OK
}

/// Executes Linux `quit.rs`-parity graceful shutdown across all live sessions
/// and tracked transfer tasks, awaiting `totaldrop_core::portmap::released()`.
///
/// Keeps the static 2-thread Tokio runtime reusable across subsequent calls.
pub(crate) fn shutdown_all(timeout_ms: u32) -> i32 {
    let entries: Vec<Arc<SessionEntry>> = match SESSIONS.lock() {
        Ok(mut table) => table.drain().map(|(_, entry)| entry).collect(),
        Err(_) => return crate::FFI_ERR_INTERNAL,
    };

    for entry in entries {
        entry.cancel.cancel();
        let pending_offer = if let Ok(mut inner) = entry.state.lock() {
            inner.destroyed = true;
            inner.terminal = true;
            inner.events.clear();
            inner.pending_offer.take()
        } else {
            None
        };
        if let Some(offer) = pending_offer {
            TRANSFERS.spawn(&RUNTIME, async move {
                let _ = offer.stop().await;
            });
        }
    }

    let stopping = if timeout_ms == 0 {
        STOPPING
    } else {
        Duration::from_millis(u64::from(timeout_ms))
    };

    let _ = RUNTIME.block_on(quit::finish(
        &TRANSFERS,
        totaldrop_core::portmap::released(),
        stopping,
    ));

    FFI_OK
}
