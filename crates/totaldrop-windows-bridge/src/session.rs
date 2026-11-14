// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bridge over [`totaldrop_core`] options, progress projections, error
//! mapping, and TotalDrop's platform-invariant brand mark motion (`Kose`,
//! ADR 0016 & `docs/tasarim.md`).

use serde::{Deserialize, Serialize};
use totaldrop_core::{Cause, Error as CoreError, Event, PathOptions, ReceiveOptions, SendOptions};

use crate::l10n::{RegionalPercent, WindowsLocalizer};

/// TotalDrop brand mark (`Kose`) SVG path on its 112x112 unit canvas
/// (`docs/tasarim.md`). Never mirrored in right-to-left layouts.
pub const MARK_SVG_PATH: &str = "M55 15H97V57A42 42 0 1 1 55 15Z";

/// TotalDrop brand mark color on light backgrounds (`#6D4AE0`).
pub const MARK_HEX_LIGHT: &str = "#6D4AE0";

/// TotalDrop brand mark color on dark backgrounds (`#A68BFF`).
pub const MARK_HEX_DARK: &str = "#A68BFF";

/// Full 4-quarter rotation cycle duration of the `Kose` mark during an active
/// transfer (`3200 ms`, `docs/tasarim.md`).
pub const MARK_CYCLE_MS: u32 = 3200;

/// Duration of each 90-degree quarter step (`600 ms` turn + `200 ms` dwell =
/// `800 ms`).
pub const MARK_QUARTER_MS: u32 = 800;

/// Validated settings snapshot shared between WinUI 3 Settings and
/// [`totaldrop_core::SendOptions`] / [`totaldrop_core::ReceiveOptions`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeNetworkConfig {
    /// Rendezvous WebSocket URL (`wss://…`).
    pub rendezvous_server: String,
    /// Relay WebSocket URL (`wss://…`), or empty to disable relay fallback.
    pub relay_server: String,
    /// STUN endpoint (`host:port`), or empty to disable STUN discovery.
    pub stun_server: String,
    /// Privacy mode: route exclusively over the relay so the peer never sees
    /// this PC's IP address.
    pub privacy_relay_only: bool,
    /// Stronger 3-word transfer code toggle (`true` -> 3 words, `false` -> 2
    /// words).
    pub stronger_three_word_code: bool,
}

impl Default for BridgeNetworkConfig {
    fn default() -> Self {
        let send_defaults = SendOptions::default();
        Self {
            rendezvous_server: send_defaults.server,
            relay_server: send_defaults.paths.relay,
            stun_server: send_defaults.paths.stun,
            privacy_relay_only: send_defaults.paths.relay_only,
            stronger_three_word_code: false,
        }
    }
}

impl BridgeNetworkConfig {
    /// Checks that user-configured rendezvous and relay URLs start with
    /// `wss://` (or `ws://127.0.0.1` / `ws://[::1]` for local loopback testing).
    #[must_use]
    pub fn is_valid_rendezvous_url(url: &str) -> bool {
        let trimmed = url.trim();
        trimmed.starts_with("wss://")
            || trimmed.starts_with("ws://127.0.0.1:")
            || trimmed.starts_with("ws://[::1]:")
            || trimmed.starts_with("ws://localhost:")
    }

    /// Converts this configuration into [`totaldrop_core::SendOptions`].
    #[must_use]
    pub fn to_send_options(&self) -> SendOptions {
        SendOptions {
            server: self.rendezvous_server.clone(),
            words: if self.stronger_three_word_code { 3 } else { 2 },
            paths: self.to_path_options(),
        }
    }

    /// Converts this configuration into [`totaldrop_core::ReceiveOptions`].
    #[must_use]
    pub fn to_receive_options(&self) -> ReceiveOptions {
        ReceiveOptions {
            server: self.rendezvous_server.clone(),
            paths: self.to_path_options(),
        }
    }

    /// Converts this configuration into [`totaldrop_core::PathOptions`].
    #[must_use]
    pub fn to_path_options(&self) -> PathOptions {
        PathOptions {
            relay: self.relay_server.clone(),
            stun: self.stun_server.clone(),
            relay_only: self.privacy_relay_only,
            gateway: totaldrop_core::portmap::Gateway::Auto,
        }
    }
}

/// Read-only view-model projection of a [`totaldrop_core::Event`] formatted for
/// WinUI 3 `x:Bind` and Windows Narrator UI Automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransferViewEvent {
    /// Waiting in the rendezvous mailbox for the receiver to enter the code.
    Waiting {
        /// Localized status caption (`sendWaiting`).
        caption: String,
    },
    /// CPace + QUIC + Noise XXpsk3 + ML-KEM-768 session established.
    Connected {
        /// Four English verification words (`FlowDirection.LeftToRight`, spoken
        /// with an `en` locale voice by Windows Narrator).
        verification_words: Vec<String>,
        /// Space-joined English verification words.
        joined_words_ltr: String,
    },
    /// Chunked STREAM transfer progress update (`#483`).
    Progress {
        /// Raw bytes completed.
        done_bytes: u64,
        /// Total bytes in transfer.
        total_bytes: u64,
        /// Region-formatted completed size (`"12 MB"`, `"1,5 MB"`).
        formatted_done: String,
        /// Region-formatted total size.
        formatted_total: String,
        /// Rounded-down regional percentage (`whole` + `formatted`).
        percent: RegionalPercent,
    },
}

impl TransferViewEvent {
    /// Projects a [`totaldrop_core::Event`] using `localizer`'s display
    /// language and Windows regional number/percent rules.
    #[must_use]
    pub fn from_core_event(event: Event, localizer: &WindowsLocalizer) -> Self {
        match event {
            Event::Waiting => Self::Waiting {
                caption: localizer.text("sendWaiting"),
            },
            Event::Connected { words } => {
                let joined_words_ltr = words.join("  ");
                Self::Connected {
                    verification_words: words,
                    joined_words_ltr,
                }
            }
            Event::Progress { done, total } => Self::Progress {
                done_bytes: done,
                total_bytes: total,
                formatted_done: localizer.format_bytes(done),
                formatted_total: localizer.format_bytes(total),
                percent: localizer.format_percent(done, total),
            },
        }
    }
}

/// Localized failure summary for WinUI 3 error banners, keeping the underlying
/// technical detail in English for bug reports (`technicalDetail`, ADR 0019).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedTransferError {
    /// Primary localized message shown to the user.
    pub summary: String,
    /// Optional localized plain-language explanation (`causeTimedOut`, …).
    pub cause_detail: Option<String>,
    /// Unmodified English technical string for problem reports.
    pub technical_english: String,
}

impl LocalizedTransferError {
    /// Maps a [`totaldrop_core::Error`] and its [`Cause`] into localized user
    /// text while preserving `err.to_string()` in English.
    #[must_use]
    pub fn from_core_error(err: &CoreError, localizer: &WindowsLocalizer) -> Self {
        let primary_key = match err {
            CoreError::WrongCode => "errorWrongCode",
            CoreError::PeerLeft => "errorPeerLeft",
            CoreError::Rendezvous(_) => "errorServer",
            CoreError::Connect(_) => "errorConnect",
            CoreError::Protocol(_) => "errorOther",
            CoreError::InvalidOffer(_) => "errorInvalidOffer",
            CoreError::Rejected(_) => "errorDeclined",
            CoreError::Cancelled(_) => "errorCancelled",
            CoreError::Stopped => "errorStopped",
            CoreError::Io(_) => "errorStorage",
            CoreError::Code(_) => "errorInvalidCode",
            CoreError::Random => "errorOther",
        };
        let cause = err.cause();
        let cause_detail = if cause == Cause::Unknown {
            None
        } else {
            let cause_key = format!("cause{}", cause.as_str());
            Some(localizer.text(&cause_key))
        };
        Self {
            summary: localizer.text(primary_key),
            cause_detail,
            technical_english: err.to_string(),
        }
    }
}

/// Determines whether the TotalDrop `Kose` mark should play its 3.2-second
/// quarter-turn animation given transfer state and Windows'
/// `UISettings.AnimationsEnabled` accessibility setting (ADR 0016).
#[must_use]
pub const fn should_animate_mark(transfer_running: bool, windows_animations_enabled: bool) -> bool {
    transfer_running && windows_animations_enabled
}
