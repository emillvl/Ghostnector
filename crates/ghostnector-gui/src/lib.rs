#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `ghostnector-gui` — the GTK4 presentation client.
//!
//! It is a **client of the control plane, never an authority**. `Snapshot` is the only source of
//! protection state; this crate renders it and forwards user actions. It holds no privilege, is
//! never exempt from policy, and never talks to `netd` or `appd`.
//!
//! The crate is split so that everything except the widgets is testable without a display:
//!
//! * [`model`] — the state-to-view mapping, the action vocabulary, and the refusal matrix. Pure.
//! * [`client`] — the real core connection (control + subscription) and its reconnect epochs.
//! * `app` — the GTK widgets, behind the `gtk` feature (Linux release builds only).

pub mod client;
pub mod model;

#[cfg(all(unix, feature = "gtk"))]
pub mod app;
