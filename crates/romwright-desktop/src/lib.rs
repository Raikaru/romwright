//! Romwright desktop: the egui shell, its panels, and the offscreen wgpu
//! driver. The binary in `main.rs` is a thin command-line front; panels and
//! tools build on the modules here (see `PANELS.md`).

pub mod address;
pub mod app;
pub mod code;
pub mod gate;
pub mod headless;
pub mod jobs;
pub mod nav;
pub mod panel;
pub mod panels;
pub mod projects;
pub mod service;
pub mod settings;
pub mod table;
pub mod theme;
pub mod widgets;
