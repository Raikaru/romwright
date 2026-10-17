//! The design system every panel draws with: colour tokens, the type scale,
//! the spacing grid and egui style installation. Panels take colours and
//! sizes from here (`cx.theme`) and never hard-code them; see `PANELS.md`.
//!
//! Layered neutrals (app → panel → raised → hover → selected), one accent,
//! semantic syntax colours shared by every code view, and state colours.
//! Dark is the default; light follows the system preference or the View
//! menu; high contrast is kept from the Qt workbench for accessibility.

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow, Stroke,
    TextStyle, Visuals, style::ScrollStyle,
};
use std::sync::Arc;

/// Spacing grid (px). Every margin, gap and padding is one of these.
pub mod space {
    pub const XXS: f32 = 2.0;
    pub const XS: f32 = 4.0;
    pub const SM: f32 = 8.0;
    pub const MD: f32 = 12.0;
    pub const LG: f32 = 16.0;
    pub const XL: f32 = 24.0;
}

/// Component metrics.
pub mod metrics {
    /// Table / list row height.
    pub const ROW: f32 = 24.0;
    /// Code line height (listing, decompiler).
    pub const CODE_ROW: f32 = 20.0;
    /// Inputs, buttons and popups.
    pub const RADIUS: u8 = 6;
    /// Small chips, highlights.
    pub const RADIUS_SM: u8 = 4;
    /// Toolbar height.
    pub const TOOLBAR: f32 = 44.0;
    /// Status bar height.
    pub const STATUS_BAR: f32 = 26.0;
    /// Tab strip height.
    pub const TAB_BAR: f32 = 32.0;
    /// Address input width in characters.
    pub const ADDRESS_CHARS: f32 = 16.0;
}

/// The small type scale. UI text is Inter; code is JetBrains Mono.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    /// 11 px: captions, column headers, badges.
    Caption,
    /// 13 px: body text, table cells, buttons.
    Body,
    /// 13 px medium: emphasised body, active tabs.
    Strong,
    /// 15 px semibold: panel titles, dialog headings.
    Title,
    /// 13 px mono: listings, source, addresses.
    Code,
    /// 12 px mono: dense code (bytes, gutters).
    CodeSmall,
}

const INTER_MEDIUM: &str = "inter-medium";
const INTER_SEMIBOLD: &str = "inter-semibold";
const MONO_BOLD: &str = "mono-bold";

pub fn font(kind: Type) -> FontId {
    match kind {
        Type::Caption => FontId::new(11.5, FontFamily::Name(INTER_MEDIUM.into())),
        Type::Body => FontId::new(13.0, FontFamily::Proportional),
        Type::Strong => FontId::new(13.0, FontFamily::Name(INTER_MEDIUM.into())),
        Type::Title => FontId::new(15.0, FontFamily::Name(INTER_SEMIBOLD.into())),
        Type::Code => FontId::new(13.0, FontFamily::Monospace),
        Type::CodeSmall => FontId::new(12.0, FontFamily::Monospace),
    }
}

/// Bold monospace for emphasised code (function headers).
pub fn code_bold() -> FontId {
    FontId::new(13.0, FontFamily::Name(MONO_BOLD.into()))
}

/// Semantic token kinds shared by every code view: the same kind is the
/// same colour in the listing, the decompiler and any later view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Syntax {
    Plain,
    Keyword,
    Type,
    Function,
    Address,
    Register,
    Constant,
    String,
    Comment,
    Warning,
    Mnemonic,
    Variable,
    Label,
    Punctuation,
    /// Instruction bytes and other secondary code text.
    Dim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeName {
    Dark,
    Light,
    Contrast,
}

impl ThemeName {
    pub const ALL: [ThemeName; 3] = [ThemeName::Dark, ThemeName::Light, ThemeName::Contrast];

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "contrast" => Some(Self::Contrast),
            _ => None,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::Contrast => "contrast",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Dark => "Dark",
            Self::Light => "Light",
            Self::Contrast => "High contrast",
        }
    }
}

/// The user's choice: a fixed theme or whatever the system prefers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeChoice {
    System,
    Fixed(ThemeName),
}

impl ThemeChoice {
    pub fn parse(text: &str) -> Option<Self> {
        if text == "system" { Some(Self::System) } else { ThemeName::parse(text).map(Self::Fixed) }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Fixed(name) => name.key(),
        }
    }

    /// Resolves against the system preference (`None` when unknown → dark).
    pub fn resolve(self, system: Option<egui::Theme>) -> ThemeName {
        match self {
            Self::Fixed(name) => name,
            Self::System => match system {
                Some(egui::Theme::Light) => ThemeName::Light,
                _ => ThemeName::Dark,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct Theme {
    pub name: ThemeName,
    // Layered neutrals, darkest (dark theme) to most prominent.
    /// Window background behind docks.
    pub bg_app: Color32,
    /// Code canvases (listing, source).
    pub bg_code: Color32,
    /// Dock bodies, tables.
    pub bg_panel: Color32,
    /// Toolbars, tab strips, headers, popups, inputs.
    pub bg_raised: Color32,
    pub bg_hover: Color32,
    pub bg_selected: Color32,
    /// Zebra stripe overlay.
    pub bg_stripe: Color32,
    /// Subtle 1 px separator.
    pub border: Color32,
    /// Focused input outline / strong separator.
    pub border_strong: Color32,
    // Text.
    pub text: Color32,
    pub text_muted: Color32,
    pub text_faint: Color32,
    // The one accent.
    pub accent: Color32,
    pub accent_hover: Color32,
    /// Text on an accent fill.
    pub on_accent: Color32,
    /// Translucent accent for selections and occurrence highlights.
    pub accent_soft: Color32,
    /// Current code line.
    pub current_line: Color32,
    // State.
    pub ok: Color32,
    pub warn: Color32,
    pub error: Color32,
    // Syntax.
    pub syntax_plain: Color32,
    pub syntax_keyword: Color32,
    pub syntax_type: Color32,
    pub syntax_function: Color32,
    pub syntax_address: Color32,
    pub syntax_register: Color32,
    pub syntax_constant: Color32,
    pub syntax_string: Color32,
    pub syntax_comment: Color32,
    pub syntax_warning: Color32,
    pub syntax_mnemonic: Color32,
    pub syntax_variable: Color32,
    pub syntax_label: Color32,
    pub syntax_punctuation: Color32,
    pub syntax_dim: Color32,
}

const fn rgb(value: u32) -> Color32 {
    Color32::from_rgb((value >> 16) as u8, (value >> 8) as u8, value as u8)
}

const fn rgba(value: u32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied_const((value >> 16) as u8, (value >> 8) as u8, value as u8, alpha)
}

impl Theme {
    pub fn new(name: ThemeName) -> Self {
        match name {
            ThemeName::Dark => Self {
                name,
                bg_app: rgb(0x0e1116),
                bg_code: rgb(0x0f1318),
                bg_panel: rgb(0x13171d),
                bg_raised: rgb(0x191e26),
                bg_hover: rgb(0x212834),
                bg_selected: rgb(0x1f3350),
                bg_stripe: rgba(0xffffff, 6),
                border: rgb(0x242b36),
                border_strong: rgb(0x3a4556),
                text: rgb(0xd5dce6),
                text_muted: rgb(0x8c97a6),
                text_faint: rgb(0x5d6878),
                accent: rgb(0x4c8dff),
                accent_hover: rgb(0x6aa1ff),
                on_accent: rgb(0xffffff),
                accent_soft: rgba(0x4c8dff, 46),
                current_line: rgba(0x4c8dff, 28),
                ok: rgb(0x5fc28a),
                warn: rgb(0xe3b25a),
                error: rgb(0xef6b73),
                syntax_plain: rgb(0xd5dce6),
                syntax_keyword: rgb(0xc792ea),
                syntax_type: rgb(0x5fd1c5),
                syntax_function: rgb(0x82aaff),
                syntax_address: rgb(0x6f9fd8),
                syntax_register: rgb(0xf0a868),
                syntax_constant: rgb(0xf78c6c),
                syntax_string: rgb(0xa5d68a),
                syntax_comment: rgb(0x637082),
                syntax_warning: rgb(0xe3b25a),
                syntax_mnemonic: rgb(0xc792ea),
                syntax_variable: rgb(0xe6cf8e),
                syntax_label: rgb(0x82aaff),
                syntax_punctuation: rgb(0x8c97a6),
                syntax_dim: rgb(0x5d6878),
            },
            ThemeName::Light => Self {
                name,
                bg_app: rgb(0xeef1f5),
                bg_code: rgb(0xffffff),
                bg_panel: rgb(0xffffff),
                bg_raised: rgb(0xf6f8fa),
                bg_hover: rgb(0xeaeef3),
                bg_selected: rgb(0xdbe8fd),
                bg_stripe: rgba(0x0b1a33, 7),
                border: rgb(0xdde2e9),
                border_strong: rgb(0xbac3cf),
                text: rgb(0x1d2430),
                text_muted: rgb(0x5d6878),
                text_faint: rgb(0x98a2b0),
                accent: rgb(0x2563eb),
                accent_hover: rgb(0x1d4fd0),
                on_accent: rgb(0xffffff),
                accent_soft: rgba(0x2563eb, 36),
                current_line: rgba(0x2563eb, 22),
                ok: rgb(0x1f8a4c),
                warn: rgb(0xa86500),
                error: rgb(0xc93743),
                syntax_plain: rgb(0x1d2430),
                syntax_keyword: rgb(0x8839c9),
                syntax_type: rgb(0x0b7b74),
                syntax_function: rgb(0x2457c5),
                syntax_address: rgb(0x3d6aa8),
                syntax_register: rgb(0xb2560e),
                syntax_constant: rgb(0xc2410c),
                syntax_string: rgb(0x2f7d32),
                syntax_comment: rgb(0x8a94a3),
                syntax_warning: rgb(0xa86500),
                syntax_mnemonic: rgb(0x8839c9),
                syntax_variable: rgb(0x8a5a00),
                syntax_label: rgb(0x2457c5),
                syntax_punctuation: rgb(0x6b7585),
                syntax_dim: rgb(0x98a2b0),
            },
            ThemeName::Contrast => Self {
                name,
                bg_app: rgb(0x000000),
                bg_code: rgb(0x000000),
                bg_panel: rgb(0x000000),
                bg_raised: rgb(0x101010),
                bg_hover: rgb(0x2a2a2a),
                bg_selected: rgb(0x003a80),
                bg_stripe: rgba(0xffffff, 14),
                border: rgb(0x6a6a6a),
                border_strong: rgb(0xffffff),
                text: rgb(0xffffff),
                text_muted: rgb(0xd0d0d0),
                text_faint: rgb(0xa0a0a0),
                accent: rgb(0x00c8ff),
                accent_hover: rgb(0x60ddff),
                on_accent: rgb(0x000000),
                accent_soft: rgba(0x00c8ff, 70),
                current_line: rgba(0x00c8ff, 50),
                ok: rgb(0x00ff66),
                warn: rgb(0xffff00),
                error: rgb(0xff4040),
                syntax_plain: rgb(0xffffff),
                syntax_keyword: rgb(0xff80ff),
                syntax_type: rgb(0x00ffc0),
                syntax_function: rgb(0x80ffff),
                syntax_address: rgb(0x00ffff),
                syntax_register: rgb(0xffc040),
                syntax_constant: rgb(0xffa060),
                syntax_string: rgb(0x80ff80),
                syntax_comment: rgb(0xb0b0b0),
                syntax_warning: rgb(0xffff00),
                syntax_mnemonic: rgb(0xff80ff),
                syntax_variable: rgb(0xffff80),
                syntax_label: rgb(0x80ffff),
                syntax_punctuation: rgb(0xd0d0d0),
                syntax_dim: rgb(0xa0a0a0),
            },
        }
    }

    pub fn syntax(&self, kind: Syntax) -> Color32 {
        match kind {
            Syntax::Plain => self.syntax_plain,
            Syntax::Keyword => self.syntax_keyword,
            Syntax::Type => self.syntax_type,
            Syntax::Function => self.syntax_function,
            Syntax::Address => self.syntax_address,
            Syntax::Register => self.syntax_register,
            Syntax::Constant => self.syntax_constant,
            Syntax::String => self.syntax_string,
            Syntax::Comment => self.syntax_comment,
            Syntax::Warning => self.syntax_warning,
            Syntax::Mnemonic => self.syntax_mnemonic,
            Syntax::Variable => self.syntax_variable,
            Syntax::Label => self.syntax_label,
            Syntax::Punctuation => self.syntax_punctuation,
            Syntax::Dim => self.syntax_dim,
        }
    }

    /// Installs palette, metrics and type scale into egui.
    pub fn apply(&self, context: &egui::Context) {
        let radius = CornerRadius::same(metrics::RADIUS);
        context.set_theme(if self.name == ThemeName::Light { egui::Theme::Light } else { egui::Theme::Dark });
        context.all_styles_mut(|style| {
            style.text_styles = [
                (TextStyle::Small, font(Type::Caption)),
                (TextStyle::Body, font(Type::Body)),
                (TextStyle::Button, font(Type::Body)),
                (TextStyle::Heading, font(Type::Title)),
                (TextStyle::Monospace, font(Type::Code)),
            ]
            .into();
            let spacing = &mut style.spacing;
            spacing.item_spacing = egui::vec2(space::SM, space::XS + 2.0);
            spacing.button_padding = egui::vec2(space::MD - 2.0, space::XS + 1.0);
            spacing.interact_size = egui::vec2(24.0, 26.0);
            spacing.menu_margin = Margin::same(space::XS as i8 + 2);
            spacing.window_margin = Margin::same(space::LG as i8);
            spacing.icon_spacing = space::XS + 2.0;
            spacing.combo_height = 320.0;
            spacing.menu_width = 220.0;
            let mut scroll = ScrollStyle::floating();
            scroll.bar_width = 8.0;
            scroll.floating_width = 3.0;
            scroll.floating_allocated_width = 0.0;
            scroll.bar_inner_margin = 2.0;
            scroll.bar_outer_margin = 2.0;
            spacing.scroll = scroll;
            style.interaction.tooltip_delay = 0.35;
            style.interaction.selectable_labels = false;

            let mut visuals = match self.name {
                ThemeName::Light => Visuals::light(),
                ThemeName::Dark | ThemeName::Contrast => Visuals::dark(),
            };
            visuals.panel_fill = self.bg_panel;
            visuals.window_fill = self.bg_raised;
            visuals.window_stroke = Stroke::new(1.0, self.border);
            visuals.window_corner_radius = CornerRadius::same(metrics::RADIUS + 2);
            visuals.menu_corner_radius = radius;
            visuals.window_shadow = Shadow { offset: [0, 8], blur: 24, spread: 0, color: rgba(0x000000, 70) };
            visuals.popup_shadow = Shadow { offset: [0, 4], blur: 16, spread: 0, color: rgba(0x000000, 60) };
            visuals.extreme_bg_color = self.bg_app;
            visuals.text_edit_bg_color = Some(self.bg_app);
            visuals.faint_bg_color = self.bg_stripe;
            visuals.code_bg_color = self.bg_raised;
            visuals.override_text_color = None;
            visuals.weak_text_color = Some(self.text_muted);
            visuals.hyperlink_color = self.accent;
            visuals.error_fg_color = self.error;
            visuals.warn_fg_color = self.warn;
            visuals.selection.bg_fill = self.bg_selected;
            visuals.selection.stroke = Stroke::new(1.0, self.text);
            visuals.text_cursor.stroke = Stroke::new(1.5, self.accent);
            visuals.striped = true;
            visuals.collapsing_header_frame = false;
            visuals.indent_has_left_vline = false;
            visuals.button_frame = true;
            let widgets = &mut visuals.widgets;
            for (state, fill, stroke, text) in [
                (&mut widgets.noninteractive, self.bg_panel, self.border, self.text),
                (&mut widgets.inactive, self.bg_raised, self.border, self.text),
                (&mut widgets.hovered, self.bg_hover, self.border_strong, self.text),
                (&mut widgets.active, self.bg_selected, self.accent, self.text),
                (&mut widgets.open, self.bg_hover, self.border_strong, self.text),
            ] {
                state.bg_fill = fill;
                state.weak_bg_fill = fill;
                state.bg_stroke = Stroke::new(1.0, stroke);
                state.fg_stroke = Stroke::new(1.0, text);
                state.corner_radius = radius;
                state.expansion = 0.0;
            }
            widgets.noninteractive.fg_stroke = Stroke::new(1.0, self.text);
            widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.border);
            style.visuals = visuals;
        });
    }

    /// Tab strips and splitters for the dock area.
    pub fn dock_style(&self, egui_style: &egui::Style) -> egui_dock::Style {
        let mut style = egui_dock::Style::from_egui(egui_style);
        style.dock_area_padding = None;
        style.main_surface_border_stroke = Stroke::NONE;
        style.main_surface_border_rounding = CornerRadius::ZERO;
        style.separator.width = 1.0;
        style.separator.extra = 6.0;
        style.separator.color_idle = self.border;
        style.separator.color_hovered = self.accent;
        style.separator.color_dragged = self.accent;
        style.tab_bar.bg_fill = self.bg_raised;
        style.tab_bar.height = metrics::TAB_BAR;
        style.tab_bar.hline_color = self.border;
        style.tab_bar.corner_radius = CornerRadius::ZERO;
        style.tab_bar.fill_tab_bar = false;
        style.tab.spacing = 0.0;
        style.tab.minimum_width = Some(64.0);
        style.tab.hline_below_active_tab_name = true;
        style.tab.tab_body.bg_fill = self.bg_panel;
        style.tab.tab_body.stroke = Stroke::NONE;
        style.tab.tab_body.corner_radius = CornerRadius::ZERO;
        style.tab.tab_body.inner_margin = Margin::ZERO;
        for interaction in [
            &mut style.tab.inactive,
            &mut style.tab.inactive_with_kb_focus,
        ] {
            interaction.bg_fill = self.bg_raised;
            interaction.outline_color = Color32::TRANSPARENT;
            interaction.text_color = self.text_muted;
            interaction.corner_radius = CornerRadius::ZERO;
        }
        {
            let interaction = &mut style.tab.hovered;
            interaction.bg_fill = self.bg_hover;
            interaction.outline_color = Color32::TRANSPARENT;
            interaction.text_color = self.text;
            interaction.corner_radius = CornerRadius::ZERO;
        }
        for interaction in [
            &mut style.tab.active,
            &mut style.tab.active_with_kb_focus,
            &mut style.tab.focused,
            &mut style.tab.focused_with_kb_focus,
        ] {
            interaction.bg_fill = self.bg_panel;
            interaction.outline_color = Color32::TRANSPARENT;
            interaction.text_color = self.text;
            interaction.corner_radius = CornerRadius::ZERO;
        }
        style.buttons.close_tab_color = self.text_faint;
        style.buttons.close_tab_active_color = self.text;
        style.buttons.close_tab_bg_fill = self.bg_hover;
        style.overlay.selection_color = self.accent_soft;
        style.overlay.button_color = self.bg_raised;
        style.overlay.button_border_stroke = Stroke::new(1.0, self.border_strong);
        style
    }
}

/// Bundled fonts (SIL OFL 1.1, see `assets/fonts/*-OFL.txt`): Inter for UI,
/// JetBrains Mono for code, egui's defaults behind them for symbols.
pub fn install_fonts(context: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let mut add = |name: &str, bytes: &'static [u8]| {
        fonts.font_data.insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    };
    add("inter", include_bytes!("../assets/fonts/Inter-Regular.ttf"));
    add(INTER_MEDIUM, include_bytes!("../assets/fonts/Inter-Medium.ttf"));
    add(INTER_SEMIBOLD, include_bytes!("../assets/fonts/Inter-SemiBold.ttf"));
    add("mono", include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf"));
    add(MONO_BOLD, include_bytes!("../assets/fonts/JetBrainsMono-Bold.ttf"));
    let proportional_fallbacks = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let monospace_fallbacks = fonts.families.get(&FontFamily::Monospace).cloned().unwrap_or_default();
    let chain = |first: &str, rest: &[String]| {
        std::iter::once(first.to_owned()).chain(rest.iter().cloned()).collect::<Vec<_>>()
    };
    fonts.families.insert(FontFamily::Proportional, chain("inter", &proportional_fallbacks));
    fonts.families.insert(FontFamily::Monospace, chain("mono", &monospace_fallbacks));
    fonts.families.insert(FontFamily::Name(INTER_MEDIUM.into()), chain(INTER_MEDIUM, &proportional_fallbacks));
    fonts.families.insert(FontFamily::Name(INTER_SEMIBOLD.into()), chain(INTER_SEMIBOLD, &proportional_fallbacks));
    fonts.families.insert(FontFamily::Name(MONO_BOLD.into()), chain(MONO_BOLD, &monospace_fallbacks));
    context.set_fonts(fonts);
}
