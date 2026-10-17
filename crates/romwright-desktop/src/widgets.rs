//! Shared building blocks so every panel looks the same: vector icons,
//! buttons, segmented controls, empty/loading states and truncating labels.
//! All colours and sizes come from [`crate::theme`].

use crate::theme::{Theme, Type, font, metrics, space};
use egui::{
    Align2, Color32, CornerRadius, Pos2, Rect, Response, RichText, Sense, Stroke, Ui, Vec2, pos2, vec2,
};

/// Line icons drawn on a 16×16 grid (the Qt workbench's SVG set, plus a few).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Back,
    Forward,
    Close,
    Down,
    Up,
    Refresh,
    Search,
    Check,
    Cross,
    Play,
}

pub fn paint_icon(painter: &egui::Painter, rect: Rect, icon: Icon, color: Color32) {
    let scale = rect.width().min(rect.height()) / 16.0;
    let origin = rect.center() - vec2(8.0, 8.0) * scale;
    let at = |x: f32, y: f32| origin + vec2(x, y) * scale;
    let stroke = Stroke::new(1.6 * scale.max(1.0), color);
    let line = |points: &[Pos2]| {
        painter.add(egui::Shape::line(points.to_vec(), stroke));
    };
    match icon {
        Icon::Back => line(&[at(10.0, 4.0), at(6.0, 8.0), at(10.0, 12.0)]),
        Icon::Forward => line(&[at(6.0, 4.0), at(10.0, 8.0), at(6.0, 12.0)]),
        Icon::Down => line(&[at(4.0, 6.0), at(8.0, 10.0), at(12.0, 6.0)]),
        Icon::Up => line(&[at(4.0, 10.0), at(8.0, 6.0), at(12.0, 10.0)]),
        Icon::Close | Icon::Cross => {
            line(&[at(4.5, 4.5), at(11.5, 11.5)]);
            line(&[at(11.5, 4.5), at(4.5, 11.5)]);
        }
        Icon::Check => line(&[at(3.5, 8.5), at(6.5, 11.5), at(12.5, 4.5)]),
        Icon::Search => {
            painter.circle_stroke(at(7.0, 7.0), 4.0 * scale, stroke);
            line(&[at(10.0, 10.0), at(13.0, 13.0)]);
        }
        Icon::Refresh => {
            let center = at(8.0, 8.0);
            let radius = 4.8 * scale;
            let points: Vec<Pos2> = (0..=20)
                .map(|step| {
                    let angle = -0.6 + step as f32 / 20.0 * 4.8;
                    center + vec2(angle.cos(), angle.sin()) * radius
                })
                .collect();
            let end = *points.last().expect("arc points");
            line(&points);
            line(&[end + vec2(-2.6, -0.4) * scale, end, end + vec2(0.4, -2.6) * scale]);
        }
        Icon::Play => {
            painter.add(egui::Shape::convex_polygon(
                vec![at(5.0, 3.5), at(12.5, 8.0), at(5.0, 12.5)],
                color,
                Stroke::NONE,
            ));
        }
    }
}

/// Frameless square icon button with a soft hover background.
pub fn icon_button(ui: &mut Ui, theme: &Theme, icon: Icon, tooltip: &str, enabled: bool) -> Response {
    let size = Vec2::splat(28.0);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(size, sense);
    if ui.is_rect_visible(rect) {
        let hovered = enabled && response.hovered();
        if hovered {
            ui.painter().rect_filled(rect, CornerRadius::same(metrics::RADIUS), theme.bg_hover);
        }
        let color = if !enabled {
            theme.text_faint
        } else if hovered {
            theme.text
        } else {
            theme.text_muted
        };
        paint_icon(ui.painter(), rect.shrink(6.0), icon, color);
    }
    response.on_hover_text(tooltip)
}

fn framed_button(ui: &mut Ui, text: &str, fill: Color32, hover: Color32, stroke: Stroke, color: Color32, enabled: bool) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font(Type::Strong), color);
    let size = vec2(galley.size().x + 2.0 * space::MD, 28.0);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(size, sense);
    if ui.is_rect_visible(rect) {
        let fill = if enabled && response.hovered() { hover } else { fill };
        ui.painter().rect(rect, CornerRadius::same(metrics::RADIUS), fill, stroke, egui::StrokeKind::Inside);
        let text_color = if enabled { color } else { color.gamma_multiply(0.45) };
        ui.painter().galley_with_override_text_color(rect.center() - galley.size() / 2.0, galley, text_color);
    }
    response
}

/// The one accent-filled call to action in a region (toolbar Decompile).
pub fn primary_button(ui: &mut Ui, theme: &Theme, text: &str, enabled: bool) -> Response {
    framed_button(ui, text, theme.accent, theme.accent_hover, Stroke::NONE, theme.on_accent, enabled)
}

/// Ordinary button: raised fill, subtle border.
pub fn button(ui: &mut Ui, theme: &Theme, text: &str, enabled: bool) -> Response {
    framed_button(ui, text, theme.bg_raised, theme.bg_hover, Stroke::new(1.0, theme.border), theme.text, enabled)
}

/// A small toggle chip (listing "Bytes").
pub fn chip(ui: &mut Ui, theme: &Theme, text: &str, selected: bool) -> Response {
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font(Type::Caption), theme.text);
    let size = vec2(galley.size().x + 2.0 * space::SM + 2.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let (fill, stroke, color) = if selected {
            (theme.accent_soft, Stroke::new(1.0, theme.accent), theme.text)
        } else if response.hovered() {
            (theme.bg_hover, Stroke::new(1.0, theme.border_strong), theme.text)
        } else {
            (Color32::TRANSPARENT, Stroke::new(1.0, theme.border), theme.text_muted)
        };
        ui.painter().rect(rect, CornerRadius::same(metrics::RADIUS), fill, stroke, egui::StrokeKind::Inside);
        ui.painter().galley_with_override_text_color(rect.center() - galley.size() / 2.0, galley, color);
    }
    response
}

/// Segmented control (Analysis / Matching). Returns true when changed.
pub fn segmented(ui: &mut Ui, theme: &Theme, labels: &[&str], selected: &mut usize, enabled: &[bool]) -> bool {
    let font_id = font(Type::Strong);
    let widths: Vec<f32> = labels
        .iter()
        .map(|label| ui.painter().layout_no_wrap((*label).to_owned(), font_id.clone(), theme.text).size().x + 2.0 * space::MD)
        .collect();
    let total = widths.iter().sum::<f32>() + 4.0;
    let (rect, _) = ui.allocate_exact_size(vec2(total, 30.0), Sense::hover());
    ui.painter().rect(rect, CornerRadius::same(metrics::RADIUS + 1), theme.bg_app, Stroke::new(1.0, theme.border), egui::StrokeKind::Inside);
    let mut x = rect.left() + 2.0;
    let mut changed = false;
    for (index, (label, width)) in labels.iter().zip(&widths).enumerate() {
        let cell = Rect::from_min_size(pos2(x, rect.top() + 2.0), vec2(*width, rect.height() - 4.0));
        let is_enabled = enabled.get(index).copied().unwrap_or(true);
        let id = ui.id().with(("segment", label));
        let response = ui.interact(cell, id, if is_enabled { Sense::click() } else { Sense::hover() });
        let active = *selected == index;
        if active {
            ui.painter().rect_filled(cell, CornerRadius::same(metrics::RADIUS - 1), theme.bg_hover);
        } else if is_enabled && response.hovered() {
            ui.painter().rect_filled(cell, CornerRadius::same(metrics::RADIUS - 1), theme.bg_raised);
        }
        let color = if active {
            theme.text
        } else if is_enabled {
            theme.text_muted
        } else {
            theme.text_faint
        };
        ui.painter().text(cell.center(), Align2::CENTER_CENTER, *label, font_id.clone(), color);
        let response = if is_enabled { response } else { response.on_hover_text("Not available yet in this desktop") };
        if response.clicked() && !active {
            *selected = index;
            changed = true;
        }
        x += width;
    }
    changed
}

/// Thin vertical separator between toolbar groups.
pub fn toolbar_separator(ui: &mut Ui, theme: &Theme) {
    let (rect, _) = ui.allocate_exact_size(vec2(space::MD + 1.0, 20.0), Sense::hover());
    ui.painter().vline(rect.center().x, rect.y_range(), Stroke::new(1.0, theme.border));
}

/// Caption-sized muted label (section and field labels).
pub fn caption(ui: &mut Ui, theme: &Theme, text: &str) -> Response {
    ui.label(RichText::new(text).font(font(Type::Caption)).color(theme.text_muted))
}

/// A label that ellipsizes to the available width and shows the full text
/// on hover.
pub fn truncated(ui: &mut Ui, text: impl Into<String>, kind: Type, color: Color32) -> Response {
    ui.add(egui::Label::new(RichText::new(text.into()).font(font(kind)).color(color)).truncate())
}

/// Centered empty state: a title and one line saying what to do.
pub fn empty_state(ui: &mut Ui, theme: &Theme, title: &str, detail: &str) {
    centered(ui, |ui| {
        ui.label(RichText::new(title).font(font(Type::Strong)).color(theme.text_muted));
        if !detail.is_empty() {
            ui.label(RichText::new(detail).font(font(Type::Body)).color(theme.text_faint));
        }
    });
}

/// Centered spinner with a line of text.
pub fn loading(ui: &mut Ui, theme: &Theme, text: &str) {
    centered(ui, |ui| {
        ui.add(egui::Spinner::new().size(18.0).color(theme.accent));
        ui.label(RichText::new(text).font(font(Type::Body)).color(theme.text_muted));
    });
}

fn centered(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    let rect = ui.available_rect_before_wrap();
    let inner = Rect::from_center_size(rect.center(), vec2(rect.width().min(420.0), 72.0));
    ui.scope_builder(egui::UiBuilder::new().max_rect(inner).layout(egui::Layout::top_down(egui::Align::Center)), add);
    ui.allocate_rect(rect, Sense::hover());
}

/// A slim header bar at the top of a panel body: caption-styled title on
/// the left, controls added by `right` on the right.
pub fn panel_header(ui: &mut Ui, theme: &Theme, title: &str, right: impl FnOnce(&mut Ui)) {
    let height = 32.0;
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, theme.bg_panel);
    ui.painter().hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, theme.border));
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(vec2(space::MD, 0.0)))
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    child.spacing_mut().item_spacing.x = space::XS + 2.0;
    child.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        right(ui);
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            truncated(ui, title, Type::Caption, theme.text_muted);
        });
    });
}
