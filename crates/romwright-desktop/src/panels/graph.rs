//! Function graph (Qt `GraphDock` + `GraphCanvas`): the complete native CFG
//! of the function at the cursor, laid out by the shared layered layout
//! (`romwright_core::graph::native_layout`) and painted here with pan, zoom,
//! fit-to-view, a minimap and block navigation.
//!
//! The graph normally arrives with the decompiler's answer
//! ([`ShellEvent::Decompiled`]), so one decompile feeds both views; without a
//! decompiler panel (or on request) the panel fetches it itself with
//! [`GraphPanel::load_graph`] (the bridge's `function_bb_graph`).
//!
//! Nodes are keyed by block identity, never by address: distinct native
//! blocks may share an address or hold no operations at all.

use crate::address;
use crate::panel::{Panel, PanelContext, PanelId, Placement, ShellEvent};
use crate::service::Task;
use crate::theme::{Theme, Type, font, metrics, space};
use crate::widgets;
use egui::{Align2, Color32, CornerRadius, FontId, Key, Pos2, Rect, Sense, Shape, Stroke, StrokeKind, Vec2, pos2, vec2};
use romwright_core::graph::{BbEdgeKind, LAYOUT_NODE_HEIGHT, LAYOUT_NODE_WIDTH, NativeGraph, native_layout};
use romwright_model::{Address, AddressSpace, FunctionRow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const ID: PanelId = "graph";
const DECOMPILER_PANEL: PanelId = "decompiler";

const NODE_W: f32 = LAYOUT_NODE_WIDTH as f32;
const NODE_H: f32 = LAYOUT_NODE_HEIGHT as f32;
/// Edge routing in layout units (Qt `GraphCanvas::setGraph`).
const STUB: f32 = 24.0;
const SHORT_EDGE: f32 = 90.0;
const LOOP_INSET: f32 = 20.0;
const LANE_GAP: f32 = 10.0;
const LANE_CLEARANCE: f32 = 8.0;
const DANGLING: f32 = 30.0;
/// Header strip of a block card, in layout units.
const NODE_HEADER: f32 = 24.0;
const MIN_ZOOM: f32 = 0.02;
const MAX_ZOOM: f32 = 3.0;
/// Fit never magnifies a small graph past this (Qt capped at 2.0).
const FIT_MAX_ZOOM: f32 = 1.25;
/// Below this fitted zoom the initial view focuses the current block.
const READABLE_ZOOM: f32 = 0.65;
const TEXT_ZOOM: f32 = 0.35;
const WHEEL_STEP: f32 = 1.15;
const MINIMAP: Vec2 = vec2(200.0, 140.0);

struct ResolvedEdge {
    from: usize,
    to: Option<usize>,
    kind: BbEdgeKind,
    path: Vec<Pos2>,
    bounds: Rect,
}

/// What a click on a block asks for: the block identity, and its address
/// when the block holds operations (only those navigate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockClick {
    pub id: u64,
    pub address: Option<u64>,
}

/// The canvas: scene geometry, selection and viewport. Painting and input
/// live in [`GraphView::show`]; everything else is plain state so the gate
/// can drive it headlessly.
pub struct GraphView {
    graph: Arc<NativeGraph>,
    edges: Vec<ResolvedEdge>,
    lookup: HashMap<u64, usize>,
    exits: Vec<bool>,
    bounds: Rect,
    /// Function entry address and the block that holds it.
    entry: Option<u64>,
    entry_block: Option<usize>,
    /// Block clicked by the user; survives an echo of its own address.
    selected: Option<usize>,
    /// Block holding the navigation cursor.
    cursor_block: Option<usize>,
    zoom: f32,
    pan: Vec2,
    fit_pending: bool,
    viewport: Vec2,
}

impl Default for GraphView {
    fn default() -> Self {
        Self {
            graph: Arc::default(),
            edges: Vec::new(),
            lookup: HashMap::new(),
            exits: Vec::new(),
            bounds: Rect::NOTHING,
            entry: None,
            entry_block: None,
            selected: None,
            cursor_block: None,
            zoom: 1.0,
            pan: Vec2::ZERO,
            fit_pending: false,
            viewport: Vec2::ZERO,
        }
    }
}

fn node_rect(graph: &NativeGraph, index: usize) -> Rect {
    let node = &graph.nodes[index];
    Rect::from_min_size(pos2(node.x as f32, node.y as f32), vec2(NODE_W, NODE_H))
}

fn bounding(points: &[Pos2]) -> Rect {
    points.iter().fold(Rect::NOTHING, |rect, point| rect.union(Rect::from_min_max(*point, *point)))
}

impl GraphView {
    pub fn is_empty(&self) -> bool {
        self.graph.nodes.is_empty()
    }

    pub fn graph(&self) -> &NativeGraph {
        &self.graph
    }

    pub fn zoom(&self) -> f32 {
        self.zoom
    }

    /// Block identity of the clicked block, if one is selected.
    pub fn selected_id(&self) -> Option<u64> {
        self.selected.map(|index| self.graph.nodes[index].id)
    }

    /// Replaces the graph, resetting selection; the next frame picks the
    /// initial view. Edge geometry is resolved once here, as Qt did.
    pub fn set_graph(&mut self, graph: Arc<NativeGraph>, entry: Option<u64>) {
        self.selected = None;
        self.cursor_block = None;
        self.entry = entry;
        // The first retained operation need not be the entry instruction:
        // the block holding it, else the IR's first block, is the entry.
        self.entry_block = entry
            .and_then(|entry| Self::block_holding(&graph, entry))
            .or_else(|| (!graph.nodes.is_empty()).then_some(0));
        self.lookup = graph.nodes.iter().enumerate().map(|(index, node)| (node.id, index)).collect();
        let node_bounds = (0..graph.nodes.len()).fold(Rect::NOTHING, |rect, index| rect.union(node_rect(&graph, index)));
        self.exits = vec![true; graph.nodes.len()];
        self.edges.clear();
        self.edges.reserve(graph.edges.len());
        let mut outer = Vec::new();
        for edge in &graph.edges {
            let Some(&from) = self.lookup.get(&edge.from) else { continue };
            self.exits[from] = false;
            let to = self.lookup.get(&edge.to).copied();
            let from_rect = node_rect(&graph, from);
            let start = pos2(from_rect.center().x, from_rect.bottom());
            let path = match to {
                None => vec![start, start + vec2(0.0, DANGLING)],
                Some(to) if to == from => {
                    // A loop occupies the gap beside its own block.
                    let upper = pos2(from_rect.right(), from_rect.top() + LOOP_INSET);
                    let lower = upper + vec2(0.0, LOOP_INSET);
                    vec![lower, lower + vec2(STUB, 0.0), upper + vec2(STUB, 0.0), upper]
                }
                Some(to) => {
                    let to_rect = node_rect(&graph, to);
                    let end = pos2(to_rect.center().x, to_rect.top());
                    if end.y > start.y && end.y - start.y <= SHORT_EDGE {
                        let middle = (start.y + end.y) / 2.0;
                        vec![start, pos2(start.x, middle), pos2(end.x, middle), end]
                    } else {
                        // Long and feedback edges travel outside the block
                        // columns; horizontal legs stay in row gaps.
                        outer.push(self.edges.len());
                        vec![start, start + vec2(0.0, STUB), end - vec2(0.0, STUB), end]
                    }
                }
            };
            self.edges.push(ResolvedEdge { from, to, kind: edge.kind, bounds: Rect::NOTHING, path });
        }
        outer.sort_by(|a, b| {
            let top = |index: usize| self.edges[index].path[1].y.min(self.edges[index].path[2].y);
            top(*a).total_cmp(&top(*b))
        });
        let mut lanes: [Vec<f32>; 2] = [Vec::new(), Vec::new()];
        for index in outer {
            let path = &mut self.edges[index].path;
            let top = path[1].y.min(path[2].y);
            let bottom = path[1].y.max(path[2].y);
            let right = (path[0].x + path[3].x) / 2.0 >= node_bounds.center().x;
            let lanes = &mut lanes[usize::from(right)];
            let lane = lanes.iter().position(|until| until + LANE_CLEARANCE < top).unwrap_or(lanes.len());
            if lane == lanes.len() {
                lanes.push(bottom);
            } else {
                lanes[lane] = bottom;
            }
            let x = if right {
                node_bounds.right() + STUB + lane as f32 * LANE_GAP
            } else {
                node_bounds.left() - STUB - lane as f32 * LANE_GAP
            };
            *path = vec![path[0], path[1], pos2(x, path[1].y), pos2(x, path[2].y), path[2], path[3]];
        }
        let mut bounds = node_bounds;
        for edge in &mut self.edges {
            edge.bounds = bounding(&edge.path);
            bounds = bounds.union(edge.bounds);
        }
        self.bounds = bounds;
        self.graph = graph;
        self.zoom = 1.0;
        self.pan = Vec2::ZERO;
        self.fit_pending = true;
    }

    pub fn clear(&mut self) {
        self.set_graph(Arc::default(), None);
    }

    /// Reverse address sync (listing, decompiler, history). A specifically
    /// selected block survives an echo of its own address.
    pub fn set_address(&mut self, address: Option<u64>) {
        if let Some(index) = self.selected
            && (address.is_none() || self.graph.nodes[index].address != address)
        {
            self.selected = None;
        }
        self.cursor_block = address.and_then(|address| {
            Self::block_holding(&self.graph, address).or_else(|| self.entry_block.filter(|_| Some(address) == self.entry))
        });
    }

    /// The block starting at `address`, else the first whose operations span it.
    fn block_holding(graph: &NativeGraph, address: u64) -> Option<usize> {
        let nodes = &graph.nodes;
        nodes.iter().position(|node| node.address == Some(address)).or_else(|| {
            nodes.iter().position(|node| node.address.zip(node.last).is_some_and(|(first, last)| first <= address && address <= last))
        })
    }

    fn highlighted(&self, index: usize) -> bool {
        self.selected.or(self.cursor_block) == Some(index)
    }

    fn current_block(&self) -> usize {
        self.selected.or(self.cursor_block).or(self.entry_block).unwrap_or(0)
    }

    /// The whole graph centred in the viewport.
    pub fn fit(&mut self) {
        self.fit_pending = false;
        if self.is_empty() || self.bounds.width() <= 0.0 || self.bounds.height() <= 0.0 {
            return;
        }
        let margin = 2.0 * space::XL;
        let zx = (self.viewport.x - margin).max(1.0) / self.bounds.width();
        let zy = (self.viewport.y - margin).max(1.0) / self.bounds.height();
        self.zoom = zx.min(zy).clamp(MIN_ZOOM, FIT_MAX_ZOOM);
        self.pan = (self.viewport - self.bounds.size() * self.zoom) / 2.0 - self.bounds.min.to_vec2() * self.zoom;
    }

    /// The current block at natural size near the top of the view.
    pub fn focus_current(&mut self) {
        self.fit_pending = false;
        if self.is_empty() {
            return;
        }
        let rect = node_rect(&self.graph, self.current_block());
        self.zoom = 1.0;
        self.pan = vec2((self.viewport.x - NODE_W) / 2.0, space::XL + space::LG) - rect.min.to_vec2();
    }

    fn initial_view(&mut self) {
        self.fit();
        if self.zoom < READABLE_ZOOM {
            self.focus_current();
        }
    }

    fn zoom_around(&mut self, anchor: Vec2, factor: f32) {
        let zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        self.pan = anchor - (anchor - self.pan) * (zoom / self.zoom);
        self.zoom = zoom;
    }

    fn to_screen(&self, origin: Pos2, point: Pos2) -> Pos2 {
        origin + self.pan + point.to_vec2() * self.zoom
    }

    fn node_at(&self, local: Vec2) -> Option<usize> {
        let scene = ((local - self.pan) / self.zoom).to_pos2();
        (0..self.graph.nodes.len()).find(|&index| node_rect(&self.graph, index).contains(scene))
    }

    /// Selects block `index`; Qt `selectNode`.
    fn select(&mut self, index: usize) -> BlockClick {
        let node = &self.graph.nodes[index];
        self.selected = Some(index);
        self.cursor_block = Some(index);
        BlockClick { id: node.id, address: node.address }
    }

    fn fits_entirely(&self) -> bool {
        let rect = Rect::from_min_size(self.pan.to_pos2() + self.bounds.min.to_vec2() * self.zoom, self.bounds.size() * self.zoom);
        Rect::from_min_size(Pos2::ZERO, self.viewport).expand(1.0).contains_rect(rect)
    }

    /// Paints the canvas into `rect` and handles input; returns the block
    /// the user clicked.
    pub fn show(&mut self, ui: &mut egui::Ui, theme: &Theme, rect: Rect) -> Option<BlockClick> {
        let id = ui.id().with("graph-canvas");
        let response = ui.interact(rect, id, Sense::click_and_drag());
        self.viewport = rect.size();
        if self.fit_pending && !self.is_empty() {
            self.initial_view();
        }
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, CornerRadius::ZERO, theme.bg_code);
        if self.is_empty() {
            return None;
        }
        let origin = rect.min;
        let mut clicked = None;

        // Minimap first: it captures input over its own rectangle.
        let minimap = (!self.fits_entirely()).then(|| self.minimap_rect(rect));
        let pointer = response.hover_pos();
        let over_minimap = |pos: Option<Pos2>| minimap.is_some_and(|(frame, ..)| pos.is_some_and(|pos| frame.contains(pos)));

        // Input.
        if response.clicked() || response.drag_started() || response.secondary_clicked() {
            response.request_focus();
        }
        if let Some((_, inner, scale, offset)) = minimap
            && (response.clicked() || response.dragged())
            && let Some(pos) = response.interact_pointer_pos()
            && over_minimap(response.interact_pointer_pos())
            && inner.expand(space::XS).contains(pos)
        {
            // Centre the view on the minimap point.
            let scene = ((pos - inner.min - offset) / scale).to_pos2() + self.bounds.min.to_vec2();
            self.pan = self.viewport / 2.0 - scene.to_vec2() * self.zoom;
        } else {
            if response.dragged() {
                self.pan += response.drag_delta();
            }
            if response.clicked()
                && let Some(pos) = response.interact_pointer_pos()
                && let Some(index) = self.node_at(pos - origin)
            {
                clicked = Some(self.select(index));
            }
        }
        if response.hovered() {
            let (wheel, pinch) = ui.input(|input| {
                let wheel: f32 = input
                    .raw
                    .events
                    .iter()
                    .filter_map(|event| match event {
                        egui::Event::MouseWheel { unit, delta, .. } => Some(match unit {
                            egui::MouseWheelUnit::Point | egui::MouseWheelUnit::Page => delta.y / 50.0,
                            egui::MouseWheelUnit::Line => delta.y,
                        }),
                        _ => None,
                    })
                    .sum();
                (wheel, input.zoom_delta())
            });
            let factor = WHEEL_STEP.powf(wheel) * pinch;
            if let Some(pos) = pointer
                && factor != 1.0
            {
                self.zoom_around(pos - origin, factor);
            }
        }
        if response.has_focus() {
            let (home, fit, zoom_in, zoom_out) = ui.input(|input| {
                (
                    input.key_pressed(Key::Home),
                    input.key_pressed(Key::F) && input.modifiers.is_none(),
                    input.key_pressed(Key::Plus) || input.key_pressed(Key::Equals),
                    input.key_pressed(Key::Minus),
                )
            });
            if home {
                self.focus_current();
            }
            if fit {
                self.fit();
            }
            if zoom_in || zoom_out {
                self.zoom_around(self.viewport / 2.0, if zoom_in { WHEEL_STEP } else { 1.0 / WHEEL_STEP });
            }
        }
        let mut action = None;
        response.context_menu(|ui| {
            if ui.button("Current block  (Home)").clicked() {
                action = Some(false);
                ui.close();
            }
            if ui.button("Fit entire graph  (F)").clicked() {
                action = Some(true);
                ui.close();
            }
        });
        match action {
            Some(true) => self.fit(),
            Some(false) => self.focus_current(),
            None => {}
        }

        let hovered = pointer.filter(|pos| !over_minimap(Some(*pos))).and_then(|pos| self.node_at(pos - origin));
        if let Some(index) = hovered
            && !response.dragged()
        {
            let node = &self.graph.nodes[index];
            let place = node.address.map_or_else(|| "no operations".to_string(), |address| format!("0x{address:x}"));
            response.clone().on_hover_text(format!("Block {} · {place}\n{} operations", node.id, node.operations));
        }
        let popup = ui.visuals().popup_shadow;
        self.paint(&painter, theme, rect, hovered, popup);
        if let Some(minimap) = minimap {
            self.paint_minimap(&painter, theme, minimap);
        }
        self.paint_legend(&painter, theme, rect);
        clicked
    }

    fn edge_color(theme: &Theme, kind: BbEdgeKind) -> Color32 {
        match kind {
            BbEdgeKind::True => theme.ok,
            BbEdgeKind::False => theme.error,
            BbEdgeKind::Call => theme.accent,
            BbEdgeKind::Unconditional => theme.text_faint,
        }
    }

    fn paint(&self, painter: &egui::Painter, theme: &Theme, rect: Rect, hovered: Option<usize>, popup: egui::Shadow) {
        let origin = rect.min;
        let zoom = self.zoom;
        let visible = Rect::from_min_max(
            ((rect.min - origin - self.pan) / zoom).to_pos2(),
            ((rect.max - origin - self.pan) / zoom).to_pos2(),
        )
        .expand(STUB);
        // Dot grid anchored to the scene so it moves with the graph.
        let spacing = 2.0 * STUB;
        if zoom * spacing >= space::LG {
            let first = (visible.min / spacing).floor();
            let mut shapes = Vec::new();
            let mut x = first.x * spacing;
            while x <= visible.max.x {
                let mut y = first.y * spacing;
                while y <= visible.max.y {
                    shapes.push(Shape::circle_filled(self.to_screen(origin, pos2(x, y)), 1.0, theme.border));
                    y += spacing;
                }
                x += spacing;
            }
            painter.extend(shapes);
        }

        let focus = self.selected.or(hovered);
        let width = 1.5;
        let mut emphasised = Vec::new();
        let mut shapes = Vec::with_capacity(self.edges.len() * 2);
        for (index, edge) in self.edges.iter().enumerate() {
            if !edge.bounds.intersects(visible) {
                continue;
            }
            if focus.is_some_and(|node| edge.from == node || edge.to == Some(node)) {
                emphasised.push(index);
                continue;
            }
            let color = Self::edge_color(theme, edge.kind);
            self.edge_shapes(&mut shapes, origin, edge, if focus.is_some() { color.gamma_multiply(0.55) } else { color }, width);
        }
        for index in emphasised {
            let edge = &self.edges[index];
            self.edge_shapes(&mut shapes, origin, edge, Self::edge_color(theme, edge.kind), width + 1.0);
        }
        painter.extend(shapes);

        let radius = CornerRadius::same(((metrics::RADIUS as f32) * zoom.min(1.0)).round().max(1.0) as u8);
        // A soft lift under each card, from the theme's popup shadow.
        let shadow = (zoom >= READABLE_ZOOM).then(|| egui::Shadow {
            offset: [0, 2],
            blur: (popup.blur / 2).max(1),
            spread: 0,
            color: popup.color.gamma_multiply(0.45),
        });
        let scaled = |kind: Type| {
            let mut id: FontId = font(kind);
            id.size = (id.size * zoom * 2.0).round() / 2.0;
            id
        };
        let text = zoom >= TEXT_ZOOM;
        let (code, caption) = (scaled(Type::Code), scaled(Type::Caption));
        for (index, node) in self.graph.nodes.iter().enumerate() {
            let scene = node_rect(&self.graph, index);
            if !scene.intersects(visible) {
                continue;
            }
            let card = Rect::from_min_max(self.to_screen(origin, scene.min), self.to_screen(origin, scene.max));
            let highlighted = self.highlighted(index);
            let is_entry = self.entry_block == Some(index);
            if let Some(shadow) = shadow {
                painter.add(shadow.as_shape(card, radius));
            }
            if highlighted {
                painter.rect_stroke(card.expand(3.0), radius, Stroke::new(4.0, theme.accent_soft), StrokeKind::Outside);
            }
            let border = if highlighted {
                Stroke::new(2.0, theme.accent)
            } else if hovered == Some(index) {
                Stroke::new(1.0, theme.text_faint)
            } else {
                Stroke::new(1.0, theme.border_strong)
            };
            painter.rect_filled(card, radius, if hovered == Some(index) { theme.bg_hover } else { theme.bg_raised });
            let header = Rect::from_min_size(card.min, vec2(card.width(), NODE_HEADER * zoom));
            let header_radius = CornerRadius { nw: radius.nw, ne: radius.ne, sw: 0, se: 0 };
            painter.rect_filled(header, header_radius, if is_entry { theme.accent_soft } else { theme.bg_stripe });
            painter.hline(header.x_range(), header.bottom(), Stroke::new(1.0, theme.border));
            painter.rect_stroke(card, radius, border, StrokeKind::Inside);
            if !text {
                continue;
            }
            let pad = space::SM * zoom;
            let header_mid = header.center().y;
            match node.address {
                Some(address) => {
                    painter.text(pos2(card.left() + pad, header_mid), Align2::LEFT_CENTER, format!("0x{address:x}"), code.clone(), theme.syntax_address);
                }
                None => {
                    painter.text(pos2(card.left() + pad, header_mid), Align2::LEFT_CENTER, "empty block", caption.clone(), theme.text_faint);
                }
            }
            let tag = if is_entry { "entry".to_string() } else { format!("#{}", node.id) };
            painter.text(pos2(card.right() - pad, header_mid), Align2::RIGHT_CENTER, tag, caption.clone(), if is_entry { theme.accent } else { theme.text_faint });
            let body_mid = (header.bottom() + card.bottom()) / 2.0;
            let operations = if node.operations == 1 { "1 operation".to_string() } else { format!("{} operations", node.operations) };
            painter.text(pos2(card.left() + pad, body_mid), Align2::LEFT_CENTER, operations, caption.clone(), theme.text_muted);
            if self.exits[index] {
                painter.text(pos2(card.right() - pad, body_mid), Align2::RIGHT_CENTER, "exit", caption.clone(), theme.warn);
            }
        }
    }

    fn edge_shapes(&self, shapes: &mut Vec<Shape>, origin: Pos2, edge: &ResolvedEdge, color: Color32, width: f32) {
        let points: Vec<Pos2> = edge.path.iter().map(|point| self.to_screen(origin, *point)).collect();
        let stroke = Stroke::new(width, color);
        if edge.kind == BbEdgeKind::Call {
            shapes.extend(Shape::dashed_line(&points, stroke, 6.0, 4.0));
        } else {
            shapes.push(Shape::line(points.clone(), stroke));
        }
        if edge.to.is_some()
            && let [.., before, tip] = points[..]
        {
            let direction = tip - before;
            let length = direction.length();
            if length > 0.0 {
                let unit = direction / length;
                let size = (8.0 * self.zoom).clamp(3.0, 8.0) + width - 1.5;
                let normal = vec2(-unit.y, unit.x);
                shapes.push(Shape::convex_polygon(
                    vec![tip, tip - unit * size + normal * (size / 2.0), tip - unit * size - normal * (size / 2.0)],
                    color,
                    Stroke::NONE,
                ));
            }
        }
    }

    /// (frame, inner drawing area, scale, centring offset).
    fn minimap_rect(&self, rect: Rect) -> (Rect, Rect, f32, Vec2) {
        let available = (rect.size() * 0.3).min(MINIMAP);
        let scale = (available.x / self.bounds.width()).min(available.y / self.bounds.height());
        let size = self.bounds.size() * scale;
        let frame = Rect::from_min_size(rect.max - size - Vec2::splat(space::MD + space::SM), size + Vec2::splat(space::SM));
        let inner = frame.shrink(space::XS);
        (frame, inner, scale, Vec2::ZERO)
    }

    fn paint_minimap(&self, painter: &egui::Painter, theme: &Theme, (frame, inner, scale, offset): (Rect, Rect, f32, Vec2)) {
        painter.rect(frame, CornerRadius::same(metrics::RADIUS), theme.bg_panel, Stroke::new(1.0, theme.border_strong), StrokeKind::Inside);
        let map = |point: Pos2| inner.min + offset + (point - self.bounds.min) * scale;
        let mut shapes = Vec::with_capacity(self.graph.nodes.len());
        for index in 0..self.graph.nodes.len() {
            let scene = node_rect(&self.graph, index);
            let block = Rect::from_min_max(map(scene.min), map(scene.max));
            let block = Rect::from_center_size(block.center(), block.size().max(Vec2::splat(1.5)));
            let color = if self.highlighted(index) { theme.accent } else { theme.text_faint };
            shapes.push(Shape::rect_filled(block, CornerRadius::ZERO, color));
        }
        painter.extend(shapes);
        let view = Rect::from_min_size(((-self.pan) / self.zoom).to_pos2(), self.viewport / self.zoom);
        let view = Rect::from_min_max(map(view.min), map(view.max)).intersect(inner);
        if view.is_positive() {
            painter.rect(view, CornerRadius::same(metrics::RADIUS_SM), theme.accent_soft, Stroke::new(1.0, theme.accent), StrokeKind::Inside);
        }
    }

    fn paint_legend(&self, painter: &egui::Painter, theme: &Theme, rect: Rect) {
        let caption = font(Type::Caption);
        let entries = [(BbEdgeKind::True, "true"), (BbEdgeKind::False, "false"), (BbEdgeKind::Unconditional, "jump")]
            .map(|(kind, label)| (kind, painter.layout_no_wrap(label.into(), caption.clone(), theme.text_muted)));
        let swatch = space::LG;
        let width = entries.iter().map(|(_, galley)| swatch + space::XS + galley.size().x).sum::<f32>()
            + space::MD * (entries.len() - 1) as f32
            + 2.0 * space::SM;
        let height = metrics::ROW;
        let pill = Rect::from_min_size(pos2(rect.left() + space::MD, rect.bottom() - space::MD - height), vec2(width, height));
        painter.rect(pill, CornerRadius::same(metrics::RADIUS), theme.bg_panel, Stroke::new(1.0, theme.border), StrokeKind::Inside);
        let mut x = pill.left() + space::SM;
        let y = pill.center().y;
        for (kind, galley) in entries {
            painter.line_segment([pos2(x, y), pos2(x + swatch, y)], Stroke::new(2.0, Self::edge_color(theme, kind)));
            x += swatch + space::XS;
            let size = galley.size();
            painter.galley(pos2(x, y - size.y / 2.0), galley, theme.text_muted);
            x += size.x + space::MD;
        }
    }
}

struct Load {
    generation: u64,
    entry: Address,
    started: Instant,
    task: Task<(NativeGraph, f64)>,
}

#[derive(Default)]
pub struct GraphPanel {
    view: GraphView,
    function: Option<FunctionRow>,
    /// Entry of the installed graph.
    shown: Option<Address>,
    /// Entry whose graph this panel is waiting for.
    wanted: Option<Address>,
    message: String,
    load: Option<Load>,
    generation: u64,
    loaded: u64,
    fetch_ms: Option<f64>,
    layout_ms: Option<f64>,
}

fn ram(address: &Address) -> Option<u64> {
    (address.space == AddressSpace::Ram).then_some(address.offset)
}

impl GraphPanel {
    pub fn view(&self) -> &GraphView {
        &self.view
    }

    /// Graphs answered by [`Self::load_graph`] (the gate's fetch counter).
    pub fn graphs_loaded(&self) -> u64 {
        self.loaded
    }

    /// Request→answer of the last [`Self::load_graph`] (`ui.graph.fetch_ms`).
    pub fn last_fetch_ms(&self) -> Option<f64> {
        self.fetch_ms
    }

    /// Layout-only time of the last installed graph (`ui.graph.layout_ms`).
    pub fn last_layout_ms(&self) -> Option<f64> {
        self.layout_ms
    }

    /// Decompiles `entry` and lays out its native CFG in a job (the bridge's
    /// `function_bb_graph`).
    pub fn load_graph(&mut self, cx: &PanelContext<'_>, entry: &Address) {
        self.generation += 1;
        self.wanted = Some(entry.clone());
        self.message = format!("Building the graph of {}…", address::format(entry));
        let (binary, program, task_entry) = (cx.session.binary.clone(), cx.session.program.clone(), entry.clone());
        let task = cx.service.job(format!("graph {}", address::format(entry)), move |job| {
            if task_entry.space != AddressSpace::Ram {
                return Err("only RAM functions have a native CFG".into());
            }
            let ir = {
                let mut pool = job.worker_pool()?;
                let core = job.fork()?;
                let request = job.execution_request(&core, &binary, &program, None, Duration::from_secs(60))?;
                job.progress("decompiling");
                let doc = pool.decompile_doc(&core, &request, &task_entry).map_err(|error| error.to_string())?;
                doc.function_ir.ok_or_else(|| "native function CFG is unavailable".to_string())?
            };
            let started = Instant::now();
            let graph = native_layout(&ir);
            let layout = started.elapsed();
            // The bridge's timing line, parsed by `benchmarks/ui_gate.py`.
            eprintln!("BRIDGE-GRAPH {layout:?} nodes={}", graph.nodes.len());
            job.detail(format!("{} blocks, {} edges", graph.nodes.len(), graph.edges.len()));
            Ok((graph, layout.as_secs_f64() * 1000.0))
        });
        self.load = Some(Load { generation: self.generation, entry: entry.clone(), started: Instant::now(), task });
    }

    fn install(&mut self, cx: &PanelContext<'_>, entry: Address, graph: Option<Arc<NativeGraph>>) {
        self.wanted = None;
        match graph {
            Some(graph) => {
                self.view.set_graph(graph, ram(&entry));
                self.message.clear();
            }
            None => {
                self.view.clear();
                self.message = format!("No native CFG for {}", address::format(&entry));
            }
        }
        self.shown = Some(entry);
        self.view.set_address(cx.session.address.as_ref().and_then(ram));
    }

    fn reset(&mut self, message: String) {
        self.generation += 1;
        self.wanted = None;
        self.shown = None;
        self.view.clear();
        self.message = message;
    }

    fn heading(&self) -> String {
        let mut heading = "GRAPH".to_string();
        if let Some(function) = &self.function {
            heading.push_str(&format!("  ·  {}", function.name));
        }
        if !self.view.is_empty() {
            let graph = self.view.graph();
            heading.push_str(&format!("  ·  {} blocks  ·  {} edges", graph.nodes.len(), graph.edges.len()));
        }
        heading
    }
}

impl Panel for GraphPanel {
    fn id(&self) -> PanelId {
        ID
    }

    fn title(&self) -> String {
        "Graph".into()
    }

    fn placement(&self) -> Placement {
        Placement::Right
    }

    fn on_event(&mut self, event: &ShellEvent, cx: &mut PanelContext<'_>) {
        match event {
            ShellEvent::ProgramChanged | ShellEvent::Refresh => {
                self.function = None;
                self.reset(String::new());
            }
            ShellEvent::FunctionChanged { function: None, cursor } => {
                self.function = None;
                self.reset(format!("No known function contains {}", address::format(cursor)));
            }
            ShellEvent::FunctionChanged { function: Some(function), cursor } => {
                self.function = Some(function.clone());
                if self.shown.as_ref() != Some(&function.entry) && self.wanted.as_ref() != Some(&function.entry) {
                    self.reset(format!("Decompiling {} for its graph…", function.name));
                    self.wanted = Some(function.entry.clone());
                }
                self.view.set_address(ram(cursor));
            }
            ShellEvent::Decompiled { entry, cursor, graph, layout_ms, .. } => {
                if self.function.as_ref().is_some_and(|function| &function.entry != entry) {
                    return;
                }
                if self.shown.as_ref() != Some(entry) || graph.as_ref().is_some_and(|graph| !Arc::ptr_eq(graph, &self.view.graph)) {
                    self.install(cx, entry.clone(), graph.clone());
                    if *layout_ms > 0.0 {
                        self.layout_ms = Some(*layout_ms);
                    }
                }
                self.view.set_address(ram(cursor));
            }
            ShellEvent::AddressChanged { address, .. } => self.view.set_address(ram(address)),
            _ => {}
        }
    }

    fn poll(&mut self, cx: &mut PanelContext<'_>) {
        let Some(answer) = self.load.as_ref().and_then(|load| load.task.poll()) else { return };
        let Some(load) = self.load.take() else { return };
        // Every answer counts (the gate waits on it); only the current one
        // is installed.
        self.fetch_ms = Some(load.started.elapsed().as_secs_f64() * 1000.0);
        self.loaded += 1;
        if load.generation != self.generation {
            return;
        }
        match answer {
            Ok((graph, layout_ms)) => {
                self.layout_ms = Some(layout_ms);
                self.install(cx, load.entry, Some(Arc::new(graph)));
            }
            Err(error) => {
                self.view.clear();
                self.wanted = None;
                self.shown = None;
                self.message = format!("Graph failed for {}\n{error}", address::format(&load.entry));
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, cx: &mut PanelContext<'_>) {
        let theme = cx.theme;
        // Without a decompiler to answer, the graph fetches itself, and only
        // while its tab is visible.
        if let Some(entry) = self.wanted.clone()
            && self.load.is_none()
            && !cx.has_panel(DECOMPILER_PANEL)
        {
            self.load_graph(cx, &entry);
        }
        let heading = self.heading();
        let has_graph = !self.view.is_empty();
        let (mut fit, mut focus, mut zoom) = (false, false, None);
        widgets::panel_header(ui, theme, &heading, |ui| {
            if !has_graph {
                return;
            }
            if widgets::chip(ui, theme, "Fit", false).on_hover_text("Fit the entire graph (F)").clicked() {
                fit = true;
            }
            if widgets::chip(ui, theme, "Current block", false).on_hover_text("Show the current block at 100% (Home)").clicked() {
                focus = true;
            }
            if widgets::chip(ui, theme, "+", false).on_hover_text("Zoom in (+)").clicked() {
                zoom = Some(WHEEL_STEP);
            }
            widgets::caption(ui, theme, &format!("{:.0}%", self.view.zoom() * 100.0));
            if widgets::chip(ui, theme, "−", false).on_hover_text("Zoom out (−)").clicked() {
                zoom = Some(1.0 / WHEEL_STEP);
            }
        });
        if fit {
            self.view.fit();
        }
        if focus {
            self.view.focus_current();
        }
        if let Some(factor) = zoom {
            let center = self.view.viewport / 2.0;
            self.view.zoom_around(center, factor);
        }
        let rect = ui.available_rect_before_wrap();
        if !has_graph {
            ui.painter().rect_filled(rect, CornerRadius::ZERO, theme.bg_code);
            if self.load.is_some() || (self.wanted.is_some() && cx.has_panel(DECOMPILER_PANEL)) {
                widgets::loading(ui, theme, &self.message);
            } else if cx.session.program.is_empty() {
                widgets::empty_state(ui, theme, "No program open", "Choose an image in the toolbar to see its function graphs.");
            } else if self.message.is_empty() {
                widgets::empty_state(ui, theme, "No function graph", "Navigate into a function to see its control flow.");
            } else {
                let (title, detail) = self.message.split_once('\n').unwrap_or((&self.message, ""));
                widgets::empty_state(ui, theme, title, detail);
            }
            return;
        }
        ui.allocate_rect(rect, Sense::hover());
        if let Some(click) = self.view.show(ui, theme, rect)
            && let Some(address) = click.address
        {
            cx.navigate(Address::ram(address), true);
        }
    }

    fn busy(&self) -> bool {
        self.load.is_some()
    }
}

/// Qt `GateRunner::graphInteractions` against the real canvas: three blocks
/// (two sharing 0x10, one empty) are clicked through egui pointer events;
/// each selects its own block, only blocks with an address navigate, and an
/// echo of the navigated address keeps the block identity. Replacing the
/// graph with a self-loop resets the selection and changes the painted
/// frame. Returns the first broken expectation.
pub fn graph_interactions() -> Result<(), String> {
    use romwright_core::graph::{BbEdge, NativeGraphNode};
    let context = egui::Context::default();
    crate::theme::install_fonts(&context);
    let theme = Theme::new(crate::theme::ThemeName::Dark);
    let size = vec2(700.0, 260.0);
    let node = |id, address: Option<u64>, x| NativeGraphNode {
        id,
        address,
        last: address,
        operations: usize::from(address.is_some()),
        x,
        y: 0,
    };
    let nodes = vec![node(1, Some(0x10), 0), node(2, Some(0x10), 240), node(3, None, 480)];
    let graph = |edges: Vec<BbEdge>| Arc::new(NativeGraph { nodes: nodes.clone(), edges });
    let mut view = GraphView::default();
    view.set_graph(graph(Vec::new()), None);
    let frame = |view: &mut GraphView, events: Vec<egui::Event>| {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
            events,
            ..Default::default()
        };
        let mut clicked = None;
        let mut output = context.run_ui(input, |ui| {
            let rect = ui.max_rect();
            clicked = view.show(ui, &theme, rect);
        });
        // Headless: nothing uploads the font atlas.
        output.textures_delta.clear();
        let shapes: Vec<_> = output.shapes.into_iter().map(|shape| shape.shape).collect();
        (clicked, format!("{shapes:?}"))
    };
    let (_, without_loop) = frame(&mut view, Vec::new());
    if view.selected_id().is_some() {
        return Err("a fresh graph has a selected block".into());
    }
    let mut selected = Vec::new();
    let mut navigated = Vec::new();
    for x in [110.0, 350.0, 590.0] {
        let pos = pos2(x, 130.0);
        let button = |pressed| egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed, modifiers: egui::Modifiers::NONE };
        frame(&mut view, vec![egui::Event::PointerMoved(pos), button(true)]);
        let (click, _) = frame(&mut view, vec![button(false)]);
        let Some(click) = click else { return Err(format!("no block answered a click at x={x}")) };
        selected.push(click.id);
        if let Some(address) = click.address {
            navigated.push(address);
            view.set_address(Some(address));
        }
        if view.selected_id() != Some(click.id) {
            return Err(format!("the address echo dropped block {}", click.id));
        }
    }
    if selected != [1, 2, 3] || navigated != [0x10, 0x10] {
        return Err(format!("selected {selected:?}, navigated {navigated:x?}"));
    }
    view.set_graph(graph(vec![BbEdge { from: 1, to: 1, kind: BbEdgeKind::True }]), None);
    if view.selected_id().is_some() {
        return Err("replacing the graph kept the selection".into());
    }
    // Move the pointer away so hover state matches the first frame.
    frame(&mut view, vec![egui::Event::PointerGone]);
    let (_, with_loop) = frame(&mut view, Vec::new());
    if with_loop == without_loop {
        return Err("the self-loop did not change the painted frame".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn graph_interactions_hold() {
        super::graph_interactions().unwrap();
    }
}
