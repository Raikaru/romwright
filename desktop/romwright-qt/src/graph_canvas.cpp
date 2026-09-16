#include "graph_canvas.h"

#include "theme.h"

#include <QFontDatabase>
#include <QContextMenuEvent>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QPainter>
#include <QWheelEvent>
#include <algorithm>

namespace {


constexpr int kNodeWidth = 180;
constexpr int kNodeHeight = 60;

QColor edgeColor(const QString &kind) {
    if (kind == QStringLiteral("true")) {
        return Theme::current().edge_true;
    }
    if (kind == QStringLiteral("false")) {
        return Theme::current().edge_false;
    }
    if (kind == QStringLiteral("call")) {
        return Theme::current().edge_call;
    }
    return Theme::current().edge_unconditional;
}

}  // namespace

GraphCanvas::GraphCanvas(QWidget *parent) : QWidget(parent) {
    setMinimumSize(420, 260);
    setMouseTracking(false);
    setFocusPolicy(Qt::StrongFocus);
    setToolTip(QStringLiteral("Wheel: zoom · Shift-drag or middle-drag: pan\n"
                              "Home: current block · F: fit entire graph"));
}

void GraphCanvas::setGraph(const QVector<Node> &nodes, const QVector<Edge> &edges) {
    nodes_ = nodes;
    selected_node_ = -1;
    highlight_address_.clear();
    panning_ = false;
    node_lookup_.clear();
    QRectF node_bounds;
    for (int i = 0; i < nodes_.size(); ++i) {
        node_lookup_.insert(nodes_[i].id, i);
        node_bounds = node_bounds.united(QRectF(nodes_[i].pos, QSizeF(kNodeWidth, kNodeHeight)));
    }
    graph_bounds_ = node_bounds;
    resolved_edges_.clear();
    resolved_edges_.reserve(edges.size());
    QVector<int> outer_edges;
    for (const Edge &edge : edges) {
        const int from = node_lookup_.value(edge.from, -1);
        const int to = node_lookup_.value(edge.to, -1);
        if (from < 0) {
            continue;
        }
        ResolvedEdge resolved;
        resolved.from_index = from;
        resolved.to_index = to;
        resolved.kind = edge.kind;
        const QPointF start = nodes_[from].pos + QPointF(kNodeWidth / 2.0, kNodeHeight);
        if (to < 0) {
            resolved.path = {start, start + QPointF(0, 30)};
        } else if (from == to) {
            // A loop occupies the gap beside its own node, not a zero-length line.
            const QPointF upper = nodes_[from].pos + QPointF(kNodeWidth, 20);
            const QPointF lower = upper + QPointF(0, 20);
            resolved.path = {lower, lower + QPointF(24, 0), upper + QPointF(24, 0), upper};
        } else {
            const QPointF end = nodes_[to].pos + QPointF(kNodeWidth / 2.0, 0);
            if (end.y() > start.y() && end.y() - start.y() <= 90) {
                const qreal middle = (start.y() + end.y()) / 2;
                resolved.path = {start, QPointF(start.x(), middle), QPointF(end.x(), middle), end};
            } else {
                // Long and feedback edges travel outside node columns; their
                // horizontal legs stay in row gaps, never through other blocks.
                resolved.path = {start, start + QPointF(0, 24),
                                 end - QPointF(0, 24), end};
                outer_edges.append(resolved_edges_.size());
            }
        }
        resolved_edges_.append(resolved);
    }
    std::stable_sort(outer_edges.begin(), outer_edges.end(), [this](int a, int b) {
        const auto &pa = resolved_edges_[a].path;
        const auto &pb = resolved_edges_[b].path;
        return qMin(pa[1].y(), pa[2].y()) < qMin(pb[1].y(), pb[2].y());
    });
    QVector<qreal> occupied_until[2];
    for (int index : outer_edges) {
        auto &path = resolved_edges_[index].path;
        const qreal top = qMin(path[1].y(), path[2].y());
        const qreal bottom = qMax(path[1].y(), path[2].y());
        const bool right = (path.first().x() + path.last().x()) / 2 >= node_bounds.center().x();
        auto &lanes = occupied_until[right ? 1 : 0];
        int lane = 0;
        while (lane < lanes.size() && lanes[lane] + 8 >= top) {
            ++lane;
        }
        if (lane == lanes.size()) {
            lanes.append(bottom);
        } else {
            lanes[lane] = bottom;
        }
        const qreal x = right ? node_bounds.right() + 24 + lane * 10
                              : node_bounds.left() - 24 - lane * 10;
        path = {path[0], path[1], QPointF(x, path[1].y()),
                QPointF(x, path[2].y()), path[2], path[3]};
    }
    for (const auto &edge : resolved_edges_) {
        graph_bounds_ = graph_bounds_.united(edge.path.boundingRect());
    }
    zoom_ = 1.0;
    pan_ = QPointF(0, 0);
    fit_pending_ = true;
    update();
}

void GraphCanvas::setAddress(const QString &address) {
    if (address.isEmpty() || selected_node_ < 0 || nodes_[selected_node_].address != address) {
        selected_node_ = -1;
    }
    highlight_address_ = address;
    update();
}

QString GraphCanvas::selectedNodeId() const {
    return selected_node_ < 0 ? QString{} : nodes_[selected_node_].id;
}

void GraphCanvas::fitToView() {
    fit_pending_ = false;
    if (nodes_.isEmpty()) {
        return;
    }
    const QRectF bounds = graph_bounds_;
    if (bounds.width() <= 0 || bounds.height() <= 0) {
        return;
    }
    const double zx = qMax(1, width() - 40) / bounds.width();
    const double zy = qMax(1, height() - 40) / bounds.height();
    zoom_ = qMin(qMin(zx, zy), 2.0);
    pan_ = QPointF((width() - bounds.width() * zoom_) / 2.0 - bounds.x() * zoom_,
                  (height() - bounds.height() * zoom_) / 2.0 - bounds.y() * zoom_);
    update();
}

void GraphCanvas::focusCurrentBlock() {
    if (nodes_.isEmpty()) {
        return;
    }
    int index = selected_node_;
    if (index < 0 && !highlight_address_.isEmpty()) {
        for (int i = 0; i < nodes_.size(); ++i) {
            if (nodes_[i].address == highlight_address_) {
                index = i;
                break;
            }
        }
    }
    if (index < 0) {
        index = 0;
    }
    fit_pending_ = false;
    zoom_ = 1.0;
    pan_ = QPointF((width() - kNodeWidth) / 2.0, 24) - nodes_[index].pos;
    update();
}

void GraphCanvas::initialView() {
    fitToView();
    if (zoom_ < 0.65) {
        focusCurrentBlock();
    }
}

QSize GraphCanvas::sizeHint() const { return {640, 320}; }


int GraphCanvas::nodeAt(const QPoint &pos) const {
    const QPointF scene_pos = (QPointF(pos) - pan_) / zoom_;
    for (int index = 0; index < nodes_.size(); ++index) {
        if (QRectF(nodes_[index].pos, QSizeF(kNodeWidth, kNodeHeight)).contains(scene_pos)) {
            return index;
        }
    }
    return -1;
}

void GraphCanvas::selectNode(int index) {
    selected_node_ = index;
    highlight_address_ = nodes_[index].address;
    emit nodeSelected(nodes_[index].id);
    if (!highlight_address_.isEmpty()) {
        emit addressSelected(highlight_address_, true);
    }
    update();
}

void GraphCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), Theme::current().background);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

    if (nodes_.isEmpty()) {
        painter.setPen(Theme::current().empty_text);
        painter.drawText(rect().adjusted(8, 8, -8, -8), Qt::AlignTop | Qt::AlignLeft,
                         QStringLiteral("No function graph loaded"));
        return;
    }
    if (fit_pending_) {
        initialView();
    }

    painter.translate(pan_);
    painter.scale(zoom_, zoom_);
    for (const ResolvedEdge &edge : resolved_edges_) {
        QPen pen(edgeColor(edge.kind), 1.5);
        pen.setCosmetic(true);
        if (edge.kind == QStringLiteral("call")) {
            pen.setStyle(Qt::DashLine);
        }
        painter.setPen(pen);
        painter.drawPolyline(edge.path);
        if (edge.to_index >= 0) {
            const QPointF tip = edge.path.last();
            const QPointF dir = tip - edge.path[edge.path.size() - 2];
            const double len = qSqrt(dir.x() * dir.x() + dir.y() * dir.y());
            if (len > 0) {
                const QPointF unit = dir / len;
                const qreal size = 10 / qMax(1.0, zoom_);
                const QPointF normal(-unit.y(), unit.x());
                const QPointF arrow[] = {tip, tip - unit * size + normal * (size / 2),
                                         tip - unit * size - normal * (size / 2)};
                painter.setBrush(pen.color());
                painter.drawPolygon(arrow, 3);
                painter.setBrush(Qt::NoBrush);
            }
        }
    }

    for (int index = 0; index < nodes_.size(); ++index) {
        const Node &node = nodes_[index];
        const QRectF box(node.pos, QSizeF(kNodeWidth, kNodeHeight));
        const bool highlighted = selected_node_ >= 0 ? index == selected_node_
            : !highlight_address_.isEmpty() && node.address == highlight_address_;
        painter.setBrush(Theme::current().node_fill);
        QPen border(highlighted ? Theme::current().node_highlight : Theme::current().node_border,
                    highlighted ? 2 : 1);
        border.setCosmetic(true);
        painter.setPen(border);
        painter.drawRoundedRect(box, 5, 5);
        if (zoom_ >= 0.35) {
            painter.setPen(Theme::current().node_text);
            const QString label = QStringLiteral("bb_%1 · %2\n%3 operations")
                .arg(node.id, node.address.isEmpty() ? QStringLiteral("no address") : node.address)
                .arg(node.operations);
            painter.drawText(box.adjusted(6, 4, -6, -4), Qt::AlignCenter, label);
        }
    }
}

void GraphCanvas::wheelEvent(QWheelEvent *event) {
    const double factor = event->angleDelta().y() > 0 ? 1.15 : 1 / 1.15;
    const double new_zoom = qBound(0.0001, zoom_ * factor, 3.0);
    // Zoom around the cursor.
    const QPointF cursor = event->position();
    pan_ = cursor - (cursor - pan_) * (new_zoom / zoom_);
    zoom_ = new_zoom;
    update();
    event->accept();
}

void GraphCanvas::mousePressEvent(QMouseEvent *event) {
    if (event->button() == Qt::MiddleButton ||
        (event->button() == Qt::LeftButton && event->modifiers() & Qt::ShiftModifier)) {
        panning_ = true;
        pan_start_ = event->pos();
        event->accept();
        return;
    }
    if (event->button() == Qt::LeftButton) {
        const int index = nodeAt(event->pos());
        if (index >= 0) {
            selectNode(index);
            event->accept();
            return;
        }
    }
    QWidget::mousePressEvent(event);
}

void GraphCanvas::mouseMoveEvent(QMouseEvent *event) {
    if (panning_) {
        pan_ += QPointF(event->pos() - pan_start_);
        pan_start_ = event->pos();
        update();
        event->accept();
    }
}

void GraphCanvas::mouseReleaseEvent(QMouseEvent *event) {
    panning_ = false;
    QWidget::mouseReleaseEvent(event);
}

void GraphCanvas::mouseDoubleClickEvent(QMouseEvent *event) {
    const int index = nodeAt(event->pos());
    if (event->button() == Qt::LeftButton && index >= 0) {
        selectNode(index);
    }
    event->accept();
}

void GraphCanvas::resizeEvent(QResizeEvent *event) {
    if (!nodes_.isEmpty() && fit_pending_) {
        initialView();
    }
    QWidget::resizeEvent(event);
}

void GraphCanvas::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_Home) {
        focusCurrentBlock();
    } else if (event->key() == Qt::Key_F && event->modifiers() == Qt::NoModifier) {
        fitToView();
    } else {
        QWidget::keyPressEvent(event);
        return;
    }
    event->accept();
}

void GraphCanvas::contextMenuEvent(QContextMenuEvent *event) {
    QMenu menu(this);
    menu.addAction(QStringLiteral("Current block (Home)"), this, &GraphCanvas::focusCurrentBlock);
    menu.addAction(QStringLiteral("Fit entire graph (F)"), this, &GraphCanvas::fitToView);
    menu.exec(event->globalPos());
}
