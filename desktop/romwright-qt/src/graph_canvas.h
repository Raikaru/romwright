#pragma once

#include <QHash>
#include <QPointF>
#include <QPolygonF>
#include <QVector>
#include <QWidget>

/// Complete native CFG, keyed by block identity. Pan/zoom and node clicks
/// navigate; distinct native blocks may share the same instruction address.
class GraphCanvas final : public QWidget {
    Q_OBJECT

public:
    explicit GraphCanvas(QWidget *parent = nullptr);

    struct Node {
        QString id;
        QString address;
        quint64 operations = 0;
        QPointF pos;  // layout coordinates (core units)
    };
    struct Edge {
        QString from;
        QString to;
        QString kind;
    };

    /// Replaces the graph; large graphs open at a readable block scale.
    void setGraph(const QVector<Node> &nodes, const QVector<Edge> &edges);
    /// Reverse address sync preserves a specifically selected matching block.
    void setAddress(const QString &address);
    QString selectedNodeId() const;
    void fitToView();
    QSize sizeHint() const override;

signals:
    void addressSelected(const QString &address, bool record);
    void nodeSelected(const QString &blockId);

protected:
    void paintEvent(QPaintEvent *) override;
    void wheelEvent(QWheelEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void mouseDoubleClickEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;

private:
    int nodeAt(const QPoint &pos) const;
    void initialView();
    void focusCurrentBlock();
    void selectNode(int index);
    struct ResolvedEdge {
        int from_index = -1;
        int to_index = -1;
        QString kind;
        QPolygonF path;
    };

    QVector<Node> nodes_;
    QVector<ResolvedEdge> resolved_edges_;
    QHash<QString, int> node_lookup_;
    QRectF graph_bounds_;
    int selected_node_ = -1;
    double zoom_ = 1.0;
    QPointF pan_;
    bool panning_ = false;
    QPoint pan_start_;
    QString highlight_address_;
    bool fit_pending_ = false;
};
