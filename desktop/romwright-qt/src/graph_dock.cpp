#include "graph_dock.h"
#include "graph_canvas.h"
#include <QJsonArray>

GraphDock::GraphDock(QWidget *parent)
    : QDockWidget(QStringLiteral("Function graph"), parent), canvas_(new GraphCanvas(this)) {
    setObjectName("functionGraphDock");
    connect(canvas_, &GraphCanvas::addressSelected, this, &GraphDock::addressSelected);
    setWidget(canvas_);
}

void GraphDock::setGraph(const QJsonObject &graph) {
    QVector<GraphCanvas::Node> nodes;
    QVector<GraphCanvas::Edge> edges;
    if (graph.value("complete").toBool()) {
        for (const auto &value : graph.value("nodes").toArray()) {
            const auto row = value.toObject();
            GraphCanvas::Node node;
            node.id = row.value("id").toString();
            node.address = row.value("address").toString();
            node.operations = row.value("operations").toVariant().toULongLong();
            node.pos = QPointF(row.value("x").toDouble(), row.value("y").toDouble());
            nodes.append(node);
        }
        for (const auto &value : graph.value("edges").toArray()) {
            const auto row = value.toObject();
            edges.append({row.value("from").toString(), row.value("to").toString(),
                          row.value("kind").toString()});
        }
    }
    canvas_->setGraph(nodes, edges);
    setWindowTitle(nodes.isEmpty() ? QStringLiteral("Function graph — unavailable")
                                   : QStringLiteral("Native CFG — %1 blocks, %2 edges")
                                         .arg(nodes.size())
                                         .arg(edges.size()));
}
