#pragma once
#include <QDockWidget>
#include <QJsonObject>
class GraphCanvas;

class GraphDock final : public QDockWidget {
    Q_OBJECT
  public:
    explicit GraphDock(QWidget *parent = nullptr);
    GraphCanvas *canvas() const { return canvas_; }
    void setGraph(const QJsonObject &graph);
  signals:
    void addressSelected(const QString &address, bool record);

  private:
    GraphCanvas *canvas_;
};
