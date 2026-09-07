#pragma once

#include <QDockWidget>

class CoreBridge;
class QTableWidget;
class QTabWidget;

class XrefsDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit XrefsDock(CoreBridge *bridge, QWidget *parent = nullptr);

    void loadXrefs(const QString &program, const QString &address);

    /// Rows rendered, and how many arrived with no evidence sentence. The UI
    /// gate publishes both, so "every fact says what proved it" is measured
    /// on what the table holds rather than asserted.
    int renderedRows() const { return rendered_rows_; }
    int unexplainedRows() const { return unexplained_rows_; }

signals:
    void addressDoubleClicked(const QString &address);
    /// Both tables have answered: the counters below are final.
    void loadFinished();
    void jobStarted(const QString &name);
    void jobFinished(const QString &name, bool ok, const QString &detail);

private:
    CoreBridge *bridge_;
    QTableWidget *xrefs_to_ = nullptr;
    QTableWidget *xrefs_from_ = nullptr;
    int pending_ = 0;
    int rendered_rows_ = 0;
    int unexplained_rows_ = 0;
};
