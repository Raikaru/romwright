#pragma once

#include <QDockWidget>

class CoreBridge;
class QLabel;
class QLineEdit;
class QTableWidget;
class QTableView;
class StringsTableModel;

class FactsDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit FactsDock(CoreBridge *bridge, QWidget *parent = nullptr);

    StringsTableModel *stringsModel() const { return strings_model_; }
    void loadFacts(const QString &program, const QString &search_term = QString());

signals:
    void addressSelected(const QString &address, bool record);
    void addressDoubleClicked(const QString &address);
    void statusRequested(const QString &message, bool error);

private:
    void searchFacts();
    QString program_;
    quint64 generation_ = 0;
    quint64 search_generation_ = 0;
    QLineEdit *search_edit_ = nullptr;
    QLabel *search_status_ = nullptr;
    CoreBridge *bridge_;
    QTableWidget *symbols_ = nullptr;
    QTableView *strings_ = nullptr;
    StringsTableModel *strings_model_ = nullptr;
    QTableWidget *search_results_ = nullptr;
};
