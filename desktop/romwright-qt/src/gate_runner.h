#pragma once

#include <QElapsedTimer>
#include <QJsonObject>
#include <QObject>
#include <QString>

class CoreBridge;
class MainWindow;

class GateRunner final : public QObject {
    Q_OBJECT

public:
    explicit GateRunner(MainWindow *window, CoreBridge *bridge, QObject *parent = nullptr);

    void run(bool store_only = false);
    void modelRefreshed();

private:
    void recordInstallFacts();
    bool sourceInteractions();
    bool graphInteractions();
    void startLargestFunction();
    void startDecompile(const QString &address);
    void startGraph(const QJsonObject &graph);
    void startXrefs();
    void startFilteredXrefs();
    void startProgramSwitch();
    void finishProgramSwitch(int functions);
    void awaitAnalysis(int polls);
    void finish(bool ok, const QString &detail = {});

    MainWindow *window_;
    CoreBridge *bridge_;

    enum class Stage { Inactive, LoadingList, Filtering, ClearingFilter };
    bool active_ = false;
    bool store_only_ = false;
    Stage stage_ = Stage::Inactive;
    QElapsedTimer timer_;
    QJsonObject metrics_;
    QString address_;
};
