#pragma once

#include <QDockWidget>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <functional>

class CoreBridge;
class QComboBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QTimer;

class MatchingDock final : public QDockWidget {
    Q_OBJECT
  public:
    explicit MatchingDock(CoreBridge *bridge, QWidget *parent = nullptr);
    bool setProgram(const QString &program, const QString &binary);
    bool confirmClose(QWidget *closing_window);
    void createWorkspace(const QJsonObject &setup);
    void loadWorkspace(qint64 id);
    void loadCandidate(qint64 id);
    void executeOperation(const QJsonObject &operation);

  signals:
    void jobStarted(const QString &label);
    void jobFinished(const QString &label, bool ok, const QString &detail);
    void workspaceLoaded(qint64 id);
    void candidateLoaded(qint64 id);
    void operationFinished(const QJsonValue &result);
    void statusRequested(const QString &message, bool error);

  private:
    using ValueCallback = std::function<void(const QJsonValue &)>;
    void workspaceRequest(QJsonObject operation, ValueCallback callback);
    void refreshWorkspaces(qint64 after = 0);
    void refreshCandidates(qint64 after = 0);
    void refreshHistory(qint64 after = 0);
    void refreshChecks(qint64 after = 0);
    void loadSource();
    void acceptCandidate(const QJsonObject &candidate);
    void saveSource(std::function<void()> continuation = {});
    void discardSource();
    void pinSelection(bool clear = false);
    void searchSelection();
    void pollJob();
    void cancelJob();
    void renderResult(const QJsonValue &result);
    void renderPins();
    void updateControls();
    void fail(const QString &message);
    bool canLeaveSource();
    QJsonObject selection() const;
    void createWorkspaceDialog();
    void addProfile();
    void calibrate();
    void trialContext();
    void explicitSearch();
    void configureProject();
    void preparePatch();
    void verifyPatch(bool apply);
    void exportWorkspace();
    void importWorkspace();

    CoreBridge *bridge_;
    QString program_, binary_, loaded_file_, loaded_source_, job_label_;
    QJsonObject workspace_, candidate_, patch_;
    QJsonArray trials_, checks_;
    QJsonValue result_;
    quint64 generation_ = 0;
    quint64 candidate_generation_ = 0;
    qint64 job_ = 0;
    int pending_ = 0;
    bool busy_ = false;
    bool poll_pending_ = false;
    QComboBox *workspaces_, *candidates_, *profiles_, *files_;
    QPlainTextEdit *source_, *details_, *patch_text_;
    QTableWidget *mismatches_, *history_;
    QTabWidget *tabs_;
    QLabel *summary_, *state_, *pins_;
    QSpinBox *budget_, *seconds_;
    QPushButton *save_, *discard_, *run_, *search_, *cancel_, *prepare_, *verify_, *apply_;
    QTimer *timer_;
    QList<QWidget *> idle_controls_;
};
