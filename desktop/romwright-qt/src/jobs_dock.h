#pragma once

#include <QDockWidget>
#include <QHash>

class CoreBridge;
class QLabel;
class QListWidget;
class QListWidgetItem;

class JobsDock final : public QDockWidget {
    Q_OBJECT

public:
    explicit JobsDock(CoreBridge *bridge, QWidget *parent = nullptr);

    int beginJob(const QString &label);
    void finishJob(int id, bool ok, const QString &detail);
    void refreshJobs();
    void dismissJob();

signals:
    void statusRequested(const QString &message, bool error);

private:
    void pruneFinished();
    CoreBridge *bridge_;
    QLabel *jobs_summary_ = nullptr;
    QListWidget *jobs_ = nullptr;
    QHash<int, QListWidgetItem *> rows_;
    int next_id_ = 0;
    bool refresh_pending_ = false;
    bool refresh_again_ = false;
};
