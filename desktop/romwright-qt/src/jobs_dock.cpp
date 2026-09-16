#include "jobs_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPointer>
#include <QTimer>
#include <QPushButton>
#include <QVBoxLayout>

JobsDock::JobsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Analysis jobs"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("analysisJobsDock"));

    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 0, 0);

    jobs_summary_ = new QLabel(QStringLiteral("Worker pool: no decompile jobs"), panel);
    jobs_summary_->setObjectName(QStringLiteral("workerPoolStatus"));
    jobs_summary_->setWordWrap(true);
    layout->addWidget(jobs_summary_);

    jobs_ = new QListWidget(panel);
    jobs_->setObjectName(QStringLiteral("analysisJobs"));
    jobs_->setUniformItemSizes(true);
    jobs_->setTextElideMode(Qt::ElideRight);
    connect(jobs_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem *item) {
        if (!item->data(Qt::UserRole + 3).isValid())
            return;
        QMessageBox details(this);
        details.setWindowTitle(item->data(Qt::UserRole + 1).toString());
        details.setTextFormat(Qt::PlainText);
        details.setText(item->data(Qt::UserRole + 2).toString());
        details.exec();
    });
    layout->addWidget(jobs_, 1);

    auto *dismiss = new QPushButton(QStringLiteral("Dismiss selected"), panel);
    dismiss->setToolTip(QStringLiteral("Remove this log entry; native work continues. "
                                      "Matching jobs have their own Cancel control."));
    connect(dismiss, &QPushButton::clicked, this, &JobsDock::dismissJob);
    layout->addWidget(dismiss);

    setWidget(panel);
}

int JobsDock::beginJob(const QString &label) {
    pruneFinished();
    const int id = next_id_++;
    auto *item = new QListWidgetItem(QStringLiteral("▶ ") + label.simplified(), jobs_);
    item->setData(Qt::UserRole, id);
    item->setData(Qt::UserRole + 1, label);
    item->setToolTip(label);
    item->setForeground(QColor("#e5c07b"));
    rows_.insert(id, item);
    jobs_->scrollToBottom();
    return id;
}

void JobsDock::finishJob(int id, bool ok, const QString &detail) {
    if (auto *item = rows_.value(id, nullptr)) {
        item->setData(Qt::UserRole + 2, detail);
        item->setData(Qt::UserRole + 3, ok);
        item->setText((ok ? QStringLiteral("✓ ") : QStringLiteral("✗ ")) +
                      item->data(Qt::UserRole + 1).toString().simplified() +
                      QStringLiteral(" · ") + detail.simplified());
        item->setToolTip(detail);
        item->setForeground(ok ? QColor("#98c379") : QColor("#e06c75"));
    }
    pruneFinished();
    emit statusRequested(detail, !ok);
    refreshJobs();
}

void JobsDock::refreshJobs() {
    if (jobs_summary_ == nullptr) {
        return;
    }
    if (refresh_pending_) {
        refresh_again_ = true;
        return;
    }
    refresh_pending_ = true;
    bridge_->request(
        QJsonObject{{"method", "jobs_page"}, {"offset", 0}, {"limit", 64}},
        [this, guard = QPointer<JobsDock>(this)](const QJsonObject &response) {
            if (!guard)
                return;
            refresh_pending_ = false;
            if (refresh_again_) {
                refresh_again_ = false;
                QTimer::singleShot(0, this, &JobsDock::refreshJobs);
            }
            QString error;
            if (!successful(response, &error)) {
                jobs_summary_->setText(QStringLiteral("Worker pool unavailable: %1").arg(error));
                jobs_summary_->setStyleSheet(QStringLiteral("color:#e06c75"));
                return;
            }
            const QJsonObject result = response.value("result").toObject();
            const QJsonObject pool = result.value("pool").toObject();
            const qint64 cap_bytes = pool.value("memory_cap_bytes").toInteger();
            const QString cap = cap_bytes == 0
                                    ? QStringLiteral("unlimited")
                                    : QStringLiteral("%1 MiB").arg(cap_bytes / (1024 * 1024));
            QString summary =
                QStringLiteral("Worker pool: %1 idle, %2 busy, %3 restarts, cap %4 (%5 hits)")
                    .arg(pool.value("idle_workers").toInteger())
                    .arg(pool.value("busy_workers").toInteger())
                    .arg(pool.value("restarts").toInteger())
                    .arg(cap)
                    .arg(pool.value("memory_cap_hits").toInteger());
            const QJsonArray rows = result.value("rows").toArray();
            for (int i = rows.size() - 1; i >= 0; --i) {
                const QJsonObject row = rows.at(i).toObject();
                if (row.value("state").toString() == QStringLiteral("failed")) {
                    summary += QStringLiteral("\nLast failure: %1 — %2")
                                   .arg(row.value("operation").toString(),
                                        row.value("detail").toString());
                    break;
                }
            }
            jobs_summary_->setText(summary);
            jobs_summary_->setStyleSheet(QString());
        });
}

void JobsDock::dismissJob() {
    const int row = jobs_->currentRow();
    if (auto *item = jobs_->item(row)) {
        rows_.remove(item->data(Qt::UserRole).toInt());
        delete jobs_->takeItem(row);
    }
}

void JobsDock::pruneFinished() {
    for (int row = 0; jobs_->count() >= 512 && row < jobs_->count();) {
        auto *item = jobs_->item(row);
        if (!item->data(Qt::UserRole + 3).isValid()) {
            ++row;
            continue;
        }
        rows_.remove(item->data(Qt::UserRole).toInt());
        delete jobs_->takeItem(row);
    }
}
