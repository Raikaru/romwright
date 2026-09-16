// Analyst mutations and search dialogs; the main window owns navigation and layout.
#include "main_window.h"

#include "core_bridge.h"
#include "function_table_model.h"
#include "functions_dock.h"
#include "jobs_dock.h"
#include "json_util.h"
#include "navigation_controller.h"

#include <QDialog>
#include <QAction>
#include <QDialogButtonBox>
#include <QJsonArray>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPointer>
#include <QPushButton>
#include <QShortcut>
#include <QTabBar>
#include <functional>
#include <memory>
#include <QInputDialog>
#include <QJsonObject>
#include <QLineEdit>
#include <QListWidget>
#include <QVBoxLayout>

void MainWindow::renameFunctionAt(const QString &address, const QString &name) {
    QString new_name = name;
    if (new_name.isEmpty()) {
        bool ok = false;
        new_name = QInputDialog::getText(this, QStringLiteral("Rename function"), QStringLiteral("New name:"), QLineEdit::Normal, QString(), &ok);
        if (!ok || new_name.trimmed().isEmpty()) { return; }
    }
    const int job = jobs_dock_->beginJob(QStringLiteral("rename %1").arg(address));
    const QString p = this->program();
    bridge_->request(QJsonObject{{"method", "rename"}, {"program", p}, {"address", address}, {"name", new_name}},
                     [this, guard = QPointer<MainWindow>(this), job, p, new_name](const QJsonObject &res) {
                         if (guard.isNull()) { return; }
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         decompile_cache_.clear();
                         if (this->program() == p) {
                             functions_dock_->model()->refresh();
                             decompile();
                         }
                         jobs_dock_->finishJob(job, true, QStringLiteral("renamed to %1").arg(new_name));
                     });
}

void MainWindow::renameFunction() { renameFunctionAt(address_edit_->text(), name_edit_->text().trimmed()); }

void MainWindow::applyComment() {
    const QString addr = address_edit_->text();
    const int job = jobs_dock_->beginJob(QStringLiteral("comment %1").arg(addr));
    const QString p = this->program();
    bridge_->request(QJsonObject{{"method", "comment"}, {"program", p}, {"address", addr}, {"kind", comment_kind_edit_->text()}, {"text", comment_edit_->text()}},
                     [this, guard = QPointer<MainWindow>(this), job, p](const QJsonObject &res) {
                         if (guard.isNull()) { return; }
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         if (this->program() == p) { loadListing(); }
                         jobs_dock_->finishJob(job, true, QStringLiteral("comment applied"));
                     });
}

void MainWindow::undoCommand() {
    const int job = jobs_dock_->beginJob(QStringLiteral("undo"));
    const QString p = this->program();
    bridge_->request(QJsonObject{{"method", "undo"}, {"program", p}},
                     [this, guard = QPointer<MainWindow>(this), job, p](const QJsonObject &res) {
                         if (guard.isNull()) { return; }
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         decompile_cache_.clear();
                         if (this->program() == p) {
                             functions_dock_->model()->refresh();
                             decompile();
                             loadListing();
                         }
                         jobs_dock_->finishJob(job, true, res.value("result").toObject().value("message").toString());
                     });
}

void MainWindow::showCommandPalette() {
    QDialog dialog(this);
    dialog.setObjectName(QStringLiteral("commandPalette"));
    dialog.setWindowTitle(QStringLiteral("Command palette"));
    dialog.resize(640, 420);
    auto *layout = new QVBoxLayout(&dialog);
    auto *filter = new QLineEdit(&dialog);
    filter->setObjectName(QStringLiteral("commandFilter"));
    filter->setPlaceholderText(QStringLiteral("Find a command…"));
    filter->setAccessibleName(QStringLiteral("Find a command"));
    auto *list = new QListWidget(&dialog);
    list->setObjectName(QStringLiteral("commandResults"));
    auto *status = new QLabel(&dialog);
    layout->addWidget(filter);
    layout->addWidget(list);
    layout->addWidget(status);
    QVector<QPointer<QAction>> commands;
    std::function<void(QMenu *, const QString &)> collect = [&](QMenu *menu, const QString &prefix) {
        for (auto *action : menu->actions()) {
            if (action->isSeparator())
                continue;
            QString label = action->text();
            label.remove(QLatin1Char('&'));
            const QString path = prefix.isEmpty() ? label : prefix + QStringLiteral(" / ") + label;
            if (action->menu()) {
                collect(action->menu(), path);
            } else if (action->shortcut() != QKeySequence(QStringLiteral("Ctrl+Shift+P"))) {
                auto *item = new QListWidgetItem(path, list);
                item->setData(Qt::UserRole, commands.size());
                if (!action->shortcut().isEmpty())
                    item->setText(path + QLatin1Char('\t') + action->shortcut().toString(QKeySequence::NativeText));
                if (!action->isEnabled())
                    item->setFlags(Qt::NoItemFlags);
                commands.append(action);
            }
        }
    };
    for (auto *action : menuBar()->actions())
        if (action->menu())
            collect(action->menu(), action->text().remove(QLatin1Char('&')));
    const auto apply_filter = [list, status](const QString &text) {
        int first = -1;
        int matches = 0;
        for (int row = 0; row < list->count(); ++row) {
            auto *item = list->item(row);
            const bool matches_filter = item->text().contains(text.trimmed(), Qt::CaseInsensitive);
            item->setHidden(!matches_filter);
            if (matches_filter) {
                ++matches;
                if (first < 0 && item->flags().testFlag(Qt::ItemIsEnabled))
                    first = row;
            }
        }
        list->setCurrentRow(first);
        status->setText(matches == 0 ? QStringLiteral("No matching commands.")
                                    : QStringLiteral("Enter runs the selected command; Esc closes."));
    };
    connect(filter, &QLineEdit::textChanged, &dialog, apply_filter);
    QPointer<QAction> selected;
    const auto activate = [&dialog, list, &commands, &selected]() {
        auto *item = list->currentItem();
        if (!item || item->isHidden() || !item->flags().testFlag(Qt::ItemIsEnabled))
            return;
        selected = commands.value(item->data(Qt::UserRole).toInt());
        if (selected && selected->isEnabled())
            dialog.accept();
    };
    connect(filter, &QLineEdit::returnPressed, &dialog, activate);
    connect(list, &QListWidget::itemActivated, &dialog, activate);
    for (int direction : {-1, 1}) {
        auto *shortcut = new QShortcut(QKeySequence(direction < 0 ? Qt::Key_Up : Qt::Key_Down), filter);
        shortcut->setContext(Qt::WidgetShortcut);
        connect(shortcut, &QShortcut::activated, &dialog, [list, direction]() {
            for (int row = list->currentRow() + direction; row >= 0 && row < list->count(); row += direction) {
                auto *item = list->item(row);
                if (!item->isHidden() && item->flags().testFlag(Qt::ItemIsEnabled)) {
                    list->setCurrentRow(row);
                    list->scrollToItem(item);
                    break;
                }
            }
        });
    }
    apply_filter(QString());
    filter->setFocus();
    if (dialog.exec() == QDialog::Accepted && selected)
        selected->trigger();
}

void MainWindow::showSignatureSearch() {
    QDialog dialog(this);
    dialog.setObjectName(QStringLiteral("byteSearch"));
    dialog.setWindowTitle(QStringLiteral("Byte-pattern search"));
    dialog.resize(640, 420);
    auto *layout = new QVBoxLayout(&dialog);
    auto *pattern = new QLineEdit(&dialog);
    pattern->setObjectName(QStringLiteral("bytePattern"));
    pattern->setPlaceholderText(QStringLiteral("Hex bytes; ?? matches any byte — e.g. 48 8B ??"));
    pattern->setAccessibleName(QStringLiteral("Byte pattern"));
    auto *list = new QListWidget(&dialog);
    list->setObjectName(QStringLiteral("byteSearchResults"));
    auto *status = new QLabel(&dialog);
    status->setObjectName(QStringLiteral("byteSearchStatus"));
    status->setWordWrap(true);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto *search = buttons->addButton(QStringLiteral("Search"), QDialogButtonBox::ActionRole);
    search->setObjectName(QStringLiteral("byteSearchButton"));
    layout->addWidget(pattern);
    layout->addWidget(status);
    layout->addWidget(list);
    layout->addWidget(buttons);
    const QString image = this->binary();
    auto generation = std::make_shared<quint64>(0);
    const auto changed = [=](const QString &text) {
        ++*generation;
        list->clear();
        search->setEnabled(!image.isEmpty() && !text.trimmed().isEmpty());
        status->setText(image.isEmpty() ? QStringLiteral("Open a program with a binary before searching.")
                                       : QStringLiteral("Enter a pattern and press Enter to search mapped bytes."));
    };
    connect(pattern, &QLineEdit::textChanged, &dialog, changed);
    const auto run = [this, image, generation, pattern, list, status, search,
                      guard = QPointer<QDialog>(&dialog)]() {
        if (!search->isEnabled())
            return;
        const quint64 request = ++*generation;
        search->setEnabled(false);
        list->clear();
        status->setText(QStringLiteral("Searching…"));
        bridge_->request(QJsonObject{{"method", "search_bytes"}, {"binary", image},
                                    {"pattern", pattern->text().trimmed()}, {"limit", 257}},
                         [guard, generation, request, list, status, search](const QJsonObject &res) {
                             if (!guard || request != *generation)
                                 return;
                             search->setEnabled(true);
                             QString error;
                             if (!successful(res, &error)) {
                                 status->setText(QStringLiteral("Search failed: %1").arg(error));
                                 return;
                             }
                             const auto rows = res.value("result").toArray();
                             for (int i = 0; i < qMin(rows.size(), qsizetype(256)); ++i) {
                                 const QString address = addressText(rows[i].toObject().value("address"));
                                 auto *item = new QListWidgetItem(address, list);
                                 item->setData(Qt::UserRole, address);
                             }
                             if (list->count())
                                 list->setCurrentRow(0);
                             status->setText(rows.size() > 256
                                                 ? QStringLiteral("Showing the first 256 matches; refine the pattern.")
                                                 : QStringLiteral("%1 matches. Activate a result to navigate.").arg(rows.size()));
                         });
    };
    connect(search, &QPushButton::clicked, &dialog, run);
    connect(pattern, &QLineEdit::returnPressed, &dialog, run);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(list, &QListWidget::itemActivated, &dialog, [this, &dialog](QListWidgetItem *item) {
        const QString address = item->data(Qt::UserRole).toString();
        dialog.accept();
        workspace_modes_->setCurrentIndex(0);
        navigation_->goTo(address, true);
    });
    changed(QString());
    pattern->setFocus();
    dialog.exec();
}
