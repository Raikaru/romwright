// The analyst's mutating commands and the two search dialogs. They belong
// beside the window rather than inside it: `main_window.cpp` builds the
// window and routes navigation, and m0-006 keeps that file small enough to
// read (`tests/main_window_split_test.py`).
#include "main_window.h"

#include "core_bridge.h"
#include "function_table_model.h"
#include "functions_dock.h"
#include "jobs_dock.h"
#include "json_util.h"

#include <QDialog>
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
    bridge_->request(QJsonObject{{"method", "rename"}, {"program", program_edit_->text()}, {"address", address}, {"name", new_name}},
                     [this, job, address, new_name](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         decompile_cache_.remove(program_edit_->text() + QLatin1Char('|') + address);
                         functions_dock_->model()->refresh();
                         decompile();
                         jobs_dock_->finishJob(job, true, QStringLiteral("renamed to %1").arg(new_name));
                     });
}

void MainWindow::renameFunction() { renameFunctionAt(address_edit_->text(), name_edit_->text().trimmed()); }

void MainWindow::applyComment() {
    const QString addr = address_edit_->text();
    const int job = jobs_dock_->beginJob(QStringLiteral("comment %1").arg(addr));
    bridge_->request(QJsonObject{{"method", "comment"}, {"program", program_edit_->text()}, {"address", addr}, {"kind", comment_kind_edit_->text()}, {"text", comment_edit_->text()}},
                     [this, job, addr](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         loadListingAt(addr);
                         jobs_dock_->finishJob(job, true, QStringLiteral("comment applied"));
                     });
}

void MainWindow::undoCommand() {
    const int job = jobs_dock_->beginJob(QStringLiteral("undo"));
    bridge_->request(QJsonObject{{"method", "undo"}, {"program", program_edit_->text()}},
                     [this, job](const QJsonObject &res) {
                         QString err;
                         if (!successful(res, &err)) { jobs_dock_->finishJob(job, false, err); return; }
                         functions_dock_->model()->refresh();
                         decompile();
                         loadListing();
                         jobs_dock_->finishJob(job, true, res.value("result").toObject().value("message").toString());
                     });
}

void MainWindow::showCommandPalette() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Command palette"));
    auto *l = new QVBoxLayout(&dialog);
    auto *filter = new QLineEdit(&dialog);
    auto *list = new QListWidget(&dialog);
    l->addWidget(filter);
    l->addWidget(list);
    connect(list, &QListWidget::itemActivated, &dialog, &QDialog::accept);
    dialog.exec();
}

void MainWindow::showSignatureSearch() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Byte-pattern signature search"));
    auto *l = new QVBoxLayout(&dialog);
    auto *pattern_edit = new QLineEdit(&dialog);
    auto *list = new QListWidget(&dialog);
    l->addWidget(pattern_edit);
    l->addWidget(list);
    dialog.exec();
}
