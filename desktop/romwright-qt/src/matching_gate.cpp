#include "matching_gate.h"
#include "main_window.h"
#include "matching_dock.h"
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QInputDialog>
#include <QJsonDocument>
#include <QLineEdit>
#include <QMap>
#include <QMessageBox>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextDocument>
#include <QTextStream>
#include <QTimer>

namespace {
class MatchingGate final : public QObject {
  public:
    MatchingGate(MainWindow *window, const QString &path) : QObject(window), dock_(window->matchingDock()) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            fail(QStringLiteral("Cannot open gate configuration"));
            return;
        }
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(file.readAll(), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) {
            fail(QStringLiteral("Invalid gate configuration"));
            return;
        }
        config_ = document.object();
        elapsed_.start();
        window->resize(1440, 920);
        window->showMatchingWorkspace();
        source_ = dock_->findChild<QPlainTextEdit *>(QStringLiteral("matchingSource"));
        connect(dock_, &MatchingDock::candidateLoaded, this, [this](qint64) {
            if (phase_ == 1 && source_->toPlainText().contains(QStringLiteral("+ 2")))
                phase_ = 2;
            else if (phase_ == 6 && source_->toPlainText().contains(QStringLiteral("+ 1")))
                phase_ = 7;
            else if (phase_ == 8) {
                if (!require(!source_->extraSelections().isEmpty() &&
                                 source_->extraSelections().first().cursor.selectedText() ==
                                     QStringLiteral("1"),
                             QStringLiteral("UTF-8 pin did not select the correct UTF-16 "
                                            "source character")))
                    return;
                pinned_ = dock_->findChild<QComboBox *>(QStringLiteral("matchingCandidate"))
                              ->currentData()
                              .toLongLong();
                phase_ = 9;
            } else if (phase_ == 18 && source_->toPlainText().contains(QStringLiteral("unsigned char")))
                phase_ = 19;
            else if (phase_ == 33)
                phase_ = 34;
            else if (phase_ == 35 && source_->toPlainText().contains(QStringLiteral("+ 1")))
                phase_ = 36;
        });
        connect(dock_, &MatchingDock::statusRequested, this, [this](const QString &message, bool error) {
            if (!error || finished_)
                return;
            if (phase_ == 10) {
                if (!require(source_->document()->isModified() &&
                                 source_->toPlainText().contains(QStringLiteral("+ 9")) &&
                                 dock_->findChild<QComboBox *>(QStringLiteral("matchingCandidate"))
                                         ->currentData()
                                         .toLongLong() == pinned_,
                             QStringLiteral("Rejected pin edit changed immutable candidate state")))
                    return;
                phase_ = 11;
            } else
                fail(message);
        });
        connect(dock_, &MatchingDock::jobFinished, this,
                [this](const QString &, bool ok, const QString &message) {
                    if (!ok)
                        fail(message);
                });
        connect(dock_, &MatchingDock::operationFinished, this, [this](const QJsonValue &value) {
            if (finished_)
                return;
            const auto result = value.toObject();
            if (phase_ == 3) {
                const auto diagnosis = result.value("diagnosis").toObject();
                const auto *rows = dock_->findChild<QTableWidget *>(QStringLiteral("matchingMismatches"));
                if (!require(diagnosis.value("similarity").isDouble() &&
                                 diagnosis.value("similarity").toDouble() < 100.0 && rows->rowCount() > 0,
                             QStringLiteral("Initial mismatch was not visible")))
                    return;
                mismatch_rows_ = rows->rowCount();
                revision_ =
                    result.value("run").toObject().value("record").toObject().value("revision").toInteger();
                QTimer::singleShot(0, this, [this]() {
                    if (require(dock_->grab().save(config_.value("before_image").toString()),
                                QStringLiteral("Could not save mismatch screenshot")))
                        phase_ = 4;
                });
            } else if (phase_ == 5) {
                if (!require(result.value("compiler_invocations").toInt() == 2 &&
                                 result.value("best_candidate").isDouble(),
                             QStringLiteral("Bounded search did not finish in two "
                                            "actual compilations")))
                    return;
                const auto trials = result.value("trials").toArray();
                if (!require(!trials.isEmpty() && trials.last()
                                                      .toObject()
                                                      .value("diagnosis")
                                                      .toObject()
                                                      .value("exact_object_bytes")
                                                      .toBool(),
                             QStringLiteral("Search did not reach exact object bytes")))
                    return;
                phase_ = 6;
            } else if (phase_ == 13) {
                if (!require(result.value("candidate").toInteger() == pinned_ &&
                                 result.value("diagnosis").toObject().value("exact_object_bytes").toBool(),
                             QStringLiteral("Reverted pinned candidate did not recompile exactly")))
                    return;
                phase_ = 14;
            } else if (phase_ == 16) {
                const auto ranking = result.value("ranking").toArray();
                if (!require(ranking.size() == 1 && ranking.first().toArray().last().toDouble() == 100.0,
                             QStringLiteral("Desktop calibration did not compile "
                                            "its selected reference")))
                    return;
                phase_ = 17;
            } else if (phase_ == 20) {
                const auto comparisons = value.toArray();
                if (!require(comparisons.size() == 1 &&
                                 comparisons.first().toObject().value("delta").toDouble() < 0 &&
                                 source_->toPlainText().contains(QStringLiteral("unsigned char")),
                             QStringLiteral("Context trial did not report the regression "
                                            "while preserving selected context")))
                    return;
                phase_ = 21;
            } else if (phase_ == 24) {
                if (!require(!result.value("unified_diff").toString().isEmpty(),
                             QStringLiteral("Real-project source preview is empty")))
                    return;
                phase_ = 25;
            } else if (phase_ == 26 || phase_ == 28) {
                if (!require(result.value("baseline_build_succeeded").toBool() &&
                                 result.value("build_succeeded").toBool() &&
                                 result.value("original_inputs_unchanged").toBool() &&
                                 result.value("diagnosis").toObject().value("exact_object_bytes").toBool() &&
                                 result.value("unexpected_symbols").toArray().isEmpty() &&
                                 result.value("applied").toBool() == (phase_ == 28),
                             QStringLiteral("Desktop real-project verification did not "
                                            "preserve its build/application contract")))
                    return;
                phase_ = phase_ == 26 ? 27 : 29;
            } else if (phase_ == 37) {
                if (!require(result.value("diagnosis").toObject().value("exact_object_bytes").toBool() &&
                                 !result.value("imported").toBool() &&
                                 result.value("run")
                                         .toObject()
                                         .value("record")
                                         .toObject()
                                         .value("revision")
                                         .toInteger() == revision_,
                             QStringLiteral("Imported source did not replay exactly "
                                            "without changing program facts")))
                    return;
                phase_ = 38;
            }
        });
        timer_ = new QTimer(this);
        timer_->setInterval(20);
        connect(timer_, &QTimer::timeout, this, [this]() { tick(); });
        timer_->start();
        auto *dialogs = new QTimer(this);
        dialogs->setInterval(20);
        connect(dialogs, &QTimer::timeout, this, [this]() { handleModal(); });
        dialogs->start();
        QTimer::singleShot(60000, this, [this]() {
            if (!finished_)
                fail(QStringLiteral("Matching desktop gate timed out at phase %1").arg(phase_));
        });
    }

  private:
    bool require(bool ok, const QString &message) {
        if (!ok)
            fail(message);
        return ok;
    }
    void fail(const QString &message) {
        if (finished_)
            return;
        finished_ = true;
        if (timer_)
            timer_->stop();
        QTextStream(stderr) << "matching UI gate: " << message << '\n';
        QCoreApplication::exit(1);
    }
    QPushButton *button(const char *name) {
        return dock_->findChild<QPushButton *>(QString::fromLatin1(name));
    }
    bool selectLiteral(const QString &literal) {
        const int start = source_->toPlainText().indexOf(QStringLiteral("+ ") + literal);
        if (!require(start >= 0, QStringLiteral("Literal selection is missing")))
            return false;
        auto cursor = source_->textCursor();
        cursor.setPosition(start + 2);
        cursor.setPosition(start + 2 + literal.size(), QTextCursor::KeepAnchor);
        source_->setTextCursor(cursor);
        source_->setFocus();
        return true;
    }
    void handleModal() {
        if (finished_)
            return;
        auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!dialog || configured_dialog_ == dialog)
            return;
        if (auto *message = qobject_cast<QMessageBox *>(dialog)) {
            if (phase_ == 28 || phase_ == 30) {
                configured_dialog_ = dialog;
                message->button(QMessageBox::Yes)->click();
            } else
                fail(message->text());
            return;
        }
        if (auto *files = qobject_cast<QFileDialog *>(dialog)) {
            if (phase_ != 22 && phase_ != 30 && phase_ != 32)
                return;
            configured_dialog_ = dialog;
            if (phase_ == 22) {
                files->setDirectory(config_.value("root").toString());
                files->selectFile(config_.value("root").toString());
            } else if (phase_ == 30 || files->fileMode() != QFileDialog::ExistingFiles)
                files->selectFile(config_.value("bundle").toString());
            else {
                files->setDirectory(config_.value("store").toString() + QStringLiteral("/artifacts"));
                auto *names = files->findChild<QLineEdit *>(QStringLiteral("fileNameEdit"));
                if (!require(names != nullptr,
                             QStringLiteral("Private input chooser has no filename editor")))
                    return;
                QStringList selected;
                for (const auto &digest : private_inputs_)
                    selected << QLatin1Char('"') + digest + QLatin1Char('"');
                names->setText(selected.join(QLatin1Char(' ')));
            }
            QTimer::singleShot(50, dialog, [dialog]() { dialog->accept(); });
            return;
        }
        if (auto *input = qobject_cast<QInputDialog *>(dialog); input && phase_ == 22) {
            configured_dialog_ = dialog;
            input->setTextValue(QStringLiteral("unit.o"));
            dialog->accept();
            return;
        }
        auto *editor = dialog->findChild<QPlainTextEdit *>(QStringLiteral("matchingJsonEditor"));
        if (!editor || (phase_ != 16 && phase_ != 20 && phase_ != 22 && phase_ != 32))
            return;
        configured_dialog_ = dialog;
        auto object = QJsonDocument::fromJson(editor->toPlainText().toUtf8()).object();
        if (phase_ == 20) {
            auto request = object.value("request").toObject();
            auto edits = request.value("edits").toArray();
            auto edit = edits.first().toObject();
            edit.insert("replacement", "unsigned int");
            edits[0] = edit;
            request.insert("edits", edits);
            object.insert("request", request);
        } else if (phase_ == 22) {
            object = config_.value("project").toObject();
            phase_ = 23;
        } else if (phase_ == 32) {
            object.insert("project_root", QJsonValue::Null);
            phase_ = 33;
        }
        editor->setPlainText(QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Indented)));
        dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
    }

    bool inspectBundle() {
        QFile file(config_.value("bundle").toString());
        if (!file.open(QIODevice::ReadOnly))
            return false;
        const auto bundle = QJsonDocument::fromJson(file.readAll()).object();
        const auto artifacts = bundle.value("artifacts").toObject(),
                   spec = bundle.value("workspace").toObject();
        auto input = [&](const QJsonObject &value) {
            const auto digest = value.value("digest").toString();
            if (!value.value("redistributable").toBool() && artifacts.contains(digest)) {
                fail(QStringLiteral("Desktop export included private bytes"));
                return;
            }
            if (!artifacts.contains(digest))
                private_inputs_.insert(digest);
        };
        input(spec.value("target").toObject());
        for (const auto &candidate : bundle.value("candidates").toArray()) {
            const auto files = candidate.toObject().value("spec").toObject().value("files").toObject();
            for (auto it = files.begin(); it != files.end(); ++it)
                input(it.value().toObject());
        }
        for (const auto &value : spec.value("profiles").toArray()) {
            const auto profile = value.toObject();
            if (!require(!artifacts.contains(profile.value("compiler_digest").toString()),
                         QStringLiteral("Desktop export included compiler bytes")))
                return false;
            const auto tools = profile.value("tools").toObject();
            for (auto it = tools.begin(); it != tools.end(); ++it)
                if (!require(!artifacts.contains(it.value().toObject().value("digest").toString()),
                             QStringLiteral("Desktop export included a proprietary tool")))
                    return false;
        }
        return !finished_;
    }

    void tick() {
        if (finished_)
            return;
        if (phase_ == 0 && button("matchingNew")->isEnabled()) {
            phase_ = 1;
            QTimer::singleShot(0, this, [this]() {
                auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
                if (!require(dialog != nullptr, QStringLiteral("New-workspace dialog did not open")))
                    return;
                const QMap<QString, QString> fields{
                    {"matchingSetupName", "name"},     {"matchingSetupSymbol", "symbol"},
                    {"matchingSetupTarget", "target"}, {"matchingSetupSource", "source"},
                    {"matchingSetupRoot", "root"},     {"matchingSetupCompiler", "compiler"}};
                for (auto it = fields.begin(); it != fields.end(); ++it) {
                    auto *field = dialog->findChild<QLineEdit *>(it.key());
                    if (!require(field != nullptr, QStringLiteral("Setup field missing")))
                        return;
                    field->setText(config_.value(it.value()).toString());
                }
                dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Ok)->click();
            });
            button("matchingNew")->click();
        } else if (phase_ == 2 && button("matchingRun")->isEnabled()) {
            phase_ = 3;
            button("matchingRun")->click();
        } else if (phase_ == 4 && button("matchingSearch")->isEnabled()) {
            if (!selectLiteral(QStringLiteral("2")))
                return;
            dock_->findChild<QSpinBox *>(QStringLiteral("matchingBudget"))->setValue(3);
            phase_ = 5;
            button("matchingSearch")->click();
        } else if (phase_ == 7 && button("matchingPin")->isEnabled()) {
            if (!selectLiteral(QStringLiteral("1")))
                return;
            phase_ = 8;
            button("matchingPin")->click();
        } else if (phase_ == 9 && !source_->isReadOnly()) {
            if (!selectLiteral(QStringLiteral("1")))
                return;
            auto cursor = source_->textCursor();
            cursor.insertText(QStringLiteral("9"));
            phase_ = 10;
            button("matchingSave")->click();
        } else if (phase_ == 11 && !source_->isReadOnly()) {
            source_->undo();
            if (!require(!source_->document()->isModified() &&
                             source_->toPlainText().contains(QStringLiteral("+ 1")),
                         QStringLiteral("Editor undo did not restore the pinned source")))
                return;
            phase_ = 12;
        } else if (phase_ == 12 && button("matchingRun")->isEnabled()) {
            phase_ = 13;
            button("matchingRun")->click();
        } else if (phase_ == 14 && button("matchingRun")->isEnabled()) {
            auto *history = dock_->findChild<QTableWidget *>(QStringLiteral("matchingHistory"));
            if (!require(history->rowCount() >= 4, QStringLiteral("Actual trial history was not populated")))
                return;
            phase_ = 15;
        } else if (phase_ == 15 && button("matchingCalibrate")->isEnabled()) {
            phase_ = 16;
            button("matchingCalibrate")->click();
        } else if (phase_ == 17 && !source_->isReadOnly()) {
            auto *files = dock_->findChild<QComboBox *>(QStringLiteral("matchingFile"));
            const int index = files->findText(QStringLiteral("types.h"));
            if (!require(index >= 0, QStringLiteral("Shared header is absent")))
                return;
            phase_ = 18;
            files->setCurrentIndex(index);
            QMetaObject::invokeMethod(files, "activated", Q_ARG(int, index));
        } else if (phase_ == 19 && button("matchingContext")->isEnabled()) {
            const int start = source_->toPlainText().indexOf(QStringLiteral("unsigned char"));
            auto cursor = source_->textCursor();
            cursor.setPosition(start);
            cursor.setPosition(start + 13, QTextCursor::KeepAnchor);
            source_->setTextCursor(cursor);
            phase_ = 20;
            button("matchingContext")->click();
        } else if (phase_ == 21 && button("matchingBindProject")->isEnabled()) {
            phase_ = 22;
            button("matchingBindProject")->click();
        } else if (phase_ == 23 && button("matchingPreparePatch")->isEnabled()) {
            phase_ = 24;
            button("matchingPreparePatch")->click();
        } else if (phase_ == 25 && button("matchingVerify")->isEnabled()) {
            phase_ = 26;
            button("matchingVerify")->click();
        } else if (phase_ == 27 && button("matchingApply")->isEnabled()) {
            if (config_.value("apply_project").toBool()) {
                phase_ = 28;
                button("matchingApply")->click();
            } else
                phase_ = 29;
        } else if (phase_ == 29 && button("matchingExport")->isEnabled()) {
            phase_ = 30;
            button("matchingExport")->click();
        } else if (phase_ == 30 && button("matchingExport")->isEnabled() &&
                   QFileInfo::exists(config_.value("bundle").toString())) {
            if (!inspectBundle())
                return;
            phase_ = 31;
        } else if (phase_ == 31 && button("matchingImport")->isEnabled()) {
            phase_ = 32;
            button("matchingImport")->click();
        } else if (phase_ == 34 && button("matchingRun")->isEnabled()) {
            if (!require(!button("matchingPreparePatch")->isEnabled(),
                         QStringLiteral("Imported project was automatically rebound")))
                return;
            auto *candidates = dock_->findChild<QComboBox *>(QStringLiteral("matchingCandidate"));
            int found = -1;
            for (int i = 0; i < candidates->count(); ++i)
                if (candidates->itemText(i).endsWith(QStringLiteral("Pin source selection")))
                    found = i;
            if (!require(found >= 0, QStringLiteral("Portable pinned candidate is absent")))
                return;
            phase_ = 35;
            candidates->setCurrentIndex(found);
            QMetaObject::invokeMethod(candidates, "activated", Q_ARG(int, found));
        } else if (phase_ == 36 && button("matchingRun")->isEnabled()) {
            phase_ = 37;
            button("matchingRun")->click();
        } else if (phase_ == 38 && button("matchingRun")->isEnabled()) {
            auto *history = dock_->findChild<QTableWidget *>(QStringLiteral("matchingHistory"));
            dock_->findChild<QTabWidget *>()->setCurrentIndex(1);
            if (!require(dock_->grab().save(config_.value("after_image").toString()),
                         QStringLiteral("Could not save history screenshot")))
                return;
            const QJsonObject report{{"passed", true},
                                     {"elapsed_ms", elapsed_.elapsed()},
                                     {"mismatch_rows", mismatch_rows_},
                                     {"search_compiler_invocations", 2},
                                     {"exact_object_recompiled", true},
                                     {"utf16_pin_correct", true},
                                     {"protected_edit_rejected", true},
                                     {"editor_undo_restored", true},
                                     {"history_rows", history->rowCount()},
                                     {"calibration", true},
                                     {"isolated_context_regression", true},
                                     {"project_verified", true},
                                     {"project_applied", config_.value("apply_project")},
                                     {"portable_private_inputs_excluded", true},
                                     {"portable_replay_exact", true},
                                     {"native_revision_unchanged", true},
                                     {"before_image", config_.value("before_image")},
                                     {"after_image", config_.value("after_image")}};
            const auto bytes = QJsonDocument(report).toJson(QJsonDocument::Indented);
            QSaveFile file(config_.value("report").toString());
            if (!require(file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size() &&
                             file.commit(),
                         QStringLiteral("Could not write UI gate report")))
                return;
            finished_ = true;
            timer_->stop();
            QTextStream(stdout) << bytes;
            QCoreApplication::exit(0);
        }
    }
    MatchingDock *dock_;
    QPlainTextEdit *source_ = nullptr;
    QTimer *timer_ = nullptr;
    QJsonObject config_;
    QElapsedTimer elapsed_;
    int phase_ = 0;
    int mismatch_rows_ = 0;
    qint64 pinned_ = 0;
    qint64 revision_ = 0;
    QSet<QString> private_inputs_;
    QPointer<QDialog> configured_dialog_;
    bool finished_ = false;
};
} // namespace

void runMatchingGate(MainWindow *window, const QString &path) { new MatchingGate(window, path); }
