#include "matching_dock.h"
#include "core_bridge.h"
#include "json_util.h"
#include "theme.h"

#include <QComboBox>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QLabel>
#include <QMap>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>

namespace {
QString verdict(const QJsonValue &value) {
    return value.isBool() ? (value.toBool() ? QStringLiteral("exact") : QStringLiteral("different"))
                          : QStringLiteral("unknown");
}
QString objectVerdict(const QJsonObject &trial) {
    return trial.value("candidate_digest").isNull()
               ? QStringLiteral("not built")
               : verdict(trial.value("diagnosis").toObject().value("exact_object_bytes"));
}
QString percent(const QJsonValue &value) {
    return value.isDouble() ? QString::number(value.toDouble(), 'f', 2) + QLatin1Char('%')
                            : QStringLiteral("unscored");
}
QString objectOffset(const QJsonValue &value) {
    return value.isDouble() ? QStringLiteral("0x%1").arg(value.toInteger(), 0, 16) : QString();
}
} // namespace

MatchingDock::MatchingDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Matching"), parent), bridge_(bridge) {
    setObjectName(QStringLiteral("matchingDock"));
    auto *body = new QWidget(this);
    auto *layout = new QVBoxLayout(body);
    auto row = [layout]() {
        auto *result = new QHBoxLayout();
        layout->addLayout(result);
        return result;
    };
    auto button = [this, body](QHBoxLayout *line, const QString &label, auto action) {
        auto *result = new QPushButton(label, body);
        line->addWidget(result);
        connect(result, &QPushButton::clicked, this, action);
        idle_controls_.append(result);
        return result;
    };
    auto *setup = new QWidget(body);
    setup->setObjectName(QStringLiteral("matchingSetupControls"));
    auto *setup_layout = new QVBoxLayout(setup);
    setup_layout->setContentsMargins(0, 0, 0, 0);
    auto *workspace_tools = new QHBoxLayout();
    auto *tuning = new QHBoxLayout();
    setup_layout->addLayout(workspace_tools);
    setup_layout->addLayout(tuning);
    setup->hide();
    auto *work = row();
    work->addWidget(new QLabel(QStringLiteral("Workspace"), body));
    workspaces_ = new QComboBox(body);
    workspaces_->setObjectName(QStringLiteral("matchingWorkspace"));
    workspaces_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    workspaces_->setMinimumContentsLength(18);
    work->addWidget(workspaces_, 1);
    button(workspace_tools, QStringLiteral("Refresh workspaces"), [this]() { refreshWorkspaces(); });
    button(workspace_tools, QStringLiteral("More workspaces"), [this]() {
        if (workspaces_->count())
            refreshWorkspaces(workspaces_->itemData(workspaces_->count() - 1).toLongLong());
    });
    button(work, QStringLiteral("New…"), &MatchingDock::createWorkspaceDialog)
        ->setObjectName(QStringLiteral("matchingNew"));
    button(workspace_tools, QStringLiteral("Import…"), &MatchingDock::importWorkspace)
        ->setObjectName(QStringLiteral("matchingImport"));
    button(workspace_tools, QStringLiteral("Export…"), &MatchingDock::exportWorkspace)
        ->setObjectName(QStringLiteral("matchingExport"));
    auto *candidate = work;
    candidate->addWidget(new QLabel(QStringLiteral("Candidate"), body));
    candidates_ = new QComboBox(body);
    candidates_->setObjectName(QStringLiteral("matchingCandidate"));
    candidates_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    candidates_->setMinimumContentsLength(12);
    candidate->addWidget(candidates_, 1);
    button(workspace_tools, QStringLiteral("More candidates"), [this]() {
        if (candidates_->count())
            refreshCandidates(candidates_->itemData(candidates_->count() - 1).toLongLong());
    });
    profiles_ = new QComboBox(body);
    profiles_->setObjectName(QStringLiteral("matchingProfile"));
    button(tuning, QStringLiteral("Add profile…"), &MatchingDock::addProfile);
    button(tuning, QStringLiteral("Calibrate…"), &MatchingDock::calibrate)
        ->setObjectName(QStringLiteral("matchingCalibrate"));
    button(tuning, QStringLiteral("Trial context…"), &MatchingDock::trialContext)
        ->setObjectName(QStringLiteral("matchingContext"));
    workspace_tools->addStretch();
    auto *setup_toggle = new QPushButton(QStringLiteral("Setup"), body);
    setup_toggle->setObjectName(QStringLiteral("matchingSetupToggle"));
    setup_toggle->setCheckable(true);
    setup_toggle->setToolTip(QStringLiteral("Workspace transfer, toolchain calibration and search limits"));
    work->addWidget(setup_toggle);
    connect(setup_toggle, &QPushButton::toggled, setup, &QWidget::setVisible);
    layout->addWidget(setup);
    auto *split = new QSplitter(Qt::Horizontal, body);
    split->setObjectName(QStringLiteral("matchingEditorSplit"));
    split->setChildrenCollapsible(false);
    auto *source_panel = new QWidget(split);
    auto *source_layout = new QVBoxLayout(source_panel);
    source_layout->setContentsMargins(0, 0, 0, 0);
    auto *editing = new QHBoxLayout();
    source_layout->addLayout(editing);
    files_ = new QComboBox(body);
    files_->setObjectName(QStringLiteral("matchingFile"));
    editing->addWidget(files_, 1);
    save_ = button(editing, QStringLiteral("Save"), [this]() { saveSource(); });
    save_->setObjectName(QStringLiteral("matchingSave"));
    save_->setToolTip(QStringLiteral("Create an immutable candidate. This does "
                                     "not write project source files."));
    discard_ = button(editing, QStringLiteral("Discard"), &MatchingDock::discardSource);
    discard_->setToolTip(QStringLiteral("Discard unsaved source edits"));
    auto *pin_actions = new QHBoxLayout();
    button(pin_actions, QStringLiteral("Pin selection"), [this]() {
        pinSelection();
    })->setObjectName(QStringLiteral("matchingPin"));
    button(pin_actions, QStringLiteral("Clear pins"), [this]() { pinSelection(true); });
    pins_ = new QLabel(body);
    pin_actions->addWidget(pins_, 1);
    auto *actions = row();
    actions->addWidget(new QLabel(QStringLiteral("Toolchain"), body));
    actions->addWidget(profiles_, 1);
    run_ = button(actions, QStringLiteral("Compile && compare"), [this]() {
        saveSource([this]() {
            executeOperation(QJsonObject{{"operation", "trial"},
                                         {"candidate", candidate_.value("id")},
                                         {"profile", profiles_->currentText()}});
        });
    });
    run_->setObjectName(QStringLiteral("matchingRun"));
    run_->setShortcut(QKeySequence(QStringLiteral("Ctrl+Return")));
    run_->setToolTip(QStringLiteral("Save a candidate and compile against the reference (Ctrl+Enter)"));
    search_ = button(actions, QStringLiteral("Search selection"), &MatchingDock::searchSelection);
    search_->setObjectName(QStringLiteral("matchingSearch"));
    button(tuning, QStringLiteral("Explicit alternatives…"), &MatchingDock::explicitSearch);
    tuning->addWidget(new QLabel(QStringLiteral("Compilation budget"), body));
    budget_ = new QSpinBox(body);
    budget_->setRange(1, 4096);
    budget_->setValue(12);
    tuning->addWidget(budget_);
    budget_->setObjectName(QStringLiteral("matchingBudget"));
    seconds_ = new QSpinBox(body);
    seconds_->setRange(1, 3600);
    seconds_->setValue(120);
    seconds_->setSuffix(QStringLiteral(" s"));
    tuning->addWidget(seconds_);
    cancel_ = button(actions, QStringLiteral("Cancel"), &MatchingDock::cancelJob);
    cancel_->setObjectName(QStringLiteral("matchingCancel"));
    source_ = new QPlainTextEdit(source_panel);
    source_->setObjectName(QStringLiteral("matchingSource"));
    source_->setFont(Theme::codeFont());
    source_->setLineWrapMode(QPlainTextEdit::NoWrap);
    source_layout->addWidget(source_, 1);
    source_layout->addLayout(pin_actions);
    auto *tabs = new QTabWidget(split);
    tabs_ = tabs;
    auto *evidence = new QWidget(tabs);
    auto *evidence_layout = new QVBoxLayout(evidence);
    summary_ = new QLabel(QStringLiteral("Compile a candidate to collect evidence."), evidence);
    summary_->setObjectName(QStringLiteral("matchingSummary"));
    summary_->setWordWrap(true);
    evidence_layout->addWidget(summary_);
    auto *address_note = new QLabel(
        QStringLiteral("Addresses below are object offsets, not ROM addresses. "
                       "Source lines without filenames are hints only."), evidence);
    address_note->setWordWrap(true);
    evidence_layout->addWidget(address_note);
    mismatches_ = new QTableWidget(0, 7, evidence);
    mismatches_->setObjectName(QStringLiteral("matchingMismatches"));
    mismatches_->setHorizontalHeaderLabels({"Reference offset", "Reference instruction", "Candidate offset",
                                            "Candidate instruction", "Category", "Source hint",
                                            "Testable hypothesis"});
    mismatches_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mismatches_->setSelectionBehavior(QAbstractItemView::SelectRows);
    mismatches_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    mismatches_->horizontalHeader()->setStretchLastSection(true);
    mismatches_->verticalHeader()->hide();
    evidence_layout->addWidget(mismatches_);
    tabs->addTab(evidence, QStringLiteral("Compare"));
    auto *history_page = new QWidget(tabs);
    auto *history_layout = new QVBoxLayout(history_page);
    auto *history_actions = new QHBoxLayout();
    history_layout->addLayout(history_actions);
    button(history_actions, QStringLiteral("Refresh history"), [this]() { refreshHistory(); });
    button(history_actions, QStringLiteral("More history"), [this]() {
        if (!trials_.isEmpty())
            refreshHistory(trials_.last().toObject().value("id").toInteger());
    });
    button(history_actions, QStringLiteral("Project check history"), [this]() { refreshChecks(); });
    button(history_actions, QStringLiteral("More project checks"), [this]() {
        if (!checks_.isEmpty())
            refreshChecks(checks_.last().toObject().value("id").toInteger());
    });
    history_ = new QTableWidget(0, 8, history_page);
    history_->setObjectName(QStringLiteral("matchingHistory"));
    history_->setHorizontalHeaderLabels({"Trial / candidate", "Profile", "Similarity", "Instructions",
                                         "Relocations", "Object", "Status / provenance", "Time"});
    history_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    history_->setSelectionBehavior(QAbstractItemView::SelectRows);
    history_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    history_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Stretch);
    history_->verticalHeader()->hide();
    history_layout->addWidget(history_);
    tabs->addTab(history_page, QStringLiteral("History"));
    auto *project_page = new QWidget(tabs);
    auto *project_layout = new QVBoxLayout(project_page);
    auto *project_actions = new QHBoxLayout();
    project_layout->addLayout(project_actions);
    button(project_actions, QStringLiteral("Bind real project…"), &MatchingDock::configureProject)
        ->setObjectName(QStringLiteral("matchingBindProject"));
    prepare_ = button(project_actions, QStringLiteral("Prepare source patch"), &MatchingDock::preparePatch);
    prepare_->setObjectName(QStringLiteral("matchingPreparePatch"));
    verify_ = button(project_actions, QStringLiteral("Verify build"), [this]() { verifyPatch(false); });
    apply_ = button(project_actions, QStringLiteral("Verify && apply…"), [this]() { verifyPatch(true); });
    verify_->setObjectName(QStringLiteral("matchingVerify"));
    apply_->setObjectName(QStringLiteral("matchingApply"));
    patch_text_ = new QPlainTextEdit(project_page);
    patch_text_->setReadOnly(true);
    patch_text_->setFont(source_->font());
    patch_text_->setLineWrapMode(QPlainTextEdit::NoWrap);
    patch_text_->setObjectName(QStringLiteral("matchingPatch"));
    project_layout->addWidget(patch_text_);
    tabs->addTab(project_page, QStringLiteral("Project patch"));
    details_ = new QPlainTextEdit(tabs);
    details_->setReadOnly(true);
    details_->setFont(source_->font());
    details_->setLineWrapMode(QPlainTextEdit::NoWrap);
    details_->setObjectName(QStringLiteral("matchingDetails"));
    tabs->addTab(details_, QStringLiteral("Diagnostics"));
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 1);
    split->setSizes({550, 550});
    layout->addWidget(split, 1);
    state_ = new QLabel(QStringLiteral("No matching workspace selected."), body);
    state_->setObjectName(QStringLiteral("matchingState"));
    state_->setWordWrap(true);
    layout->addWidget(state_);
    setWidget(body);
    idle_controls_ << workspaces_ << candidates_ << profiles_ << files_ << budget_ << seconds_;
    timer_ = new QTimer(this);
    timer_->setInterval(150);
    connect(timer_, &QTimer::timeout, this, &MatchingDock::pollJob);
    connect(workspaces_, &QComboBox::activated, this,
            [this](int i) { loadWorkspace(workspaces_->itemData(i).toLongLong()); });
    connect(candidates_, &QComboBox::activated, this,
            [this](int i) { loadCandidate(candidates_->itemData(i).toLongLong()); });
    connect(files_, &QComboBox::activated, this, [this]() { loadSource(); });
    connect(profiles_, &QComboBox::activated, this, [this]() {
        patch_ = {};
        patch_text_->clear();
        updateControls();
    });
    connect(source_->document(), &QTextDocument::modificationChanged, this, [this]() {
        patch_ = {};
        patch_text_->clear();
        renderPins();
        updateControls();
    });
    connect(history_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (row >= 0 && row < trials_.size()) {
            const auto trial = trials_[row].toObject();
            renderResult(trial);
            loadCandidate(trial.value("candidate").toInteger());
        }
    });
    updateControls();
}

void MatchingDock::fail(const QString &message) {
    state_->setText(message);
    state_->setStyleSheet(QStringLiteral("color:#e06c75"));
    emit statusRequested(message, true);
}

bool MatchingDock::canLeaveSource() {
    if (!source_->document()->isModified())
        return true;
    fail(QStringLiteral("Save this immutable candidate or discard the editor "
                        "change before switching context."));
    return false;
}

bool MatchingDock::confirmClose(QWidget *closing_window) {
    if (!source_->document()->isModified())
        return true;
    const auto choice = QMessageBox::question(
        closing_window, QStringLiteral("Unsaved matching candidate"),
        QStringLiteral("Save these source edits as an immutable candidate before closing? "
                       "This does not modify project files."),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Cancel);
    if (choice == QMessageBox::Discard) {
        discardSource();
        return true;
    }
    if (choice == QMessageBox::Save) {
        const QPointer<QWidget> owner(closing_window);
        saveSource([owner]() {
            if (owner)
                owner->close();
        });
    }
    return false;
}

bool MatchingDock::setProgram(const QString &program, const QString &binary) {
    if (program == program_) {
        binary_ = binary;
        updateControls();
        return true;
    }
    if (!canLeaveSource())
        return false;
    if (job_)
        cancelJob();
    if (busy_)
        emit jobFinished(job_label_, false, QStringLiteral("View changed; inspect recorded history."));
    ++generation_;
    ++candidate_generation_;
    timer_->stop();
    job_ = 0;
    busy_ = false;
    program_ = program;
    binary_ = binary;
    workspace_ = {};
    candidate_ = {};
    patch_ = {};
    trials_ = {};
    checks_ = {};
    workspaces_->clear();
    candidates_->clear();
    profiles_->clear();
    files_->clear();
    source_->clear();
    source_->document()->setModified(false);
    history_->setRowCount(0);
    mismatches_->setRowCount(0);
    patch_text_->clear();
    details_->clear();
    setWindowTitle(QStringLiteral("Matching — %1").arg(program));
    refreshWorkspaces();
    updateControls();
    return true;
}

void MatchingDock::workspaceRequest(QJsonObject operation, ValueCallback callback) {
    if (program_.isEmpty()) {
        fail(QStringLiteral("Open a program first."));
        return;
    }
    const auto generation = generation_;
    ++pending_;
    updateControls();
    bridge_->request(
        QJsonObject{{"method", "matching_workspace"}, {"program", program_}, {"operation", operation}},
        [this, guard = QPointer<MatchingDock>(this), generation,
         callback = std::move(callback)](const QJsonObject &response) {
            if (!guard)
                return;
            --pending_;
            updateControls();
            if (generation != generation_)
                return;
            QString error;
            if (!successful(response, &error)) {
                fail(error);
                return;
            }
            callback(response.value("result"));
            updateControls();
        });
}

void MatchingDock::refreshWorkspaces(qint64 after) {
    if (program_.isEmpty())
        return;
    workspaceRequest(QJsonObject{{"operation", "list"}, {"after", after}, {"limit", 128}},
                     [this, after](const QJsonValue &value) {
                         const auto selected = workspace_.value("id").toInteger();
                         if (!after)
                             workspaces_->clear();
                         for (const auto &entry : value.toArray()) {
                             const auto workspace = entry.toObject();
                             const auto spec = workspace.value("spec").toObject();
                             const auto id = workspace.value("id").toInteger();
                             if (workspaces_->findData(id) < 0)
                                 workspaces_->addItem(
                                     QStringLiteral("%1 · %2 (#%3)")
                                         .arg(spec.value("name").toString(), spec.value("symbol").toString())
                                         .arg(id),
                                     id);
                         }
                         const int found = workspaces_->findData(selected);
                         if (found >= 0)
                             workspaces_->setCurrentIndex(found);
                         if (workspace_.isEmpty() && workspaces_->count())
                             loadWorkspace(workspaces_->itemData(0).toLongLong());
                     });
}

void MatchingDock::createWorkspace(const QJsonObject &setup) {
    if (!canLeaveSource())
        return;
    workspaceRequest(QJsonObject{{"operation", "setup"}, {"setup", setup}}, [this](const QJsonValue &value) {
        const auto created = value.toObject();
        workspace_ = created.value("workspace").toObject();
        loadWorkspace(workspace_.value("id").toInteger());
    });
}

void MatchingDock::loadWorkspace(qint64 id) {
    if (!id)
        return;
    if (!canLeaveSource()) {
        workspaces_->setCurrentIndex(workspaces_->findData(workspace_.value("id").toInteger()));
        return;
    }
    ++generation_;
    ++candidate_generation_;
    workspace_ = {};
    candidate_ = {};
    patch_ = {};
    candidates_->clear();
    files_->clear();
    profiles_->clear();
    source_->clear();
    source_->document()->setModified(false);
    history_->setRowCount(0);
    trials_ = {};
    checks_ = {};
    patch_text_->clear();
    details_->clear();
    mismatches_->setRowCount(0);
    summary_->setText(QStringLiteral("Compile a candidate to collect evidence."));
    workspaceRequest(QJsonObject{{"operation", "show"}, {"workspace", id}}, [this](const QJsonValue &value) {
        workspace_ = value.toObject();
        const auto spec = workspace_.value("spec").toObject();
        const auto id = workspace_.value("id").toInteger();
        if (workspaces_->findData(id) < 0)
            workspaces_->addItem(QStringLiteral("%1 · %2 (#%3)")
                                     .arg(spec.value("name").toString(), spec.value("symbol").toString())
                                     .arg(id),
                                 id);
        workspaces_->setCurrentIndex(workspaces_->findData(id));
        for (const auto &profile : spec.value("profiles").toArray())
            profiles_->addItem(profile.toObject().value("name").toString());
        refreshCandidates();
        emit workspaceLoaded(workspace_.value("id").toInteger());
    });
}

void MatchingDock::refreshCandidates(qint64 after) {
    if (workspace_.isEmpty())
        return;
    workspaceRequest(
        QJsonObject{{"operation", "candidates"},
                    {"workspace", workspace_.value("id")},
                    {"after", after},
                    {"limit", 128}},
        [this, after](const QJsonValue &value) {
            if (!after)
                candidates_->clear();
            for (const auto &entry : value.toArray()) {
                const auto candidate = entry.toObject();
                const auto id = candidate.value("id").toInteger();
                if (candidates_->findData(id) < 0)
                    candidates_->addItem(QStringLiteral("#%1 %2").arg(id).arg(
                                             candidate.value("spec").toObject().value("label").toString()),
                                         id);
            }
            const auto id = candidate_.value("id").toInteger();
            if (id && candidates_->findData(id) < 0)
                candidates_->addItem(QStringLiteral("#%1 %2").arg(id).arg(
                                         candidate_.value("spec").toObject().value("label").toString()),
                                     id);
            const int found = candidates_->findData(id);
            if (found >= 0)
                candidates_->setCurrentIndex(found);
            if (candidate_.isEmpty() && candidates_->count())
                loadCandidate(candidates_->itemData(0).toLongLong());
        });
}

void MatchingDock::loadCandidate(qint64 id) {
    if (!id)
        return;
    if (!canLeaveSource()) {
        candidates_->setCurrentIndex(candidates_->findData(candidate_.value("id").toInteger()));
        return;
    }
    const auto ticket = ++candidate_generation_;
    workspaceRequest(QJsonObject{{"operation", "candidate"}, {"candidate", id}},
                     [this, ticket](const QJsonValue &value) {
                         if (ticket != candidate_generation_)
                             return;
                         const auto candidate = value.toObject();
                         if (candidate.value("workspace").toInteger() != workspace_.value("id").toInteger()) {
                             fail(QStringLiteral("Candidate belongs to another workspace."));
                             return;
                         }
                         acceptCandidate(candidate);
                         refreshHistory();
                     });
}

void MatchingDock::acceptCandidate(const QJsonObject &candidate) {
    candidate_ = candidate;
    patch_ = {};
    patch_text_->clear();
    const auto id = candidate.value("id").toInteger();
    if (candidates_->findData(id) < 0)
        candidates_->addItem(QStringLiteral("#%1 %2").arg(id).arg(
                                 candidate.value("spec").toObject().value("label").toString()),
                             id);
    candidates_->setCurrentIndex(candidates_->findData(id));
    const QString previous = files_->currentText();
    files_->clear();
    const auto files = candidate.value("spec").toObject().value("files").toObject();
    for (auto it = files.begin(); it != files.end(); ++it)
        files_->addItem(it.key());
    int index = files_->findText(previous);
    if (index < 0)
        index = files_->findText(workspace_.value("spec").toObject().value("source").toString());
    files_->setCurrentIndex(index < 0 ? 0 : index);
    loadSource();
}

void MatchingDock::loadSource() {
    if (!canLeaveSource()) {
        files_->setCurrentIndex(files_->findText(loaded_file_));
        return;
    }
    if (candidate_.isEmpty() || files_->currentText().isEmpty())
        return;
    const auto id = candidate_.value("id");
    const auto file = files_->currentText();
    loaded_file_.clear();
    loaded_source_.clear();
    source_->clear();
    source_->document()->setModified(false);
    workspaceRequest(QJsonObject{{"operation", "source"}, {"candidate", id}, {"file", file}},
                     [this, id, file](const QJsonValue &value) {
                         if (candidate_.value("id") != id || files_->currentText() != file)
                             return;
                         loaded_file_ = file;
                         loaded_source_ = value.toString();
                         source_->setPlainText(loaded_source_);
                         source_->document()->setModified(false);
                         renderPins();
                         state_->setStyleSheet(QString());
                         state_->setText(QStringLiteral("Candidate #%1 · %2. Saves fork history; only "
                                                        "Verify & apply writes project source.")
                                             .arg(id.toInteger())
                                             .arg(file));
                         emit candidateLoaded(id.toInteger());
                     });
}

void MatchingDock::saveSource(std::function<void()> continuation) {
    if (candidate_.isEmpty()) {
        fail(QStringLiteral("Select a candidate."));
        return;
    }
    if (!source_->document()->isModified()) {
        if (continuation)
            continuation();
        return;
    }
    const auto text = source_->toPlainText();
    workspaceRequest(QJsonObject{{"operation", "replace"},
                                 {"candidate", candidate_.value("id")},
                                 {"file", loaded_file_},
                                 {"source", text},
                                 {"label", QStringLiteral("Edit %1").arg(loaded_file_)}},
                     [this, text, continuation = std::move(continuation)](const QJsonValue &value) {
                         candidate_ = value.toObject();
                         loaded_source_ = text;
                         source_->document()->setModified(false);
                         const auto id = candidate_.value("id").toInteger();
                         candidates_->addItem(
                             QStringLiteral("#%1 %2").arg(id).arg(
                                 candidate_.value("spec").toObject().value("label").toString()),
                             id);
                         candidates_->setCurrentIndex(candidates_->count() - 1);
                         renderPins();
                         if (continuation)
                             continuation();
                     });
}

void MatchingDock::discardSource() {
    source_->setPlainText(loaded_source_);
    source_->document()->setModified(false);
    renderPins();
}

QJsonObject MatchingDock::selection() const {
    const auto cursor = source_->textCursor();
    const QString text = source_->toPlainText();
    return QJsonObject{{"file", loaded_file_},
                       {"start", text.left(cursor.selectionStart()).toUtf8().size()},
                       {"end", text.left(cursor.selectionEnd()).toUtf8().size()}};
}

void MatchingDock::pinSelection(bool clear) {
    const auto selected = selection();
    if (!clear && selected.value("start") == selected.value("end")) {
        fail(QStringLiteral("Select source bytes to protect."));
        return;
    }
    saveSource([this, clear, selected]() {
        auto pins = clear ? QJsonArray() : candidate_.value("spec").toObject().value("pins").toArray();
        if (!clear)
            pins.append(selected);
        workspaceRequest(QJsonObject{{"operation", "change"},
                                     {"change", QJsonObject{{"parent", candidate_.value("id")},
                                                            {"label", clear ? "Clear source pins"
                                                                            : "Pin source selection"},
                                                            {"edits", QJsonArray()},
                                                            {"pins", pins}}}},
                         [this](const QJsonValue &value) { acceptCandidate(value.toObject()); });
    });
}

void MatchingDock::searchSelection() {
    const auto selected = selection();
    if (selected.value("start") == selected.value("end")) {
        fail(QStringLiteral("Select an expression or builtin scalar type for bounded search. "
                            "Semantic equivalence is not assumed."));
        return;
    }
    saveSource([this, selected]() {
        executeOperation(QJsonObject{{"operation", "search"},
                                     {"request", QJsonObject{{"candidate", candidate_.value("id")},
                                                             {"profile", profiles_->currentText()},
                                                             {"max_compilations", budget_->value()},
                                                             {"alternatives", QJsonArray()},
                                                             {"expression", selected}}}});
    });
}

void MatchingDock::executeOperation(const QJsonObject &operation) {
    if (busy_) {
        fail(QStringLiteral("Wait for or cancel the active matching job."));
        return;
    }
    if (binary_.isEmpty()) {
        fail(QStringLiteral("Select the original imported binary for execution."));
        return;
    }
    busy_ = true;
    job_label_ = QStringLiteral("matching/%1").arg(operation.value("operation").toString());
    state_->setStyleSheet(QString());
    state_->setText(job_label_ + QStringLiteral(" · queued"));
    emit jobStarted(job_label_);
    updateControls();
    const auto generation = generation_;
    bridge_->request(QJsonObject{{"method", "job_submit"},
                                 {"op", "matching"},
                                 {"program", program_},
                                 {"binary", binary_},
                                 {"budget_ms", seconds_->value() * 1000},
                                 {"operation", operation}},
                     [this, guard = QPointer<MatchingDock>(this), generation](const QJsonObject &response) {
                         if (!guard)
                             return;
                         QString error;
                         const bool ok = successful(response, &error);
                         const auto id = response.value("result").toObject().value("job").toInteger();
                         if (generation != generation_) {
                             if (id)
                                 bridge_->request(QJsonObject{{"method", "job_cancel"}, {"job", id}},
                                                  [](const QJsonObject &) {});
                             return;
                         }
                         if (!ok) {
                             busy_ = false;
                             fail(error);
                             emit jobFinished(job_label_, false, error);
                             updateControls();
                             return;
                         }
                         job_ = id;
                         timer_->start();
                         pollJob();
                         updateControls();
                     });
}

void MatchingDock::pollJob() {
    if (!job_ || poll_pending_)
        return;
    poll_pending_ = true;
    const auto id = job_;
    bridge_->request(QJsonObject{{"method", "job_status"}, {"job", id}},
                     [this, guard = QPointer<MatchingDock>(this), id](const QJsonObject &response) {
                         if (!guard)
                             return;
                         poll_pending_ = false;
                         if (job_ != id)
                             return;
                         QString error;
                         if (!successful(response, &error)) {
                             timer_->stop();
                             job_ = 0;
                             busy_ = false;
                             fail(error);
                             emit jobFinished(job_label_, false, error);
                             updateControls();
                             return;
                         }
                         const auto status = response.value("result").toObject();
                         const auto state = status.value("state").toString();
                         state_->setText(job_label_ + QStringLiteral(" · ") + state);
                         if (state == "queued" || state == "running")
                             return;
                         timer_->stop();
                         job_ = 0;
                         busy_ = false;
                         const bool ok = state == "succeeded";
                         emit jobFinished(job_label_, ok, status.value("detail").toString());
                         if (!ok) {
                             fail(status.value("detail").toString());
                             updateControls();
                             return;
                         }
                         renderResult(status.value("result"));
                         refreshHistory();
                         const auto result = status.value("result").toObject();
                         if (result.contains("best_candidate") && result.value("best_candidate").isDouble())
                             loadCandidate(result.value("best_candidate").toInteger());
                         else
                             refreshCandidates();
                         updateControls();
                         emit operationFinished(status.value("result"));
                     });
}

void MatchingDock::cancelJob() {
    if (!job_)
        return;
    bridge_->request(QJsonObject{{"method", "job_cancel"}, {"job", job_}},
                     [this, guard = QPointer<MatchingDock>(this)](const QJsonObject &response) {
                         if (!guard)
                             return;
                         QString error;
                         if (!successful(response, &error))
                             fail(error);
                         else
                             state_->setText(QStringLiteral("Cancellation requested; waiting for "
                                                            "the running operation to settle."));
                     });
}

void MatchingDock::refreshHistory(qint64 after) {
    if (workspace_.isEmpty())
        return;
    workspaceRequest(
        QJsonObject{
            {"operation", "trials"}, {"workspace", workspace_.value("id")}, {"after", after}, {"limit", 128}},
        [this, after](const QJsonValue &value) {
            if (!after) {
                trials_ = {};
                history_->setRowCount(0);
            }
            for (const auto &entry : value.toArray()) {
                const auto trial = entry.toObject();
                const auto diagnosis = trial.value("diagnosis").toObject();
                trials_.append(trial);
                const int row = history_->rowCount();
                history_->insertRow(row);
                const QStringList cells{QStringLiteral("%1 / #%2")
                                            .arg(trial.value("id").toInteger())
                                            .arg(trial.value("candidate").toInteger()),
                                        trial.value("profile").toString(),
                                        percent(diagnosis.value("similarity")),
                                        verdict(diagnosis.value("exact_instructions")),
                                        verdict(diagnosis.value("exact_relocations")),
                                        objectVerdict(trial),
                                        trial.value("status").toString() +
                                            (trial.value("imported").toBool()
                                                 ? QStringLiteral(" · imported, unverified")
                                                 : QStringLiteral(" · local")),
                                        QStringLiteral("%1 ms").arg(trial.value("elapsed_ms").toInteger())};
                for (int column = 0; column < cells.size(); ++column)
                    history_->setItem(row, column, new QTableWidgetItem(cells[column]));
            }
        });
}

void MatchingDock::refreshChecks(qint64 after) {
    if (workspace_.isEmpty())
        return;
    workspaceRequest(
        QJsonObject{
            {"operation", "checks"}, {"workspace", workspace_.value("id")}, {"after", after}, {"limit", 128}},
        [this, after](const QJsonValue &value) {
            if (!after)
                checks_ = {};
            for (const auto &entry : value.toArray())
                checks_.append(entry);
            details_->setPlainText(QString::fromUtf8(QJsonDocument(checks_).toJson(QJsonDocument::Indented)));
            tabs_->setCurrentWidget(details_);
            state_->setText(QStringLiteral("%1 project checks loaded. More project "
                                           "checks continues the recorded history.")
                                .arg(checks_.size()));
        });
}

void MatchingDock::renderResult(const QJsonValue &result) {
    result_ = result;
    details_->setPlainText(QString::fromUtf8(
        result.isArray() ? QJsonDocument(result.toArray()).toJson(QJsonDocument::Indented)
                         : QJsonDocument(result.toObject()).toJson(QJsonDocument::Indented)));
    auto object = result.toObject();
    QJsonObject trial = object;
    if (object.contains("unified_diff")) {
        patch_ = object;
        patch_text_->setPlainText(object.value("unified_diff").toString());
    }
    if (object.contains("patch")) {
        patch_ = object.value("patch").toObject();
        patch_text_->setPlainText(patch_.value("unified_diff").toString());
    }
    const auto trials = object.value("trials").toArray();
    if (!trials.isEmpty()) {
        trial = trials.last().toObject();
        for (const auto &entry : trials)
            if (entry.toObject().value("candidate") == object.value("best_candidate"))
                trial = entry.toObject();
    }
    if (result.isArray() && !result.toArray().isEmpty())
        trial = result.toArray().first().toObject().value("trial").toObject();
    const auto diagnosis = trial.value("diagnosis").toObject();
    if (!diagnosis.isEmpty()) {
        tabs_->setCurrentIndex(0);
        summary_->setText(
            QStringLiteral("%1 · candidate #%2 · similarity %3 · instructions %4 · "
                           "relocations %5 · object %6 · project %7")
                .arg(diagnosis.value("symbol").toString())
                .arg(trial.value("candidate")
                         .toInteger(object.value("patch").toObject().value("candidate").toInteger()))
                .arg(percent(diagnosis.value("similarity")), verdict(diagnosis.value("exact_instructions")),
                     verdict(diagnosis.value("exact_relocations")), objectVerdict(trial),
                     verdict(object.value("project_exactness"))));
        mismatches_->setRowCount(0);
        for (const auto &value : diagnosis.value("mismatches").toArray()) {
            const auto mismatch = value.toObject();
            const int row = mismatches_->rowCount();
            if (row >= 512)
                break;
            mismatches_->insertRow(row);
            const auto line = mismatch.value("source_line");
            const QStringList cells{
                objectOffset(mismatch.value("target_address")),
                mismatch.value("target").toString(),
                objectOffset(mismatch.value("candidate_address")),
                mismatch.value("candidate").toString(),
                mismatch.value("category").toString(),
                line.isDouble() ? QStringLiteral("line %1 (file unknown)").arg(line.toInteger()) : QString(),
                mismatch.value("hypothesis").toString()};
            for (int column = 0; column < cells.size(); ++column) {
                auto *item = new QTableWidgetItem(cells[column]);
                item->setToolTip(cells[column]);
                mismatches_->setItem(row, column, item);
            }
        }
    }
    if (result.isArray()) {
        QStringList changes;
        for (const auto &entry : result.toArray()) {
            const auto comparison = entry.toObject();
            if (!comparison.contains("baseline") || !comparison.contains("trial"))
                continue;
            const auto before = comparison.value("baseline").toObject(),
                       after = comparison.value("trial").toObject();
            const auto delta = comparison.value("delta");
            changes << QStringLiteral("#%1: %2 → %3 (%4 points)")
                           .arg(before.value("candidate").toInteger())
                           .arg(percent(before.value("diagnosis").toObject().value("similarity")),
                                percent(after.value("diagnosis").toObject().value("similarity")),
                                delta.isDouble() ? QString::number(delta.toDouble(), 'f', 2)
                                                 : QStringLiteral("unknown"));
        }
        if (!changes.isEmpty())
            summary_->setText(QStringLiteral("Isolated context trials: %1. Mismatch "
                                             "table shows the first trial.")
                                  .arg(changes.join(QStringLiteral(" · "))));
    }
    if (object.contains("ranking")) {
        QStringList ranking;
        for (const auto &entry : object.value("ranking").toArray()) {
            const auto pair = entry.toArray();
            if (pair.size() == 2)
                ranking << pair[0].toString() + QStringLiteral(": ") + percent(pair[1]);
        }
        summary_->setText(QStringLiteral("Calibration evidence (ties retained): %1")
                              .arg(ranking.join(QStringLiteral(" · "))));
    }
    if (object.contains("applied"))
        state_->setText(object.value("applied").toBool()
                            ? QStringLiteral("Reviewed source patch applied. Build outputs "
                                             "were not copied into the project.")
                            : QStringLiteral("Verification recorded; no source applied. "
                                             "Inspect scope, build and regression evidence."));
    else if (object.contains("compiler_invocations"))
        state_->setText(QStringLiteral("%1 compilations in %2 ms; %3. Tested variants are not "
                                       "proofs of source-level equivalence.")
                            .arg(object.value("compiler_invocations").toInteger())
                            .arg(object.value("elapsed_ms").toInteger())
                            .arg(object.value("stopped").toString()));
    updateControls();
}

void MatchingDock::renderPins() {
    QList<QTextEdit::ExtraSelection> selections;
    const auto pins = candidate_.value("spec").toObject().value("pins").toArray();
    pins_->setText(
        QStringLiteral("%1 pins%2")
            .arg(pins.size())
            .arg(source_->document()->isModified() ? QStringLiteral(" · checked on save") : QString()));
    if (!source_->document()->isModified()) {
        const auto bytes = source_->toPlainText().toUtf8();
        QMap<qsizetype, int> offsets;
        for (const auto &value : pins) {
            const auto pin = value.toObject();
            if (pin.value("file").toString() == loaded_file_) {
                offsets.insert(pin.value("start").toInteger(), 0);
                offsets.insert(pin.value("end").toInteger(), 0);
            }
        }
        qsizetype byte = 0;
        int utf16 = 0;
        for (auto it = offsets.begin(); it != offsets.end(); ++it) {
            while (byte < it.key() && byte < bytes.size()) {
                const auto ch = static_cast<unsigned char>(bytes[byte++]);
                if ((ch & 0xc0) != 0x80)
                    utf16 += ch >= 0xf0 ? 2 : 1;
            }
            it.value() = utf16;
        }
        for (const auto &value : pins) {
            const auto pin = value.toObject();
            if (pin.value("file").toString() != loaded_file_)
                continue;
            QTextEdit::ExtraSelection selected;
            selected.cursor = QTextCursor(source_->document());
            selected.cursor.setPosition(offsets.value(pin.value("start").toInteger()));
            selected.cursor.setPosition(offsets.value(pin.value("end").toInteger()), QTextCursor::KeepAnchor);
            selected.format.setBackground(QColor(190, 145, 40, 65));
            selections.append(selected);
        }
    }
    source_->setExtraSelections(selections);
}

void MatchingDock::updateControls() {
    const bool idle = !busy_ && pending_ == 0;
    for (auto *control : idle_controls_)
        control->setEnabled(idle && !program_.isEmpty());
    const bool source_ready =
        !candidate_.isEmpty() && !loaded_file_.isEmpty() && loaded_file_ == files_->currentText();
    source_->setReadOnly(!idle || !source_ready);
    save_->setEnabled(idle && source_ready && source_->document()->isModified());
    discard_->setEnabled(save_->isEnabled());
    run_->setEnabled(idle && !candidate_.isEmpty() && !binary_.isEmpty());
    search_->setEnabled(run_->isEnabled());
    prepare_->setEnabled(
        run_->isEnabled() &&
        !workspace_.value("spec").toObject().value("project").toObject().value("root").toString().isEmpty());
    verify_->setEnabled(idle && !patch_.isEmpty() && !binary_.isEmpty());
    apply_->setEnabled(verify_->isEnabled());
    cancel_->setEnabled(busy_ && job_ != 0);
}
