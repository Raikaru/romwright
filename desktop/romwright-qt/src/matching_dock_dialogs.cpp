#include "matching_dock.h"
#include <QCheckBox>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QSpinBox>
#include <QStandardPaths>
#include <QVBoxLayout>
#include <optional>

namespace {
std::optional<QJsonValue> editJson(QWidget *parent, const QString &title, const QString &explanation,
                                   const QJsonValue &initial) {
    QDialog dialog(parent);
    dialog.setWindowTitle(title);
    dialog.resize(820, 540);
    auto *layout = new QVBoxLayout(&dialog);
    auto *label = new QLabel(explanation, &dialog);
    label->setWordWrap(true);
    layout->addWidget(label);
    auto *editor = new QPlainTextEdit(&dialog);
    editor->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    editor->setLineWrapMode(QPlainTextEdit::NoWrap);
    editor->setPlainText(QString::fromUtf8(initial.isArray()
                                               ? QJsonDocument(initial.toArray()).toJson(QJsonDocument::Indented)
                                               : QJsonDocument(initial.toObject()).toJson(QJsonDocument::Indented)));
    editor->setObjectName(QStringLiteral("matchingJsonEditor"));
    layout->addWidget(editor);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    QJsonValue result;
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(editor->toPlainText().toUtf8(), &error);
        if (error.error != QJsonParseError::NoError || document.isNull()) {
            QMessageBox::warning(&dialog, QStringLiteral("Invalid JSON"), error.errorString());
            return;
        }
        result = document.isArray() ? QJsonValue(document.array()) : QJsonValue(document.object());
        dialog.accept();
    });
    return dialog.exec() == QDialog::Accepted ? std::optional<QJsonValue>(result) : std::nullopt;
}
QLineEdit *pathField(QFormLayout *form, QDialog *dialog, const QString &label, bool directory = false) {
    auto *row = new QWidget(dialog);
    auto *layout = new QHBoxLayout(row);
    layout->setContentsMargins(0, 0, 0, 0);
    auto *edit = new QLineEdit(row);
    auto *browse = new QPushButton(QStringLiteral("Browse…"), row);
    layout->addWidget(edit, 1);
    layout->addWidget(browse);
    form->addRow(label, row);
    QObject::connect(browse, &QPushButton::clicked, dialog, [edit, dialog, label, directory]() {
        const auto path = directory ? QFileDialog::getExistingDirectory(dialog, label, edit->text())
                                    : QFileDialog::getOpenFileName(dialog, label, edit->text());
        if (!path.isEmpty())
            edit->setText(path);
    });
    return edit;
}
QJsonObject fileInput(const QString &path, bool public_bytes = false) {
    return QJsonObject{{"kind", "path"}, {"path", path}, {"redistributable", public_bytes}};
}
} // namespace

void MatchingDock::createWorkspaceDialog() {
    if (!canLeaveSource() || program_.isEmpty())
        return;
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("New matching workspace"));
    dialog.resize(820, 620);
    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout();
    layout->addLayout(form);
    auto *name = new QLineEdit(&dialog);
    form->addRow(QStringLiteral("Workspace name"), name);
    name->setObjectName(QStringLiteral("matchingSetupName"));
    auto *symbol = new QLineEdit(&dialog);
    symbol->setObjectName(QStringLiteral("matchingSetupSymbol"));
    form->addRow(QStringLiteral("Exact object/linker symbol"), symbol);
    auto *target = pathField(form, &dialog, QStringLiteral("Reference object"));
    target->setObjectName(QStringLiteral("matchingSetupTarget"));
    auto *source = pathField(form, &dialog, QStringLiteral("Candidate source"));
    source->setObjectName(QStringLiteral("matchingSetupSource"));
    auto *inputs = pathField(form, &dialog, QStringLiteral("Source/header root (optional)"), true);
    inputs->setObjectName(QStringLiteral("matchingSetupRoot"));
    auto *preset = new QComboBox(&dialog);
    preset->addItems({QStringLiteral("Clang / GCC"), QStringLiteral("MWCC through a user-owned wrapper")});
    form->addRow(QStringLiteral("Invocation shape"), preset);
    auto *compiler = pathField(form, &dialog, QStringLiteral("Compiler / wrapper"));
    compiler->setText(QStandardPaths::findExecutable(QStringLiteral("clang")));
    compiler->setObjectName(QStringLiteral("matchingSetupCompiler"));
    auto *wrapped = pathField(form, &dialog, QStringLiteral("Wrapped compiler executable"));
    auto *flags = new QPlainTextEdit(QStringLiteral("[\"-O2\"]"), &dialog);
    flags->setMaximumHeight(90);
    form->addRow(QStringLiteral("Compiler flags (JSON argv)"), flags);
    flags->setObjectName(QStringLiteral("matchingSetupFlags"));
    auto *public_source = new QCheckBox(QStringLiteral("I may redistribute this source file"), &dialog);
    form->addRow(public_source);
    auto *public_target = new QCheckBox(QStringLiteral("I may redistribute this reference object"), &dialog);
    form->addRow(public_target);
    auto *note = new QLabel(QStringLiteral("Headers stay private. Compiler/wrapper binaries are never bundled. The "
                                           "optional root captures C/C++ headers and sources with their relative "
                                           "paths; add other inputs through a workspace setup JSON when needed."),
                            &dialog);
    note->setWordWrap(true);
    layout->addWidget(note);
    auto *advanced = new QPushButton(QStringLiteral("Use complete setup JSON…"), &dialog);
    layout->addWidget(advanced);
    connect(preset, &QComboBox::currentIndexChanged, &dialog, [=](int index) {
        compiler->setText(QStandardPaths::findExecutable(index ? QStringLiteral("wibo") : QStringLiteral("clang")));
        flags->setPlainText(index ? QStringLiteral("[\"-nodefaults\",\"-proc\",\"gekko\",\"-O4,p\",\"-nosyspath\"]")
                                  : QStringLiteral("[\"-O2\"]"));
    });
    QJsonObject setup;
    bool advanced_mode = false;
    auto build_setup = [&]() -> bool {
        if (name->text().trimmed().isEmpty() || symbol->text().trimmed().isEmpty() || target->text().isEmpty() ||
            source->text().isEmpty() || compiler->text().isEmpty()) {
            QMessageBox::warning(
                &dialog, QStringLiteral("Missing input"),
                QStringLiteral("Name, linker symbol, source, reference object and compiler are required."));
            return false;
        }
        QJsonParseError error;
        const auto parsed = QJsonDocument::fromJson(flags->toPlainText().toUtf8(), &error);
        if (error.error != QJsonParseError::NoError || !parsed.isArray()) {
            QMessageBox::warning(&dialog, QStringLiteral("Invalid flags"),
                                 QStringLiteral("Use a JSON array of individual argument strings."));
            return false;
        }
        for (const auto &flag : parsed.array())
            if (!flag.isString()) {
                QMessageBox::warning(&dialog, QStringLiteral("Invalid flag"),
                                     QStringLiteral("Each argument must be a string."));
                return false;
            }
        if (preset->currentIndex() && wrapped->text().isEmpty()) {
            QMessageBox::warning(&dialog, QStringLiteral("Missing tool"),
                                 QStringLiteral("Choose the user-owned MWCC executable."));
            return false;
        }
        const QString source_path = QFileInfo(source->text()).absoluteFilePath();
        QString source_name = QFileInfo(source_path).fileName();
        QJsonObject files;
        if (!inputs->text().isEmpty()) {
            const QDir root(inputs->text());
            source_name = root.relativeFilePath(source_path);
            if (source_name.startsWith(QStringLiteral("../"))) {
                QMessageBox::warning(&dialog, QStringLiteral("Source outside root"),
                                     QStringLiteral("Choose a root containing the primary source."));
                return false;
            }
            QDirIterator iterator(root.absolutePath(),
                                  {"*.h", "*.hpp", "*.hxx", "*.hh", "*.inc", "*.c", "*.cc", "*.cpp", "*.cxx"},
                                  QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
            while (iterator.hasNext()) {
                const auto path = iterator.next();
                files.insert(root.relativeFilePath(path), fileInput(path));
                if (files.size() > 4096) {
                    QMessageBox::warning(
                        &dialog, QStringLiteral("Too many inputs"),
                        QStringLiteral("Choose a smaller root or an explicit setup JSON (maximum 4096 files)."));
                    return false;
                }
            }
        }
        files.insert(source_name, fileInput(source_path, public_source->isChecked()));
        QJsonArray arguments;
        QJsonArray version;
        QJsonObject tools;
        if (!wrapped->text().isEmpty()) {
            arguments.append("{tool:compiler}");
            version = QJsonArray{"{tool:compiler}", "-version"};
            tools.insert("compiler", QJsonObject{{"path", wrapped->text()}, {"digest", ""}});
        } else
            version = QJsonArray{"--version"};
        for (const auto &flag : parsed.array())
            arguments.append(flag);
        arguments.append("-c");
        arguments.append("{source}");
        arguments.append("-o");
        arguments.append("{output}");
        const QJsonObject profile{
            {"name", "default"},
            {"recipe",
             QJsonObject{{"compiler", compiler->text()}, {"arguments", QJsonArray()}, {"environment", QJsonObject()}}},
            {"compile_arguments", arguments},
            {"version_arguments", version},
            {"tools", tools}};
        setup = QJsonObject{{"name", name->text()},
                            {"symbol", symbol->text()},
                            {"source", source_name},
                            {"files", files},
                            {"target", fileInput(target->text(), public_target->isChecked())},
                            {"profiles", QJsonArray{profile}}};
        return true;
    };
    connect(advanced, &QPushButton::clicked, &dialog, [&]() {
        if (!build_setup())
            return;
        const auto edited = editJson(&dialog, QStringLiteral("Complete workspace setup"),
                                     QStringLiteral("Exact source/context inputs, named tool requirements and complete "
                                                    "argument arrays. Redistributable defaults to false."),
                                     setup);
        if (edited && edited->isObject()) {
            setup = edited->toObject();
            advanced_mode = true;
            dialog.accept();
        }
    });
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        if (build_setup())
            dialog.accept();
    });
    if (dialog.exec() == QDialog::Accepted) {
        Q_UNUSED(advanced_mode);
        createWorkspace(setup);
    }
}

void MatchingDock::addProfile() {
    if (workspace_.isEmpty())
        return;
    workspaceRequest(
        QJsonObject{{"operation", "show"}, {"workspace", workspace_.value("id")}}, [this](const QJsonValue &value) {
            workspace_ = value.toObject();
            auto spec = workspace_.value("spec").toObject();
            auto profiles = spec.value("profiles").toArray();
            if (profiles.isEmpty())
                return;
            auto profile = profiles.first().toObject();
            for (const auto &entry : profiles)
                if (entry.toObject().value("name").toString() == profiles_->currentText())
                    profile = entry.toObject();
            profile.insert("name", profile.value("name").toString() + QStringLiteral("-variant"));
            profile.remove("compiler_digest");
            auto tools = profile.value("tools").toObject();
            for (auto it = tools.begin(); it != tools.end(); ++it) {
                auto tool = it.value().toObject();
                tool.insert("digest", "");
                it.value() = tool;
            }
            profile.insert("tools", tools);
            const auto edited =
                editJson(this, QStringLiteral("Add immutable compiler profile"),
                         QStringLiteral("Use a new name. Existing profiles stay unchanged. Argument arrays preserve "
                                        "ordering; installed tools are pinned when saved."),
                         profile);
            if (!edited || !edited->isObject())
                return;
            profiles.append(edited->toObject());
            spec.insert("profiles", profiles);
            workspaceRequest(QJsonObject{{"operation", "update"},
                                         {"workspace", workspace_.value("id")},
                                         {"revision", workspace_.value("revision")},
                                         {"spec", spec}},
                             [this](const QJsonValue &updated) {
                                 workspace_ = updated.toObject();
                                 profiles_->clear();
                                 for (const auto &entry :
                                      workspace_.value("spec").toObject().value("profiles").toArray())
                                     profiles_->addItem(entry.toObject().value("name").toString());
                                 profiles_->setCurrentIndex(profiles_->count() - 1);
                             });
        });
}

void MatchingDock::calibrate() {
    saveSource([this]() {
        QJsonArray profiles;
        for (int i = 0; i < profiles_->count(); ++i)
            profiles.append(profiles_->itemText(i));
        const auto request =
            editJson(this, QStringLiteral("Calibrate actual toolchains"),
                     QStringLiteral("Choose known-reference candidate IDs and profile names. Every candidate/profile "
                                    "pair is compiled; equal scores remain tied, not identified as a unique compiler."),
                     QJsonObject{{"operation", "calibrate"},
                                 {"candidates", QJsonArray{candidate_.value("id")}},
                                 {"profiles", profiles},
                                 {"max_compilations", budget_->value()}});
        if (request && request->isObject())
            executeOperation(request->toObject());
    });
}

void MatchingDock::trialContext() {
    if (candidate_.isEmpty() || !canLeaveSource() || loaded_file_ != files_->currentText())
        return;
    const auto selected = selection();
    const auto request = editJson(
        this, QStringLiteral("Isolated shared-context trial"),
        QStringLiteral("Use candidate IDs sharing this context and UTF-8 byte edits. Each candidate gets a private "
                       "fork and a real before/after build. No program types or global facts are published."),
        QJsonObject{
            {"operation", "context"},
            {"request", QJsonObject{{"candidates", QJsonArray{candidate_.value("id")}},
                                    {"profile", profiles_->currentText()},
                                    {"max_compilations", budget_->value()},
                                    {"edits", QJsonArray{QJsonObject{
                                                  {"file", loaded_file_},
                                                  {"start", selected.value("start")},
                                                  {"end", selected.value("end")},
                                                  {"replacement", source_->textCursor().selectedText().replace(
                                                                      QChar::ParagraphSeparator, QLatin1Char('\n'))},
                                                  {"reason", "Trial a shared-context change"}}}}}}});
    if (request && request->isObject())
        executeOperation(request->toObject());
}

void MatchingDock::explicitSearch() {
    saveSource([this]() {
        const auto selected = selection();
        const auto request = editJson(
            this, QStringLiteral("Bounded explicit candidate search"),
            QStringLiteral("Each alternative is a separate array of UTF-8 source edits against the same immutable "
                           "parent. Pins are enforced. Include the baseline in the compilation budget."),
            QJsonObject{{"operation", "search"},
                        {"request", QJsonObject{{"candidate", candidate_.value("id")},
                                                {"profile", profiles_->currentText()},
                                                {"max_compilations", budget_->value()},
                                                {"expression", QJsonValue::Null},
                                                {"alternatives",
                                                 QJsonArray{QJsonArray{QJsonObject{
                                                     {"file", loaded_file_},
                                                     {"start", selected.value("start")},
                                                     {"end", selected.value("end")},
                                                     {"replacement", source_->textCursor().selectedText().replace(
                                                                         QChar::ParagraphSeparator, QLatin1Char('\n'))},
                                                     {"reason", "Test this explicit alternative"}}}}}}}});
        if (request && request->isObject())
            executeOperation(request->toObject());
    });
}

void MatchingDock::configureProject() {
    if (workspace_.isEmpty() || !canLeaveSource())
        return;
    workspaceRequest(
        QJsonObject{{"operation", "show"}, {"workspace", workspace_.value("id")}}, [this](const QJsonValue &value) {
            workspace_ = value.toObject();
            auto spec = workspace_.value("spec").toObject();
            auto binding = spec.value("project").toObject();
            if (binding.isEmpty() || binding.value("root").isNull()) {
                const auto root = QFileDialog::getExistingDirectory(this, QStringLiteral("Real project build root"));
                if (root.isEmpty())
                    return;
                bool ok = false;
                const auto output =
                    QInputDialog::getText(this, QStringLiteral("Fresh build output"),
                                          QStringLiteral("Project-relative object output containing this function:"),
                                          QLineEdit::Normal, QString(), &ok);
                if (!ok || output.isEmpty())
                    return;
                binding = QJsonObject{{"root", root},
                                      {"sources", QJsonObject{{spec.value("source").toString(), spec.value("source")}}},
                                      {"build", QJsonObject{{"executable", "ninja"},
                                                            {"arguments", QJsonArray{output}},
                                                            {"environment", QJsonObject()}}},
                                      {"objects", QJsonObject{{spec.value("symbol").toString(), output}}},
                                      {"linked_output", QJsonValue::Null},
                                      {"generated", QJsonArray{".ninja_log", ".ninja_deps"}}};
            }
            const auto edited =
                editJson(this, QStringLiteral("Bind a reviewable source patch"),
                         QStringLiteral("Map workspace source/header files to real project paths. Name the actual "
                                        "build command and fresh outputs. objects authorizes individual function/data "
                                        "symbols, including reported anonymous-data ranges. generated never hides "
                                        "object changes. Optional linked_output is compared with the imported binary."),
                         binding);
            if (!edited || !edited->isObject())
                return;
            spec.insert("project", edited->toObject());
            workspaceRequest(QJsonObject{{"operation", "update"},
                                         {"workspace", workspace_.value("id")},
                                         {"revision", workspace_.value("revision")},
                                         {"spec", spec}},
                             [this](const QJsonValue &updated) {
                                 workspace_ = updated.toObject();
                                 patch_ = {};
                                 patch_text_->clear();
                             });
        });
}

void MatchingDock::preparePatch() {
    saveSource([this]() {
        executeOperation(QJsonObject{{"operation", "prepare_patch"},
                                     {"candidate", candidate_.value("id")},
                                     {"profile", profiles_->currentText()}});
    });
}

void MatchingDock::verifyPatch(bool apply) {
    if (patch_.isEmpty())
        return;
    if (apply &&
        QMessageBox::question(
            this, QStringLiteral("Verify and apply reviewed source"),
            QStringLiteral(
                "Rebuild the baseline and candidate in isolation, check regressions and scope, then apply only the "
                "reviewed source patch to:\n%1\n\nBuild outputs are not copied back. Review the complete diff first.")
                .arg(workspace_.value("spec").toObject().value("project").toObject().value("root").toString()),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;
    executeOperation(QJsonObject{{"operation", "verify_patch"}, {"patch", patch_}, {"apply", apply}});
}

void MatchingDock::exportWorkspace() {
    if (workspace_.isEmpty())
        return;
    const auto path = QFileDialog::getSaveFileName(this, QStringLiteral("Export portable matching workspace"),
                                                   QString(), QStringLiteral("JSON (*.json)"));
    if (path.isEmpty())
        return;
    workspaceRequest(
        QJsonObject{{"operation", "export"}, {"workspace", workspace_.value("id")}},
        [this, path](const QJsonValue &value) {
            QSaveFile file(path);
            const auto bytes = QJsonDocument(value.toObject()).toJson(QJsonDocument::Indented);
            if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit()) {
                fail(QStringLiteral("Could not write workspace: %1").arg(file.errorString()));
                return;
            }
            emit statusRequested(
                QStringLiteral("Workspace exported; private inputs and proprietary tool bytes remain excluded."),
                false);
        });
}

void MatchingDock::importWorkspace() {
    if (!canLeaveSource())
        return;
    const auto path = QFileDialog::getOpenFileName(this, QStringLiteral("Import portable workspace"), QString(),
                                                   QStringLiteral("JSON (*.json)"));
    if (path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 64 * 1024 * 1024) {
        fail(QStringLiteral("Workspace must be a readable JSON file of at most 64 MiB."));
        return;
    }
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(file.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) {
        fail(QStringLiteral("Invalid workspace JSON: %1").arg(error.errorString()));
        return;
    }
    const auto bundle = document.object();
    const auto artifacts = bundle.value("artifacts").toObject();
    const auto spec = bundle.value("workspace").toObject();
    QSet<QString> missing;
    auto require = [&](const QJsonObject &input) {
        const auto digest = input.value("digest").toString();
        if (!digest.isEmpty() && !artifacts.contains(digest))
            missing.insert(digest);
    };
    require(spec.value("target").toObject());
    auto require_files = [&](const QJsonObject &files) {
        for (auto it = files.begin(); it != files.end(); ++it)
            require(it.value().toObject());
    };
    require_files(spec.value("files").toObject());
    for (const auto &candidate : bundle.value("candidates").toArray())
        require_files(candidate.toObject().value("spec").toObject().value("files").toObject());
    QJsonObject private_files;
    while (!missing.isEmpty()) {
        const auto paths = QFileDialog::getOpenFileNames(
            this, QStringLiteral("Select user-owned private inputs (%1 digests missing)").arg(missing.size()));
        if (paths.isEmpty())
            return;
        for (const auto &input_path : paths) {
            QFile input(input_path);
            if (!input.open(QIODevice::ReadOnly) || input.size() > 64 * 1024 * 1024)
                continue;
            QCryptographicHash hash(QCryptographicHash::Sha256);
            if (!hash.addData(&input))
                continue;
            const auto digest = QString::fromLatin1(hash.result().toHex());
            if (missing.remove(digest))
                private_files.insert(digest, input_path);
        }
    }
    const auto bindings =
        editJson(this, QStringLiteral("Local import bindings"),
                 QStringLiteral("Map profile names to installed compiler/wrapper paths and declared tool names to "
                                "local paths when needed. Imported results are unverified until rerun. Leave "
                                "project_root null unless explicitly rebinding a real source tree."),
                 QJsonObject{{"private_files", private_files},
                             {"compilers", QJsonObject()},
                             {"tools", QJsonObject()},
                             {"objdiff", QJsonValue::Null},
                             {"project_root", QJsonValue::Null}});
    if (!bindings || !bindings->isObject())
        return;
    auto request = bindings->toObject();
    request.insert("bundle", bundle);
    workspaceRequest(QJsonObject{{"operation", "import"}, {"request", request}}, [this](const QJsonValue &value) {
        loadWorkspace(value.toObject().value("workspace").toObject().value("id").toInteger());
    });
}
