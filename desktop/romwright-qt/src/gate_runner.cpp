#include "gate_runner.h"

#include "core_bridge.h"
#include "decompiler_dock.h"
#include "decompiler_view.h"
#include "function_table_model.h"
#include "functions_dock.h"
#include "graph_canvas.h"
#include "graph_dock.h"
#include "json_util.h"
#include "listing_canvas.h"
#include "main_window.h"
#include "navigation_controller.h"
#include "xrefs_dock.h"

#include <QApplication>
#include <QAction>
#include <QClipboard>
#include <QKeyEvent>
#include <QMimeData>
#include <QMouseEvent>
#include <QScopeGuard>
#include <QTextBlock>
#include <memory>
#include <QCoreApplication>
#include <QDir>
#include <QJsonArray>
#include <QProcessEnvironment>
#include <QJsonDocument>
#include <QTableView>
#include <QTextStream>
#include <QLabel>
#include <QTimer>

GateRunner::GateRunner(MainWindow *window, CoreBridge *bridge, QObject *parent)
    : QObject(parent), window_(window), bridge_(bridge) {}

void GateRunner::run(bool store_only) {
    if (active_) {
        return;
    }
    active_ = true;
    store_only_ = store_only;
    stage_ = Stage::Inactive;
    window_->functionsDock()->filterTimer()->setInterval(0);
    metrics_ = QJsonObject();
    address_.clear();
    if (!sourceInteractions()) {
        finish(false, QStringLiteral("Source interaction gate failed"));
        return;
    }
    if (!graphInteractions()) {
        finish(false, QStringLiteral("Graph interaction gate failed"));
        return;
    }

    const QString b = window_->binary();
    const QString p = window_->program();
    if (b.isEmpty() || p.isEmpty()) {
        finish(false, QStringLiteral("gate requires --binary and --name"));
        return;
    }

    // `ROMWRIGHT_UI_LOAD_ONLY` exercises the path an analyst actually takes
    // on a large image: map it, show the loader's answer, and let the
    // window analyse in the background. Without it the gate imports
    // everything up front and the provisional state never exists.
    const bool load_only = qEnvironmentVariableIsSet("ROMWRIGHT_UI_LOAD_ONLY");
    bridge_->request(
        QJsonObject{{"method", "import_native"},
                    {"binary", b},
                    {"name", p},
                    {"analyse", !load_only}},
        [this, p](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            window_->navigation()->setProgram(p);
            stage_ = Stage::LoadingList;
            timer_.start();
            window_->functionsDock()->setProgram(p);
        });
}

void GateRunner::modelRefreshed() {
    if (!active_) {
        return;
    }
    const Stage current_stage = stage_;
    if (current_stage != Stage::LoadingList && current_stage != Stage::Filtering &&
        current_stage != Stage::ClearingFilter) {
        return;
    }
    QTimer::singleShot(0, this, [this, current_stage]() {
        if (!active_ || stage_ != current_stage) {
            return;
        }
        if (window_->functionsDock()->tableView() != nullptr) {
            window_->functionsDock()->tableView()->viewport()->repaint();
        }
        const double elapsed_ms = static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0;
        if (current_stage == Stage::LoadingList) {
            metrics_.insert(QStringLiteral("ui.list.load_ms"), elapsed_ms);
            stage_ = Stage::Filtering;
            timer_.restart();
            window_->functionsDock()->filterTimer()->stop();
            window_->functionsDock()->setFilter(QStringLiteral("FUN_"));
        } else if (current_stage == Stage::Filtering) {
            metrics_.insert(QStringLiteral("ui.list.filter_ms"), elapsed_ms);
            stage_ = Stage::ClearingFilter;
            window_->functionsDock()->filterTimer()->stop();
            window_->functionsDock()->setFilter(QString());
        } else if (store_only_) {
            // The store-facing workflow is complete: import, list, filter.
            recordInstallFacts();
            finish(true);
        } else {
            startLargestFunction();
        }
    });
}

/// Records what this run can see about its own installation.
///
/// `ui.install.prefix_ok` is false when the executable sits in a build tree,
/// which is how a "packaged" gate can pass without a package. It looks for
/// CMake's own build artifacts beside the executable and one directory up.
///
/// `ui.install.store_only_ok` says the store-facing workflow completed with no
/// `ROMWRIGHT_*` variable set at all, so nothing outside the installed binary
/// configured this run. Neither fact is read from an environment variable that
/// asserts the answer.
void GateRunner::recordInstallFacts() {
    const QDir directory(QCoreApplication::applicationDirPath());
    const bool build_tree = directory.exists(QStringLiteral("CMakeCache.txt")) ||
                            directory.exists(QStringLiteral("CMakeFiles")) ||
                            QDir(directory.filePath(QStringLiteral(".."))) 
                                .exists(QStringLiteral("CMakeCache.txt"));
    metrics_.insert(QStringLiteral("ui.install.prefix_ok"), !build_tree);

    bool configured = false;
    const QStringList names = QProcessEnvironment::systemEnvironment().keys();
    for (const QString &name : names) {
        if (name.startsWith(QStringLiteral("ROMWRIGHT_")) &&
            name != QStringLiteral("ROMWRIGHT_UI_GATE")) {
            configured = true;
            break;
        }
    }
    metrics_.insert(QStringLiteral("ui.install.store_only_ok"), !configured);
}

bool GateRunner::sourceInteractions() {
    DecompilerView view;
    view.resize(800, 400);
    view.show();
    auto saved = std::make_unique<QMimeData>();
    auto *clipboard = QApplication::clipboard();
    if (const auto *mime = clipboard->mimeData())
        for (const auto &format : mime->formats()) saved->setData(format, mime->data(format));
    auto restore = qScopeGuard([&] { clipboard->setMimeData(saved.release()); });
    QVector<TokenView> tokens;
    auto add = [&](const QString &text, const QString &kind, const QString &address = QString(),
                   const QString &target = QString(), const QStringList &parameters = QStringList()) {
        tokens.append(TokenView{text, kind, address, 0, target, parameters});
    };
    add("int ", "Type"); add("sample", "FuncName", "0x10", "0x10");
    add("() {", "Syntax"); add("", "Break"); tokens.last().indent = 4;
    add("use", "FuncName", "0x14", "0x20", {"int count"}); add("(", "Syntax");
    add("42", "Constant", "0x14"); add("); /* } */", "Syntax");
    add("", "Break"); add("}", "Syntax"); add("", "Break");
    view.setTokens(TokenView::withArgumentHints(tokens));
    const QString original = "int sample() {\n    use(42); /* } */\n}\n";
    view.selectAll(); view.copy();
    if (clipboard->text() != original) return false;
    QTextCursor cursor(view.document());
    cursor.setPosition(view.toPlainText().indexOf("42"));
    view.setTextCursor(cursor);
    QKeyEvent select(QEvent::KeyPress, Qt::Key_Right, Qt::ShiftModifier);
    QApplication::sendEvent(&view, &select);
    QApplication::sendEvent(&view, &select);
    view.copy();
    if (clipboard->text() != "42") return false;
    view.setAddress("0x10");
    if (view.textCursor().selectedText() != "42") return false;
    QString followed, renamed;
    connect(&view, &DecompilerView::functionFollowRequested, &view,
            [&](const QString &address, bool) { followed = address; });
    connect(&view, &DecompilerView::renameRequested, &view,
            [&](const QString &address, const QString &) { renamed = address; });
    cursor.setPosition(view.toPlainText().indexOf("use"));
    cursor.select(QTextCursor::WordUnderCursor);
    view.setTextCursor(cursor);
    QKeyEvent follow(QEvent::KeyPress, Qt::Key_Return, Qt::ControlModifier);
    QApplication::sendEvent(&view, &follow);
    QKeyEvent rename(QEvent::KeyPress, Qt::Key_F2, Qt::NoModifier);
    QApplication::sendEvent(&view, &rename);
    if (followed != "0x20" || renamed != "0x20") return false;
    cursor.movePosition(QTextCursor::Start);
    view.setTextCursor(cursor);
    view.findChild<QAction *>("sourceFoldBlock")->trigger();
    if (view.document()->findBlockByNumber(1).isVisible()) return false;
    view.setAddress("0x14");
    if (!view.document()->findBlockByNumber(1).isVisible() || view.currentAddress() != "0x14") return false;
    view.findChild<QAction *>("sourceArgumentHints")->trigger();
    if (view.toPlainText() != original) return false;
    const auto before = view.toPlainText();
    QKeyEvent type(QEvent::KeyPress, Qt::Key_X, Qt::NoModifier, "x");
    QApplication::sendEvent(&view, &type);
    if (view.toPlainText() != before) return false;
    metrics_.insert("ui.source.selection_copy", true);
    metrics_.insert("ui.source.hints_excluded_from_copy", true);
    metrics_.insert("ui.source.follow_rename", true);
    metrics_.insert("ui.source.fold_reverse_sync", true);
    metrics_.insert("ui.source.read_only", true);
    return true;
}

bool GateRunner::graphInteractions() {
    GraphCanvas view;
    view.resize(700, 260);
    const QVector<GraphCanvas::Node> nodes = {
        {"a", "0x10", 1, {0, 0}}, {"b", "0x10", 1, {240, 0}}, {"empty", {}, 0, {480, 0}}};
    view.setGraph(nodes, {});
    view.show();
    const QImage without_loop = view.grab().toImage();
    if (!view.selectedNodeId().isEmpty()) return false;
    QStringList selected, navigated;
    connect(&view, &GraphCanvas::nodeSelected, &view,
            [&](const QString &id) { selected.append(id); });
    connect(&view, &GraphCanvas::addressSelected, &view, [&](const QString &address, bool) {
        navigated.append(address);
        view.setAddress(address);  // Cross-dock echo must not erase block identity.
    });
    auto click = [&](qreal x) {
        const QPointF position(x, 130);
        QMouseEvent press(QEvent::MouseButtonPress, position, view.mapToGlobal(position.toPoint()),
                          Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
        QMouseEvent release(QEvent::MouseButtonRelease, position, view.mapToGlobal(position.toPoint()),
                            Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
        QApplication::sendEvent(&view, &press);
        QApplication::sendEvent(&view, &release);
    };
    click(110);
    if (view.selectedNodeId() != "a") return false;
    click(350);
    if (view.selectedNodeId() != "b") return false;
    click(590);
    if (view.selectedNodeId() != "empty" || selected != QStringList{"a", "b", "empty"}
        || navigated != QStringList{"0x10", "0x10"}) return false;
    view.setGraph(nodes, {{"a", "a", "true"}});
    if (!view.selectedNodeId().isEmpty()) return false;
    // Other nodes enclose this loop's bounds, keeping the viewport identical.
    // Its addition must change the rendered image, not just the model.
    if (view.grab().toImage() == without_loop) return false;
    metrics_.insert("ui.graph.distinct_block_selection", true);
    metrics_.insert("ui.graph.empty_block_selection", true);
    metrics_.insert("ui.graph.selection_reset", true);
    metrics_.insert("ui.graph.self_loop_visible", true);
    return true;
}

void GateRunner::startLargestFunction() {
    stage_ = Stage::Inactive;
    bridge_->request(
        QJsonObject{{"method", "functions_page"},
                    {"program", window_->program()},
                    {"offset", 0},
                    {"limit", 1},
                    {"sort", "size:desc"}},
        [this](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            const QJsonArray rows = res.value("result").toObject().value("rows").toArray();
            if (rows.isEmpty()) {
                finish(false, QStringLiteral("gate found no functions"));
                return;
            }
            address_ = addressText(rows.first().toObject().value("entry"));
            if (address_.isEmpty() || address_ == QStringLiteral("?")) {
                finish(false, QStringLiteral("gate found invalid address"));
                return;
            }
            startDecompile(address_);
        });
}

void GateRunner::startDecompile(const QString &addr) {
    bridge_->request(
        QJsonObject{{"method", "decompile_doc"},
                    {"binary", window_->binary()},
                    {"program", window_->program()},
                    {"address", addr}},
        [this](const QJsonObject &res) {
            QString err;
            if (!successful(res, &err)) {
                finish(false, err);
                return;
            }
            const QJsonObject result = res.value("result").toObject();
            // The graph ships with the document: laying it out must not
            // pay a second worker round-trip through `function_bb_graph`
            // (that re-decompiles the function, which is what the timer
            // was measuring -- ~1.6 s on the 1865-block function).
            const QJsonObject graph = result.value("graph").toObject();
            QVector<TokenView> tokens = TokenView::fromDocument(result);
            bridge_->request(
                QJsonObject{{"method", "listing"},
                            {"binary", window_->binary()},
                            {"start", address_},
                            {"count", 128}},
                [this, tokens = std::move(tokens), graph](const QJsonObject &l_res) mutable {
                    QVector<ListingRowView> views;
                    if (successful(l_res)) {
                        for (const QJsonValue &row : l_res.value("result").toObject().value("rows").toArray()) {
                            views.append(ListingRowView::fromJson(row.toObject()));
                        }
                    }
                    window_->listingCanvas()->setWindow(views);
                    window_->decompilerDock()->view()->setTokens(tokens);
                    timer_.start();
                    window_->decompilerDock()->view()->setAddress(address_);
                    window_->listingCanvas()->setAddress(address_);
                    window_->decompilerDock()->view()->repaint();
                    window_->listingCanvas()->repaint();
                    metrics_.insert(QStringLiteral("ui.sync_ms"),
                                    static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0);
                    startGraph(graph);
                });
        });
}
void GateRunner::startGraph(const QJsonObject &graph) {
    timer_.start();
    const QJsonObject result = graph;
    {
        QVector<GraphCanvas::Node> nodes;
        QVector<GraphCanvas::Edge> edges;
        for (const QJsonValue &v : result.value("nodes").toArray()) {
            const QJsonObject row = v.toObject();
            GraphCanvas::Node n;
            n.address = row.value("address").toString();
            n.id = row.value("id").toString();
            n.operations = row.value("operations").toVariant().toULongLong();
            n.pos = QPointF(row.value("x").toVariant().toDouble(),
                            row.value("y").toVariant().toDouble());
            nodes.append(n);
        }
        for (const QJsonValue &v : result.value("edges").toArray()) {
            const QJsonObject row = v.toObject();
            GraphCanvas::Edge e;
            e.from = row.value("from").toString();
            e.to = row.value("to").toString();
            e.kind = row.value("kind").toString();
            edges.append(e);
        }
        metrics_.insert(QStringLiteral("ui.graph.layout_ms"),
                        static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0);
        timer_.start();
        window_->graphDock()->canvas()->setGraph(nodes, edges);
        window_->graphDock()->canvas()->setAddress(address_);
        window_->graphDock()->canvas()->repaint();
        metrics_.insert(QStringLiteral("ui.graph.paint_ms"),
                        static_cast<double>(timer_.nsecsElapsed()) / 1'000'000.0);
        startXrefs();
    }
}

void GateRunner::startXrefs() {
    // The dock fills asynchronously, so the metrics are read once both
    // requests have answered -- what the table holds, not what was sent.
    auto *dock = window_->xrefsDock();
    connect(dock, &XrefsDock::loadFinished, this, [this, dock]() {
        metrics_.insert(QStringLiteral("ui.xrefs.rows"), dock->renderedRows());
        metrics_.insert(QStringLiteral("ui.xrefs.unexplained"), dock->unexplainedRows());
        // The address the window actually navigated to, so a checker compares
        // the service's answer for the same address instead of guessing it.
        metrics_.insert(QStringLiteral("ui.xrefs.address"),
                        static_cast<double>(address_.toULongLong(nullptr, 16)));
        startFilteredXrefs();
    }, Qt::SingleShotConnection);
    dock->loadXrefs(window_->program(), address_);
}

void GateRunner::startFilteredXrefs() {
    // The same window, asked for one kind of evidence: what the selector
    // produces is measured, not the request that was sent.
    auto *dock = window_->xrefsDock();
    connect(dock, &XrefsDock::loadFinished, this, [this, dock]() {
        metrics_.insert(QStringLiteral("ui.xrefs.declared_rows"), dock->renderedRows());
        startProgramSwitch();
    }, Qt::SingleShotConnection);
    dock->setEvidence(QStringLiteral("declared"));
}

void GateRunner::startProgramSwitch() {
    // A project holds several images. Listing them and switching to the last
    // one is measured on the list the window then holds, not on the request.
    connect(window_, &MainWindow::programsListed, this, [this](int count) {
        metrics_.insert(QStringLiteral("ui.programs"), count);
        if (count <= 0) {
            finishProgramSwitch(0);
            return;
        }
        connect(window_->functionsDock()->model(), &FunctionTableModel::refreshed,
                this, [this]() {
                    finishProgramSwitch(
                        window_->functionsDock()->model()->rowCount(QModelIndex()));
                }, Qt::SingleShotConnection);
        // A selector that never switches must report what the list holds, not
        // hang the gate: waiting forever turns a defect into a timeout.
        QTimer::singleShot(2000, this, [this]() {
            if (active_) {
                finishProgramSwitch(
                    window_->functionsDock()->model()->rowCount(QModelIndex()));
            }
        });
        window_->selectProgramAt(count - 1);
    }, Qt::SingleShotConnection);
    window_->refreshPrograms();
}

void GateRunner::finishProgramSwitch(int functions) {
    metrics_.insert(QStringLiteral("ui.programs_switch_functions"), functions);
    const bool install_ok = qEnvironmentVariableIsSet("ROMWRIGHT_UI_INSTALL_OK");
    metrics_.insert(QStringLiteral("ui.install.ok"), install_ok);
    // What the window can tell the analyst about completeness. A listing
    // built from a loader-only import is every function the image names and
    // no body anyone walked; the window has to say so, and the gate records
    // both the store's answer and the words the window displayed.
    awaitAnalysis(0);
}

/// Watches the window's own background pass until it has nothing left, so
/// the gate records the transition an analyst sees -- provisional first,
/// complete later -- and not just one end of it.
void GateRunner::awaitAnalysis(int polls) {
    const bool load_only = qEnvironmentVariableIsSet("ROMWRIGHT_UI_LOAD_ONLY");
    bridge_->request(QJsonObject{{"method", "analysis_status"},
                                 {"program", window_->program()}},
                     [this, load_only, polls](const QJsonObject &res) {
                         const QJsonObject row =
                             res.value(QStringLiteral("result")).toObject();
                         metrics_.insert(QStringLiteral("ui.analysis.stale"),
                                         row.value(QStringLiteral("stale")).toBool());
                         metrics_.insert(QStringLiteral("ui.analysis.analysed"),
                                         row.value(QStringLiteral("analysed")).toInteger());
                         metrics_.insert(QStringLiteral("ui.analysis.seeded"),
                                         row.value(QStringLiteral("seeded")).toInteger());
                         if (auto *label = window_->findChild<QLabel *>(
                                 QStringLiteral("analysisStatus"))) {
                             metrics_.insert(QStringLiteral("ui.analysis"), label->text());
                         }
                         metrics_.insert(QStringLiteral("ui.analysis.first"),
                                         window_->firstAnalysisText());
                         metrics_.insert(QStringLiteral("ui.analysis.polls"), polls);
                         const bool stale =
                             row.value(QStringLiteral("stale")).toBool();
                         // 600 polls at 50 ms is 30 s: long enough for a
                         // corpus image, short enough that a stuck pass
                         // fails the gate instead of hanging it.
                         if (load_only && stale && polls < 600) {
                             QTimer::singleShot(50, this, [this, polls]() {
                                 awaitAnalysis(polls + 1);
                             });
                             return;
                         }
                         finish(true);
                     });
}

void GateRunner::finish(bool ok, const QString &detail) {
    if (!active_) {
        return;
    }
    active_ = false;
    stage_ = Stage::Inactive;
    const QJsonObject output{{"metrics", metrics_}};
    QTextStream out(stdout);
    out << QJsonDocument(output).toJson(QJsonDocument::Compact) << Qt::endl;
    if (!ok) {
        QTextStream err(stderr);
        err << "ui gate failed: " << detail << Qt::endl;
    }
    // Stop the bridge before leaving: a request still in flight would answer
    // into a window this exit is about to destroy.
    bridge_->shutdown();
    QApplication::exit(ok ? 0 : 1);
}
