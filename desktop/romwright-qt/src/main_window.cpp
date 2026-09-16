#include "main_window.h"

#include "analyst_dock.h"
#include "core_bridge.h"
#include "decompiler_dock.h"
#include "decompiler_view.h"
#include "facts_dock.h"
#include "function_table_model.h"
#include "functions_dock.h"
#include "gate_runner.h"
#include "graph_canvas.h"
#include "graph_dock.h"
#include "jobs_dock.h"
#include "json_util.h"
#include "listing_canvas.h"
#include "matching_dock.h"
#include "memory_dock.h"
#include "navigation_controller.h"
#include "theme.h"
#include "types_dock.h"
#include "views.h"
#include "vtables_dock.h"
#include "xrefs_dock.h"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QFileDialog>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrentRun>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QPointer>
#include <QScopedValueRollback>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QStyle>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>

#include <memory>

MainWindow::MainWindow(const QString &project, const QString &program, const QString &binary,
                       const QString &address, QWidget *parent)
    : QMainWindow(parent), bridge_(new CoreBridge(project, this)), program_(program), binary_(binary),
      address_(address) {
    navigation_ = new NavigationController(this);
    gate_runner_ = new GateRunner(this, bridge_, this);
    setWindowTitle(QStringLiteral("Romwright"));
    resize(1440, 920);
    setDockOptions(AnimatedDocks | AllowNestedDocks | AllowTabbedDocks);
    setTabPosition(Qt::AllDockWidgetAreas, QTabWidget::North);

    auto *central = new QWidget(this);
    auto *root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    auto *controls = new QGridLayout();

    controls->addWidget(new QLabel(QStringLiteral("Project"), central), 0, 0);
    controls->addWidget(project_edit_ = new QLineEdit(project, central), 0, 1);
    project_edit_->setReadOnly(true);
    project_edit_->setObjectName(QStringLiteral("projectPath"));
    controls->addWidget(new QLabel(QStringLiteral("Program"), central), 0, 2);
    controls->addWidget(program_edit_ = new QLineEdit(program, central), 0, 3);
    program_edit_->setObjectName(QStringLiteral("programName"));
    program_box_ = new QComboBox(this);
    program_box_->setObjectName(QStringLiteral("programSelector"));
    program_box_->setMinimumWidth(140);
    connect(program_box_, &QComboBox::activated, this, &MainWindow::selectProgramAt);
    controls->addWidget(new QLabel(QStringLiteral("Binary"), central), 1, 0);
    controls->addWidget(binary_edit_ = new QLineEdit(binary, central), 1, 1, 1, 3);
    binary_edit_->setObjectName(QStringLiteral("binaryPath"));
    address_edit_ = new QLineEdit(address, this);
    address_edit_->setFont(Theme::codeFont());
    const auto resize_address = [this](const QString &text) {
        const int characters = qBound(10, static_cast<int>(text.size()), 18);
        address_edit_->setFixedWidth(
            address_edit_->fontMetrics().horizontalAdvance(QLatin1Char('0')) * characters + 28);
    };
    connect(address_edit_, &QLineEdit::textChanged, this, resize_address);
    resize_address(address_edit_->text());
    address_edit_->setPlaceholderText(QStringLiteral("Address…"));
    address_edit_->setToolTip(QStringLiteral("Navigate to an address (Enter)"));
    connect(address_edit_, &QLineEdit::returnPressed, this,
            [this]() { navigation_->goTo(address_edit_->text(), true); });

    auto add_btn = [this, controls](const QString &lbl, int r, int c, auto slot) {
        auto *btn = new QPushButton(lbl, this);
        controls->addWidget(btn, r, c);
        connect(btn, &QPushButton::clicked, this, slot);
        return btn;
    };
    add_btn(QStringLiteral("Import native"), 4, 2, &MainWindow::importNative);
    add_btn(QStringLiteral("Open program"), 4, 3, &MainWindow::openProgram);
    controls->addWidget(new QLabel(QStringLiteral("Rename"), central), 2, 0);
    controls->addWidget(name_edit_ = new QLineEdit(central), 2, 1);
    add_btn(QStringLiteral("Apply rename"), 2, 2, &MainWindow::renameFunction);
    add_btn(QStringLiteral("Undo"), 2, 3, &MainWindow::undoCommand);
    controls->addWidget(new QLabel(QStringLiteral("Comment"), central), 3, 0);
    controls->addWidget(comment_edit_ = new QLineEdit(central), 3, 1);
    controls->addWidget(comment_kind_edit_ = new QLineEdit(QStringLiteral("eol"), central), 3, 2);
    add_btn(QStringLiteral("Apply comment"), 3, 3, &MainWindow::applyComment);

    auto *selection_panel = new QWidget(this);
    selection_panel->setLayout(controls);
    auto *selection_dock = new QDockWidget(QStringLiteral("Program & annotations"), this);
    selection_dock->setObjectName(QStringLiteral("selectionDock"));
    selection_dock->setWidget(selection_panel);
    addDockWidget(Qt::BottomDockWidgetArea, selection_dock);

    auto *navigation_bar = addToolBar(QStringLiteral("Navigation"));
    navigation_bar->setObjectName(QStringLiteral("navigationToolbar"));
    navigation_bar->setMovable(false);
    navigation_bar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    workspace_modes_ = new QTabBar(navigation_bar);
    workspace_modes_->setObjectName(QStringLiteral("workspaceModes"));
    workspace_modes_->setExpanding(false);
    workspace_modes_->setUsesScrollButtons(false);
    workspace_modes_->setElideMode(Qt::ElideNone);
    workspace_modes_->addTab(QStringLiteral("Analysis"));
    workspace_modes_->addTab(QStringLiteral("Matching"));
    navigation_bar->addWidget(workspace_modes_);
    navigation_bar->addSeparator();
    auto *back = navigation_bar->addAction(QIcon(QStringLiteral(":/workbench/back.svg")),
                                           QStringLiteral("Back"), this, [this]() { navigation_->back(); });
    auto *forward =
        navigation_bar->addAction(QIcon(QStringLiteral(":/workbench/forward.svg")), QStringLiteral("Forward"),
                                  this, [this]() { navigation_->forward(); });
    back->setShortcut(QKeySequence(QStringLiteral("Alt+Left")));
    forward->setShortcut(QKeySequence(QStringLiteral("Alt+Right")));
    back->setPriority(QAction::LowPriority);
    forward->setPriority(QAction::LowPriority);
    back->setEnabled(false);
    forward->setEnabled(false);
    connect(navigation_, &NavigationController::historyChanged, this,
            [back, forward](bool can_back, bool can_forward) {
                back->setEnabled(can_back);
                forward->setEnabled(can_forward);
            });
    navigation_bar->addSeparator();
    navigation_bar->addWidget(new QLabel(QStringLiteral(" Image  "), navigation_bar));
    navigation_bar->addWidget(program_box_);
    navigation_bar->addSeparator();
    navigation_bar->addWidget(new QLabel(QStringLiteral(" Address  "), navigation_bar));
    navigation_bar->addWidget(address_edit_);
    navigation_bar->addAction(QStringLiteral("Go"), this,
                              [this]() { navigation_->goTo(address_edit_->text(), true); });
    navigation_bar->addAction(QStringLiteral("Decompile"), this, &MainWindow::decompile);
    navigation_bar
        ->addAction(style()->standardIcon(QStyle::SP_BrowserReload), QStringLiteral("Refresh"),
                    this, &MainWindow::loadProgramPanels)
        ->setPriority(QAction::LowPriority);
    auto *spacer = new QWidget(navigation_bar);
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    navigation_bar->addWidget(spacer);
    navigation_bar->addAction(QStringLiteral("Program setup"), this, [selection_dock]() {
        selection_dock->show();
        selection_dock->raise();
    });

    auto *btn_listing = new QPushButton(QStringLiteral("Listing"), central);
    connect(btn_listing, &QPushButton::clicked, this, &MainWindow::loadListing);
    auto *btn_xref = new QPushButton(QStringLiteral("Xrefs"), central);
    connect(btn_xref, &QPushButton::clicked, this,
            [this]() { xrefs_dock_->loadXrefs(this->program(), address_edit_->text()); });

    listing_canvas_ = new ListingCanvas(central);
    auto *view_header = new QWidget(central);
    auto *view_actions = new QHBoxLayout(view_header);
    view_actions->setContentsMargins(4, 3, 4, 3);
    auto *view_heading = new QLabel(QStringLiteral("DISASSEMBLY"), view_header);
    view_heading->setObjectName(QStringLiteral("viewHeading"));
    view_heading->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    view_actions->addWidget(view_heading, 1);
    connect(navigation_, &NavigationController::addressChanged, view_heading,
            [view_heading](const QString &address) {
                view_heading->setText(QStringLiteral("DISASSEMBLY · %1").arg(address));
                view_heading->setToolTip(view_heading->text());
            });
    auto *bytes_toggle = new QPushButton(QStringLiteral("Bytes"), view_header);
    bytes_toggle->setObjectName(QStringLiteral("listingBytesToggle"));
    bytes_toggle->setCheckable(true);
    bytes_toggle->setChecked(listing_canvas_->bytesVisible());
    bytes_toggle->setToolTip(QStringLiteral("Show instruction bytes beside the assembly"));
    connect(bytes_toggle, &QPushButton::toggled, listing_canvas_, &ListingCanvas::setBytesVisible);
    view_actions->addWidget(bytes_toggle);
    view_actions->addWidget(btn_listing);
    view_actions->addWidget(btn_xref);
    root->addWidget(view_header);
    root->addWidget(listing_canvas_, 1);
    setCentralWidget(central);

    auto add_dock = [this](Qt::DockWidgetArea a, QDockWidget *d) {
        addDockWidget(a, d);
        return d;
    };
    functions_dock_ =
        static_cast<FunctionsDock *>(add_dock(Qt::LeftDockWidgetArea, new FunctionsDock(bridge_, this)));
    connect(functions_dock_->model(), &FunctionTableModel::requestError, this,
            [this](const QString &message) { setStatus(message, true); });
    connect(functions_dock_, &FunctionsDock::functionContextChanged, view_heading,
            [view_heading](const QString &, const QString &name) {
                view_heading->setText(QStringLiteral("DISASSEMBLY · %1").arg(name));
                view_heading->setToolTip(view_heading->text());
            });
    analyst_dock_ =
        static_cast<AnalystDock *>(add_dock(Qt::LeftDockWidgetArea, new AnalystDock(bridge_, this)));
    types_dock_ = static_cast<TypesDock *>(add_dock(Qt::LeftDockWidgetArea, new TypesDock(bridge_, this)));
    decompiler_dock_ =
        static_cast<DecompilerDock *>(add_dock(Qt::BottomDockWidgetArea, new DecompilerDock(this)));
    graph_dock_ = static_cast<GraphDock *>(add_dock(Qt::BottomDockWidgetArea, new GraphDock(this)));
    jobs_dock_ = static_cast<JobsDock *>(add_dock(Qt::BottomDockWidgetArea, new JobsDock(bridge_, this)));
    facts_dock_ = static_cast<FactsDock *>(add_dock(Qt::RightDockWidgetArea, new FactsDock(bridge_, this)));
    memory_dock_ =
        static_cast<MemoryDock *>(add_dock(Qt::RightDockWidgetArea, new MemoryDock(bridge_, this)));
    xrefs_dock_ = static_cast<XrefsDock *>(add_dock(Qt::RightDockWidgetArea, new XrefsDock(bridge_, this)));
    vtables_dock_ =
        static_cast<VtablesDock *>(add_dock(Qt::RightDockWidgetArea, new VtablesDock(bridge_, this)));
    matching_dock_ =
        static_cast<MatchingDock *>(add_dock(Qt::BottomDockWidgetArea, new MatchingDock(bridge_, this)));
    matching_dock_->hide();

    status_ = new QLabel(this);
    statusBar()->addWidget(status_, 1);
    // How complete the open program's facts are. A window that shows a
    // listing built from a loader-only import must say the answer is
    // provisional; the alternative is showing nothing until analysis ends,
    // which on a 45k-function module is minutes of an empty window.
    analysis_label_ = new QLabel(this);
    analysis_label_->setObjectName(QStringLiteral("analysisStatus"));
    statusBar()->addPermanentWidget(analysis_label_);
    analysis_timer_ = new QTimer(this);
    analysis_timer_->setInterval(50);
    connect(analysis_timer_, &QTimer::timeout, this, &MainWindow::analysePending);

    auto *menu_bar = menuBar();
    auto *file_menu = menu_bar->addMenu(QStringLiteral("&File"));
    file_menu->addAction(QStringLiteral("&Open project…"), this, [this]() {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Open SQLite project"),
                                                              project_edit_->text());
        if (!dir.isEmpty()) {
            auto *window = new MainWindow(dir, QString(), QString(), QString());
            window->setAttribute(Qt::WA_DeleteOnClose);
            window->show();
        }
    });
    recent_menu_ = file_menu->addMenu(QStringLiteral("Open &recent"));
    QSettings recent_settings(QStringLiteral("Romwright"), QStringLiteral("Romwright"));
    QStringList recent = recent_settings.value(QStringLiteral("recentProjects")).toStringList();
    recent.removeAll(project);
    recent.prepend(project);
    recent = recent.mid(0, 10);
    recent_settings.setValue(QStringLiteral("recentProjects"), recent);
    for (const QString &path : recent) {
        auto *action = recent_menu_->addAction(path);
        connect(action, &QAction::triggered, this, [path]() {
            auto *window = new MainWindow(path, QString(), QString(), QString());
            window->setAttribute(Qt::WA_DeleteOnClose);
            window->show();
        });
    }
    file_menu->addSeparator();
    file_menu->addAction(QStringLiteral("&Quit"), QKeySequence::Quit, qApp,
                         &QApplication::closeAllWindows);

    auto *view_menu = menu_bar->addMenu(QStringLiteral("&View"));
    const QList<QDockWidget *> all_docks = {
        functions_dock_, decompiler_dock_, facts_dock_, memory_dock_, graph_dock_,   analyst_dock_,
        matching_dock_,  types_dock_,      xrefs_dock_, jobs_dock_,   vtables_dock_, selection_dock};
    for (auto *dock : all_docks) {
        if (dock != matching_dock_) {
            auto *action = dock->toggleViewAction();
            view_menu->addAction(action);
            connect(action, &QAction::triggered, dock, [dock](bool visible) {
                if (visible)
                    dock->raise();
            });
        }
    }
    const auto reset_layout = [this, all_docks, selection_dock]() {
        workspace_modes_->setCurrentIndex(0);
        for (auto *dock : all_docks) {
            dock->setFloating(false);
            dock->hide();
        }
        addDockWidget(Qt::LeftDockWidgetArea, functions_dock_);
        addDockWidget(Qt::RightDockWidgetArea, decompiler_dock_);
        addDockWidget(Qt::RightDockWidgetArea, graph_dock_);
        tabifyDockWidget(decompiler_dock_, graph_dock_);
        graph_dock_->show();
        addDockWidget(Qt::BottomDockWidgetArea, xrefs_dock_);
        for (QDockWidget *dock :
             {static_cast<QDockWidget *>(facts_dock_), static_cast<QDockWidget *>(memory_dock_),
              static_cast<QDockWidget *>(jobs_dock_), static_cast<QDockWidget *>(vtables_dock_),
              static_cast<QDockWidget *>(types_dock_), static_cast<QDockWidget *>(analyst_dock_),
              static_cast<QDockWidget *>(matching_dock_), selection_dock}) {
            addDockWidget(Qt::BottomDockWidgetArea, dock);
            tabifyDockWidget(xrefs_dock_, dock);
        }
        functions_dock_->show();
        functions_dock_->raise();
        decompiler_dock_->show();
        decompiler_dock_->raise();
        xrefs_dock_->show();
        xrefs_dock_->raise();
        resizeDocks({functions_dock_, decompiler_dock_}, {310, 480}, Qt::Horizontal);
        resizeDocks({xrefs_dock_}, {180}, Qt::Vertical);
    };
    reset_layout();
    view_menu->addSeparator();
    view_menu->addAction(QStringLiteral("Reset workbench layout"), this, reset_layout);
    connect(workspace_modes_, &QTabBar::currentChanged, this, [this, all_docks, central](int mode) {
        if (mode == 1) {
            analysis_layout_ = saveState();
            for (auto *dock : all_docks)
                dock->hide();
            central->hide();
            matching_dock_->setFloating(false);
            matching_dock_->setFeatures(QDockWidget::NoDockWidgetFeatures);
            addDockWidget(Qt::RightDockWidgetArea, matching_dock_);
            matching_dock_->show();
            matching_dock_->raise();
            resizeDocks({matching_dock_}, {width()}, Qt::Horizontal);
        } else {
            matching_dock_->hide();
            matching_dock_->setFeatures(QDockWidget::DockWidgetClosable | QDockWidget::DockWidgetMovable |
                                        QDockWidget::DockWidgetFloatable);
            central->show();
            if (!analysis_layout_.isEmpty())
                restoreState(analysis_layout_);
            analysis_layout_.clear();
        }
        saveWorkspace();
    });

    auto *search_menu = menu_bar->addMenu(QStringLiteral("&Search"));
    search_menu->addAction(QStringLiteral("&Command palette"), QKeySequence(QStringLiteral("Ctrl+Shift+P")),
                           this, &MainWindow::showCommandPalette);
    search_menu->addAction(QStringLiteral("&Byte-pattern search…"), this, &MainWindow::showSignatureSearch);
    search_menu->addAction(QStringLiteral("Recover &vtables"), this,
                           [this]() { vtables_dock_->recoverVtables(this->binary()); });
    auto *matching_menu = menu_bar->addMenu(QStringLiteral("&Matching"));
    matching_menu->addAction(QStringLiteral("Open matching workspace"),
                             QKeySequence(QStringLiteral("Ctrl+Shift+M")), this,
                             &MainWindow::showMatchingWorkspace);
    connect(matching_dock_, &MatchingDock::statusRequested, this, &MainWindow::setStatus);

    connect(functions_dock_, &FunctionsDock::addressSelected, navigation_, &NavigationController::goTo);
    connect(functions_dock_->model(), &FunctionTableModel::refreshed, gate_runner_,
            &GateRunner::modelRefreshed);
    connect(decompiler_dock_->view(), &DecompilerView::addressSelected, this,
            [this](const QString &address, bool record) {
                if (!record && sameAddress(address, navigation_->address()))
                    return;
                QScopedValueRollback<bool> selecting(source_selection_, true);
                navigation_->goTo(address, record);
            });
    connect(decompiler_dock_->view(), &DecompilerView::renameRequested, this, &MainWindow::renameFunctionAt);
    connect(decompiler_dock_->view(), &DecompilerView::functionFollowRequested,
            navigation_, &NavigationController::goTo);
    connect(listing_canvas_, &ListingCanvas::addressSelected, navigation_, &NavigationController::goTo);
    connect(listing_canvas_, &ListingCanvas::contextMenuRequested, this, &MainWindow::listingContextMenu);
    connect(listing_canvas_, &ListingCanvas::windowNeeded, this, &MainWindow::loadListingAt);
    connect(listing_canvas_, &ListingCanvas::backRequested, navigation_, &NavigationController::back);
    connect(listing_canvas_, &ListingCanvas::forwardRequested, navigation_, &NavigationController::forward);
    connect(graph_dock_, &GraphDock::addressSelected, this, [this](const QString &address, bool record) {
        QScopedValueRollback<bool> selecting(source_selection_, true);
        navigation_->goTo(address, record);
        decompiler_dock_->view()->setAddress(address);
    });
    connect(facts_dock_, &FactsDock::addressSelected, this, [this](const QString &a, bool) {
        address_edit_->setText(a);
        xrefs_dock_->loadXrefs(this->program(), a);
    });
    connect(facts_dock_, &FactsDock::addressDoubleClicked, this,
            [this](const QString &a) { navigation_->goTo(a, true); });
    connect(memory_dock_, &MemoryDock::addressSelected, navigation_, &NavigationController::goTo);
    connect(analyst_dock_, &AnalystDock::addressDoubleClicked, this,
            [this](const QString &a) { navigation_->goTo(a, true); });
    connect(vtables_dock_, &VtablesDock::addressDoubleClicked, this,
            [this](const QString &a) { navigation_->goTo(a, true); });
    connect(xrefs_dock_, &XrefsDock::addressDoubleClicked, this,
            [this](const QString &a) { navigation_->goTo(a, true); });
    connect(types_dock_, &TypesDock::prototypeSaved, this, [this](const QString &addr) {
        decompile_cache_.clear();
        decompile();
    });

    auto hook = [this](auto *d) {
        auto pending = std::make_shared<QHash<QString, QList<int>>>();
        connect(d, &std::remove_pointer_t<decltype(d)>::jobStarted, jobs_dock_,
                [this, pending](const QString &n) { (*pending)[n].append(jobs_dock_->beginJob(n)); });
        connect(d, &std::remove_pointer_t<decltype(d)>::jobFinished, jobs_dock_,
                [this, pending](const QString &n, bool ok, const QString &det) {
                    auto jobs = pending->find(n);
                    if (jobs == pending->end())
                        return;
                    const int job = jobs->takeFirst();
                    if (jobs->isEmpty())
                        pending->erase(jobs);
                    jobs_dock_->finishJob(job, ok, det);
                });
    };
    hook(memory_dock_);
    hook(analyst_dock_);
    hook(types_dock_);
    hook(xrefs_dock_);
    hook(vtables_dock_);
    connect(jobs_dock_, &JobsDock::statusRequested, this, &MainWindow::setStatus);
    connect(types_dock_, &TypesDock::statusRequested, this, &MainWindow::setStatus);
    connect(facts_dock_, &FactsDock::statusRequested, this, &MainWindow::setStatus);
    connect(memory_dock_, &QDockWidget::visibilityChanged, this, [this](bool visible) {
        if (visible && !navigation_->address().isEmpty())
            memory_dock_->loadHex(this->binary(), navigation_->address());
    });

    connect(functions_dock_->model(), &FunctionTableModel::refreshed, this, [this]() {
        if (!qEnvironmentVariableIsSet("ROMWRIGHT_UI_GATE") &&
            navigation_->address().isEmpty() && functions_dock_->model()->rowCount() > 0) {
            auto *model = functions_dock_->model();
            navigation_->goTo(model->data(model->index(0, 0)).toString(), true);
        }
    });
    selection_timer_ = new QTimer(this);
    selection_timer_->setSingleShot(true);
    selection_timer_->setInterval(75);
    connect(selection_timer_, &QTimer::timeout, this, [this]() {
        const QString address = navigation_->address();
        listing_canvas_->setAddress(address);
        xrefs_dock_->loadXrefs(this->program(), address);
    });
    connect(navigation_, &NavigationController::addressChanged, this, [this](const QString &address) {
        address_edit_->setText(address);
        if (source_selection_) {
            ++decompile_generation_;
            functions_dock_->setFunction(current_function_, address);
            selection_timer_->start();
        } else {
            selection_timer_->stop();
            decompile();
            listing_canvas_->setAddress(address);
            xrefs_dock_->loadXrefs(this->program(), address);
        }
    });

    restoreWorkspace();
    if (!bridge_->startupError().isEmpty()) {
        setStatus(bridge_->startupError(), true);
    } else {
        if (!program_.isEmpty()) {
            navigation_->setProgram(program_);
            if (qEnvironmentVariableIsSet("ROMWRIGHT_UI_GATE")) {
                functions_dock_->setProgram(program_);
            } else {
                switchProgram(program_);
            }
        } else {
            setStatus(QStringLiteral("Choose an image, or import a binary from View → Selection."));
        }
        refreshPrograms();
    }
}

MainWindow::~MainWindow() {
    saveWorkspace();
    bridge_->shutdown();
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (!matching_dock_->confirmClose(this)) {
        event->ignore();
        return;
    }
    QMainWindow::closeEvent(event);
}

QString MainWindow::program() const { return program_; }

void MainWindow::refreshPrograms() {
    bridge_->request(QJsonObject{{"method", "programs"}}, [this, guard = QPointer<MainWindow>(this)](
                                                              const QJsonObject &res) {
        if (guard.isNull()) {
            return;
        }
        QString error;
        if (!successful(res, &error)) {
            setStatus(error, true);
            emit programsListed(0);
            return;
        }
        const QJsonArray rows = res.value("result").toArray();
        const QString current = this->program();
        program_box_->blockSignals(true);
        program_box_->clear();
        for (const QJsonValue &value : rows) {
            const QJsonObject row = value.toObject();
            program_box_->addItem(QStringLiteral("%1 (%2)").arg(row.value("program").toString(),
                                                                row.value("language").toString()),
                                  row.value("program").toString());
        }
        const int index = program_box_->findData(current);
        program_box_->setCurrentIndex(index);
        program_box_->blockSignals(false);
        if (index < 0 && current.isEmpty() && !rows.isEmpty()) {
            selectProgramAt(0);
        }
        emit programsListed(rows.size());
    });
}

int MainWindow::programCount() const { return program_box_ == nullptr ? 0 : program_box_->count(); }

void MainWindow::selectProgramAt(int index) {
    if (program_box_ == nullptr || index < 0 || index >= program_box_->count()) {
        return;
    }
    const QString chosen = program_box_->itemData(index).toString();
    if (chosen.isEmpty()) {
        return;
    }
    program_box_->setCurrentIndex(index);
    switchProgram(chosen);
}

void MainWindow::switchProgram(const QString &program) {
    const quint64 request = ++switch_generation_;
    setStatus(QStringLiteral("Opening %1…").arg(program));
    bridge_->request(QJsonObject{{"method", "program_input"}, {"program", program}},
                     [this, guard = QPointer<MainWindow>(this), request, program](const QJsonObject &res) {
        if (guard.isNull() || request != switch_generation_) {
            return;
        }
        QString error;
        if (!successful(res, &error)) {
            program_box_->setCurrentIndex(program_box_->findData(program_));
            setStatus(error, true);
            return;
        }
        const QJsonObject input = res.value("result").toObject();
        const QString binary = QDir(project_edit_->text()).filePath(
            QStringLiteral("artifacts/") + input.value("binary_digest").toString());
        if (!matching_dock_->setProgram(program, binary)) {
            program_box_->setCurrentIndex(program_box_->findData(program_));
            return;
        }
        const bool changed = program_ != program;
        if (changed) {
            saveWorkspace();
            address_edit_->clear();
            first_analysis_.clear();
            analysis_label_->clear();
            analysis_timer_->stop();
        }
        ++program_generation_;
        program_ = program;
        binary_ = binary;
        program_edit_->setText(program);
        binary_edit_->setText(binary);
        binary_edit_->setToolTip(input.value("source_path").toString());
        navigation_->setProgram(program);
        functions_dock_->setProgram(program);
        loadProgramPanels();
        setStatus(QStringLiteral("Showing %1").arg(program));
    });
}
QString MainWindow::binary() const { return binary_; }

QString MainWindow::firstAnalysisText() const { return first_analysis_; }

void MainWindow::showMatchingWorkspace() {
    if (matching_dock_->setProgram(this->program(), this->binary()))
        workspace_modes_->setCurrentIndex(1);
}
void MainWindow::runGate(bool store_only) { gate_runner_->run(store_only); }

void MainWindow::setStatus(const QString &message, bool error) {
    if (status_ != nullptr) {
        status_->setText(message);
        status_->setStyleSheet(error ? QStringLiteral("color:#e06c75") : QString());
    }
}

void MainWindow::loadProgramPanels() {
    const QString p = this->program(), b = this->binary(), a = address_edit_->text();
    decompile_cache_.clear();
    displayed_decompile_key_.clear();
    current_function_ = {};
    ++listing_generation_;
    ++decompile_generation_;
    listing_canvas_->clear();
    decompiler_dock_->view()->setPending(QStringLiteral("Select an address to decompile."));
    navigation_->goTo(a, navigation_->address().isEmpty());
    facts_dock_->loadFacts(p, QString());
    memory_dock_->loadMemory(p, b, a);
    graph_dock_->setGraph({});
    analyst_dock_->loadAnalystData(p);
    vtables_dock_->recoverVtables(QString());
    matching_dock_->setProgram(p, b);
    types_dock_->loadTypes(p);
    refreshAnalysisStatus();
}

void MainWindow::refreshAnalysisStatus() {
    const QString p = this->program();
    if (p.isEmpty()) {
        analysis_label_->clear();
        analysis_timer_->stop();
        return;
    }
    bridge_->request(
        QJsonObject{{"method", "analysis_status"}, {"program", p}},
        [this, guard = QPointer<MainWindow>(this), generation = program_generation_](const QJsonObject &res) {
            if (guard.isNull() || generation != program_generation_) {
                return;
            }
            QString err;
            if (!successful(res, &err)) {
                analysis_label_->clear();
                return;
            }
            const QJsonObject row = res.value(QStringLiteral("result")).toObject();
            const qint64 analysed = row.value(QStringLiteral("analysed")).toInteger();
            const qint64 seeded = row.value(QStringLiteral("seeded")).toInteger();
            const bool stale = row.value(QStringLiteral("stale")).toBool();
            analysis_label_->setText(
                stale ? QStringLiteral("provisional: %1 analysed, %2 to go").arg(analysed).arg(seeded)
                      : QStringLiteral("analysed: %1").arg(analysed));
            if (first_analysis_.isEmpty()) {
                first_analysis_ = analysis_label_->text();
            }
            // Keep asking for more only while there is more.
            if (stale && !analysis_timer_->isActive()) {
                analysis_timer_->start();
            } else if (!stale) {
                analysis_timer_->stop();
            }
        });
}

void MainWindow::analysePending() {
    // One request at a time: the pass is work, and stacking requests would
    // queue the window behind itself.
    if (analysis_running_) {
        return;
    }
    const QString p = this->program(), b = this->binary();
    if (p.isEmpty() || b.isEmpty()) {
        analysis_timer_->stop();
        return;
    }
    analysis_running_ = true;
    bridge_->request(
        QJsonObject{{"method", "analyse_pending"}, {"binary", b}, {"program", p}, {"budget", 16}},
        [this, guard = QPointer<MainWindow>(this), generation = program_generation_](const QJsonObject &res) {
            if (guard.isNull()) {
                return;
            }
            analysis_running_ = false;
            if (generation != program_generation_) {
                return;
            }
            QString err;
            if (!successful(res, &err)) {
                analysis_timer_->stop();
                return;
            }
            const QJsonObject row = res.value(QStringLiteral("result")).toObject();
            const qint64 analysed = row.value(QStringLiteral("analysed")).toInteger();
            const qint64 seeded = row.value(QStringLiteral("seeded")).toInteger();
            const bool stale = row.value(QStringLiteral("stale")).toBool();
            analysis_label_->setText(
                stale ? QStringLiteral("provisional: %1 analysed, %2 to go").arg(analysed).arg(seeded)
                      : QStringLiteral("analysed: %1").arg(analysed));
            if (!stale) {
                analysis_timer_->stop();
                // The facts changed under every view: refresh
                // once, at the end, rather than per function.
                functions_dock_->setProgram(this->program());
            }
        });
}

void MainWindow::importNative() {
    const QString binary = binary_edit_->text().trimmed(), p = program_edit_->text().trimmed();
    const int job = jobs_dock_->beginJob(QStringLiteral("native import"));
    bridge_->request(QJsonObject{{"method", "import_native"}, {"binary", binary}, {"name", p}},
                     [this, guard = QPointer<MainWindow>(this), job, p](const QJsonObject &res) {
                         if (guard.isNull()) {
                             return;
                         }
                         QString err;
                         if (!successful(res, &err)) {
                             jobs_dock_->finishJob(job, false, err);
                             return;
                         }
                         jobs_dock_->finishJob(job, true, QStringLiteral("imported %1").arg(p));
                         switchProgram(p);
                         refreshPrograms();
                     });
}

void MainWindow::openProgram() {
    const QString p = program_edit_->text().trimmed();
    const int job = jobs_dock_->beginJob(QStringLiteral("open program"));
    // The answer arrives on the event loop, which may outlive this window when
    // the gate exits: a raw `this` here read a destroyed QLineEdit.
    bridge_->request(QJsonObject{{"method", "open"}, {"program", p}},
                     [this, guard = QPointer<MainWindow>(this), job, p](const QJsonObject &res) {
                         if (guard.isNull()) {
                             return;
                         }
                         QString err;
                         if (!successful(res, &err)) {
                             jobs_dock_->finishJob(job, false, err);
                             return;
                         }
                         jobs_dock_->finishJob(job, true, QStringLiteral("opened %1").arg(p));
                         switchProgram(p);
                     });
}

void MainWindow::decompile() {
    const QString address = address_edit_->text();
    if (!sameAddress(address, navigation_->address())) {
        navigation_->goTo(address, true);
        return;
    }
    const quint64 gen = ++decompile_generation_;
    bridge_->request(
        QJsonObject{{"method", "function_at"}, {"program", this->program()}, {"address", address}},
        [this, guard = QPointer<MainWindow>(this), gen, address](const QJsonObject &res) {
            if (!guard || gen != decompile_generation_)
                return;
            QString err;
            if (!successful(res, &err)) {
                displayed_decompile_key_.clear();
                current_function_ = {};
                functions_dock_->setFunction(current_function_, address);
                decompiler_dock_->view()->setPending(QStringLiteral("Function lookup failed: %1").arg(err));
                graph_dock_->setGraph({});
                types_dock_->setPrototypeAddress({});
                setStatus(err, true);
                return;
            }
            if (res.value("result").isNull()) {
                displayed_decompile_key_.clear();
                current_function_ = {};
                functions_dock_->setFunction(current_function_, address);
                decompiler_dock_->view()->setPending(
                    QStringLiteral("No known function contains %1").arg(address));
                graph_dock_->setGraph({});
                types_dock_->setPrototypeAddress({});
                return;
            }
            const auto function = FunctionRowView::fromJson(res.value("result").toObject());
            current_function_ = function;
            functions_dock_->setFunction(function, address);
            listing_canvas_->setFunctionName(function.address, function.name);
            types_dock_->setPrototypeAddress(function.address);
            decompileFunction(function.address, address, gen);
        });
}

void MainWindow::decompileFunction(const QString &entry, const QString &address, quint64 gen) {
    const QString key = this->program() + QLatin1Char('|') + entry;
    if (const auto *cached = decompile_cache_.object(key)) {
        if (displayed_decompile_key_ != key) {
            decompiler_dock_->view()->setTokens(cached->tokens);
            graph_dock_->setGraph(cached->graph);
            displayed_decompile_key_ = key;
        }
        decompiler_dock_->view()->setAddress(address);
        graph_dock_->canvas()->setAddress(address);
        return;
    }
    displayed_decompile_key_.clear();
    const int job = jobs_dock_->beginJob(QStringLiteral("decompile %1").arg(entry));
    decompiler_dock_->view()->setPending(QStringLiteral("Decompiling…"));
    graph_dock_->setGraph({});
    bridge_->request(
        QJsonObject{{"method", "decompile_doc"},
                    {"binary", this->binary()},
                    {"program", this->program()},
                    {"address", entry}},
        [this, guard = QPointer<MainWindow>(this), job, key, gen, address](const QJsonObject &res) {
            if (!guard)
                return;
            if (gen != decompile_generation_) {
                jobs_dock_->finishJob(job, successful(res), QStringLiteral("Superseded decompilation"));
                return;
            }
            QString err;
            if (!successful(res, &err)) {
                decompiler_dock_->view()->setPending(QStringLiteral("Decompilation failed: %1").arg(err));
                jobs_dock_->finishJob(job, false, err);
                return;
            }
            const QJsonObject result = res.value("result").toObject();
            const qint64 rev = result.value("revision").toVariant().toLongLong();
            const auto graph = result.value("graph").toObject();
            auto *watcher = new QFutureWatcher<QVector<TokenView>>(this);
            connect(watcher, &QFutureWatcher<QVector<TokenView>>::finished, this,
                    [this, watcher, job, key, gen, address, rev, graph] {
                const auto tokens = watcher->result();
                watcher->deleteLater();
                if (gen != decompile_generation_) {
                    jobs_dock_->finishJob(job, true, QStringLiteral("Superseded decompilation"));
                    return;
                }
                decompile_cache_.insert(key, new CachedDecompile{rev, tokens, graph},
                                        qMax(32768, static_cast<int>(tokens.size())));
                decompiler_dock_->view()->setTokens(tokens);
                decompiler_dock_->view()->setAddress(address);
                graph_dock_->setGraph(graph);
                graph_dock_->canvas()->setAddress(address);
                displayed_decompile_key_ = key;
                jobs_dock_->finishJob(job, true,
                                      QStringLiteral("%1 tokens, revision %2").arg(tokens.size()).arg(rev));
            });
            watcher->setFuture(QtConcurrent::run([result] { return TokenView::fromDocument(result); }));
        });
}

void MainWindow::loadListing() { loadListingAt(address_edit_->text()); }

void MainWindow::loadListingAt(const QString &address) {
    const quint64 generation = ++listing_generation_;
    if (address.isEmpty() || this->binary().isEmpty()) {
        return;
    }
    const int job = jobs_dock_->beginJob(QStringLiteral("listing %1").arg(address));
    listing_canvas_->setWindow({}, QStringLiteral("Loading listing at %1…").arg(address));
    bridge_->request(
        QJsonObject{
            {"method", "listing"}, {"binary", this->binary()}, {"start", address}, {"count", 128}},
        [this, guard = QPointer<MainWindow>(this), job, address, generation](const QJsonObject &res) {
            if (!guard)
                return;
            if (generation != listing_generation_) {
                jobs_dock_->finishJob(job, successful(res), QStringLiteral("Superseded listing"));
                return;
            }
            QString err;
            if (!successful(res, &err)) {
                jobs_dock_->finishJob(job, false, err);
                listing_canvas_->setWindow({},
                    QStringLiteral("Listing failed at %1:\n%2").arg(address, err));
                return;
            }
            QVector<ListingRowView> views;
            for (const QJsonValue &v : res.value("result").toObject().value("rows").toArray()) {
                views.append(ListingRowView::fromJson(v.toObject()));
            }
            listing_canvas_->setWindow(views);
            listing_canvas_->setAddress(address);
            jobs_dock_->finishJob(job, true, QStringLiteral("listing loaded"));
        });
}

void MainWindow::listingContextMenu(const QPoint &pos, const QString &addr) {
    QMenu menu(this);
    menu.addAction(QStringLiteral("Rename function"), this,
                   [this, addr]() { renameFunctionAt(addr, QString()); });
    menu.addAction(QStringLiteral("Show xrefs"), this,
                   [this, addr]() {
                       xrefs_dock_->loadXrefs(this->program(), addr);
                       xrefs_dock_->show();
                       xrefs_dock_->raise();
                   });
    menu.addAction(QStringLiteral("Decompile here"), this, [this, addr]() { navigation_->goTo(addr, true); });
    menu.exec(pos);
}


void MainWindow::restoreWorkspace() {
    QSettings settings(QStringLiteral("Romwright"), QStringLiteral("Romwright"));
    const QString scope =
        this->program().isEmpty() ? QString() : this->program() + QLatin1Char('/');
    const QByteArray geo = settings.value(scope + QStringLiteral("geometry")).toByteArray();
    if (!geo.isEmpty()) {
        restoreGeometry(geo);
    }
    const QByteArray state = settings.value(scope + QStringLiteral("windowState")).toByteArray();
    if (!state.isEmpty()) {
        restoreState(state);
    } else {
        QTimer::singleShot(0, this, [this]() {
            if (workspace_modes_->currentIndex() == 0) {
                decompiler_dock_->raise();
                xrefs_dock_->raise();
                saveWorkspace();
            }
        });
    }
    matching_dock_->hide();
}

void MainWindow::saveWorkspace() {
    QSettings settings(QStringLiteral("Romwright"), QStringLiteral("Romwright"));
    const QString scope =
        this->program().isEmpty() ? QString() : this->program() + QLatin1Char('/');
    settings.setValue(scope + QStringLiteral("geometry"), saveGeometry());
    settings.setValue(scope + QStringLiteral("windowState"),
                      analysis_layout_.isEmpty() ? saveState() : analysis_layout_);
}
