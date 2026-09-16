#include "theme.h"

#include <QApplication>
#include <QFontDatabase>
#include <QPalette>
#include <QStyleFactory>

Theme Theme::make(const QString &name) {
    Theme t;
    if (name == QStringLiteral("light")) {
        t.background = QColor("#f5f6f8");
        t.cursor_line = QColor("#d0d8e0");
        t.highlight = QColor("#c8d8e8");
        t.empty_text = QColor("#7a8288");
        t.status_ok = QColor("#1a7f37");
        t.status_error = QColor("#c0392b");
        t.job_running = QColor("#9a6700");
        t.job_cancelled = QColor("#7a8288");
        t.address_column = QColor("#0550ae");
        t.bytes_column = QColor("#57606a");
        t.mnemonic = QColor("#8250df");
        t.operands = QColor("#1f2328");
        t.jump_target = QColor("#0969da");
        t.variable = QColor("#953800");
        t.function_name = QColor("#0550ae");
        t.operator_ = QColor("#0969da");
        t.keyword = QColor("#8250df");
        t.node_fill = QColor("#eaeef2");
        t.node_border = QColor("#0550ae");
        t.node_highlight = QColor("#9a6700");
        t.node_text = QColor("#1f2328");
        t.edge_true = QColor("#1a7f37");
        t.edge_false = QColor("#c0392b");
        t.edge_unconditional = QColor("#57606a");
        t.edge_call = QColor("#8250df");
        t.offset_column = QColor("#0550ae");
        t.hex_text = QColor("#1f2328");
        t.ascii_text = QColor("#57606a");
        t.pointer = QColor("#0969da");
        return t;
    }
    if (name == QStringLiteral("contrast")) {
        t.background = QColor("#000000");
        t.cursor_line = QColor("#3a3a3a");
        t.highlight = QColor("#4a4a00");
        t.empty_text = QColor("#a0a0a0");
        t.status_ok = QColor("#00ff00");
        t.status_error = QColor("#ff4040");
        t.job_running = QColor("#ffff00");
        t.job_cancelled = QColor("#a0a0a0");
        t.address_column = QColor("#00ffff");
        t.bytes_column = QColor("#c0c0c0");
        t.mnemonic = QColor("#ff80ff");
        t.operands = QColor("#ffffff");
        t.jump_target = QColor("#00ffff");
        t.variable = QColor("#ffff80");
        t.function_name = QColor("#80ffff");
        t.operator_ = QColor("#00ff80");
        t.keyword = QColor("#ff80ff");
        t.node_fill = QColor("#202020");
        t.node_border = QColor("#00ffff");
        t.node_highlight = QColor("#ffff00");
        t.node_text = QColor("#ffffff");
        t.edge_true = QColor("#00ff00");
        t.edge_false = QColor("#ff4040");
        t.edge_unconditional = QColor("#c0c0c0");
        t.edge_call = QColor("#ff80ff");
        t.offset_column = QColor("#00ffff");
        t.hex_text = QColor("#ffffff");
        t.ascii_text = QColor("#c0c0c0");
        t.pointer = QColor("#00ffff");
        return t;
    }
    // Dark (default).
    t.background = QColor("#101419");
    t.cursor_line = QColor("#2a3542");
    t.highlight = QColor("#3a4a5a");
    t.empty_text = QColor("#7e8996");
    t.status_ok = QColor("#98c379");
    t.status_error = QColor("#e06c75");
    t.job_running = QColor("#e5c07b");
    t.job_cancelled = QColor("#7e8996");
    t.address_column = QColor("#79b8ff");
    t.bytes_column = QColor("#8fa8bf");
    t.mnemonic = QColor("#c678dd");
    t.operands = QColor("#d6dee8");
    t.jump_target = QColor("#56b6c2");
    t.variable = QColor("#e5c07b");
    t.function_name = QColor("#61afef");
    t.operator_ = QColor("#56b6c2");
    t.keyword = QColor("#c678dd");
    t.node_fill = QColor("#202a35");
    t.node_border = QColor("#79b8ff");
    t.node_highlight = QColor("#e5c07b");
    t.node_text = QColor("#d6dee8");
    t.edge_true = QColor("#98c379");
    t.edge_false = QColor("#e06c75");
    t.edge_unconditional = QColor("#56606d");
    t.edge_call = QColor("#c678dd");
    t.offset_column = QColor("#79b8ff");
    t.hex_text = QColor("#d6dee8");
    t.ascii_text = QColor("#8fa8bf");
    t.pointer = QColor("#56b6c2");
    return t;
}

void Theme::apply(QApplication &application) {
    application.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    const Theme &t = current();
    QPalette palette;
    palette.setColor(QPalette::Window, t.node_fill);
    palette.setColor(QPalette::WindowText, t.operands);
    palette.setColor(QPalette::Base, t.background);
    palette.setColor(QPalette::AlternateBase, t.background.lighter(112));
    palette.setColor(QPalette::Text, t.operands);
    palette.setColor(QPalette::Button, t.node_fill);
    palette.setColor(QPalette::ButtonText, t.operands);
    palette.setColor(QPalette::Highlight, t.highlight);
    palette.setColor(QPalette::HighlightedText, t.operands);
    palette.setColor(QPalette::ToolTipBase, t.node_fill);
    palette.setColor(QPalette::ToolTipText, t.operands);
    palette.setColor(QPalette::Link, t.function_name);
    palette.setColor(QPalette::PlaceholderText, t.empty_text);
    palette.setColor(QPalette::Light, t.cursor_line);
    palette.setColor(QPalette::Mid, t.cursor_line);
    palette.setColor(QPalette::Dark, t.background);
    for (auto role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText})
        palette.setColor(QPalette::Disabled, role, t.empty_text);
    application.setPalette(palette);
    QFont font = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
    font.setPointSizeF(10);
    application.setFont(font);

    // Native Fusion controls retain keyboard/accessibility behavior; the
    // shared palette also reaches custom-painted views and modal dialogs.
    application.setStyleSheet(QStringLiteral(R"(
        QMainWindow, QDialog { background: %1; }
        QMainWindow::separator { background: %3; width: 4px; height: 4px; }
        QMainWindow::separator:hover, QSplitter::handle:hover { background: %5; }
        QToolBar { background: %2; border: 0; border-bottom: 1px solid %3; spacing: 6px; padding: 5px; }
        QToolBar::separator { background: %3; width: 1px; margin: 5px; }
        QToolButton, QPushButton { background: %2; border: 1px solid %3; border-radius: 3px; padding: 5px 9px; }
        QToolButton#qt_toolbar_ext_button { padding: 0; border: 0; qproperty-icon: url(:/workbench/down.svg); }
        QToolButton:hover, QPushButton:hover { background: %3; border-color: %5; }
        QToolButton:pressed, QPushButton:pressed, QToolButton:checked, QPushButton:checked { background: %4; }
        QPushButton:default { border-color: %5; }
        QPushButton#matchingRun:enabled { background: %4; border-color: %5; font-weight: 600; }
        QPushButton:disabled, QToolButton:disabled { color: %6; border-color: %2; }
        QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
            background: %1; border: 1px solid %3; border-radius: 3px; padding: 5px 7px;
            selection-background-color: %4;
        }
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border-color: %5; }
        QComboBox::drop-down { border: 0; width: 20px; }
        QComboBox::down-arrow, QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
            image: url(:/workbench/down.svg); width: 12px; height: 12px;
        }
        QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
            image: url(:/workbench/up.svg); width: 12px; height: 12px;
        }
        QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
            background: %2; border-left: 1px solid %3; width: 18px;
        }
        QComboBox QAbstractItemView { background: %1; selection-background-color: %4; }
        QAbstractItemView { background: %1; alternate-background-color: %1; border: 0;
            selection-background-color: %4; selection-color: %7; outline: 0; }
        QAbstractItemView::item { padding: 3px 4px; }
        QAbstractItemView::item:hover { background: %3; }
        QAbstractItemView::item:selected { background: %4; color: %7; }
        QHeaderView::section { background: %2; color: %6; border: 0;
            border-right: 1px solid %3; border-bottom: 1px solid %3; padding: 6px; font-weight: 600; }
        QTableCornerButton::section { background: %2; border: 0; }
        QDockWidget::title { background: %2; color: %7; padding: 7px 8px; border-bottom: 1px solid %3; }
        QDockWidget::close-button, QDockWidget::float-button { border: 0; padding: 2px; }
        QDockWidget::close-button { image: url(:/workbench/close.svg); }
        QDockWidget::float-button { image: url(:/workbench/float.svg); }
        QDockWidget::close-button:hover, QDockWidget::float-button:hover { background: %4; }
        QTabWidget::pane { border: 1px solid %3; background: %1; }
        QTabBar::tab { background: %2; color: %6; padding: 8px 12px; border-bottom: 2px solid transparent; }
        QTabBar::tab:selected { background: %1; color: %7; border-bottom-color: %5; }
        QTabBar::tab:hover { color: %7; background: %3; }
        QMenuBar { background: %2; border-bottom: 1px solid %3; }
        QMenuBar::item { padding: 6px 10px; background: transparent; }
        QMenuBar::item:selected, QMenu::item:selected { background: %4; }
        QMenu { background: %2; border: 1px solid %3; padding: 5px; }
        QMenu::item { padding: 6px 28px 6px 12px; }
        QMenu::separator { height: 1px; background: %3; margin: 5px; }
        QStatusBar { background: %2; border-top: 1px solid %3; color: %6; padding: 3px; }
        QStatusBar::item { border: 0; }
        QPlainTextEdit, QTextEdit { background: %1; color: %7; border: 1px solid %3; selection-background-color: %4; }
        QPlainTextEdit:focus, QTextEdit:focus { border-color: %5; }
        QScrollBar:vertical { background: %1; width: 12px; margin: 0; }
        QScrollBar:horizontal { background: %1; height: 12px; margin: 0; }
        QScrollBar::handle { background: %3; border-radius: 4px; min-height: 24px; min-width: 24px; }
        QScrollBar::handle:hover { background: %6; }
        QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
        QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
        QGroupBox { border: 1px solid %3; border-radius: 3px; margin-top: 10px; padding-top: 10px; }
        QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; color: %6; }
        QToolTip { background: %2; color: %7; border: 1px solid %5; padding: 6px; }
        QLabel#viewHeading { color: %6; font-weight: 600; padding: 4px 8px; }
    )")
                                  .arg(t.background.name(), t.node_fill.name(), t.cursor_line.name(),
                                       t.highlight.name(), t.function_name.name(), t.empty_text.name(),
                                       t.operands.name()));
}

const QFont &Theme::codeFont() {
    static const QFont font = []() {
        QFont value = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        value.setPointSizeF(11);
        return value;
    }();
    return font;
}
