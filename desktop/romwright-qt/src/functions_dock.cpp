#include "functions_dock.h"

#include "core_bridge.h"
#include "function_table_model.h"
#include "json_util.h"

#include <QHeaderView>
#include <QLineEdit>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>

FunctionsDock::FunctionsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Functions"), parent) {
    setObjectName(QStringLiteral("functionsDock"));
    setMinimumWidth(260);

    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 0, 0);

    filter_edit_ = new QLineEdit(panel);
    filter_edit_->setObjectName(QStringLiteral("functionFilterEdit"));
    filter_edit_->setPlaceholderText(QStringLiteral("Filter (substring, or re: for regex)"));

    filter_timer_ = new QTimer(filter_edit_);
    filter_timer_->setSingleShot(true);
    filter_timer_->setInterval(250);

    connect(filter_edit_, &QLineEdit::textChanged, filter_timer_, qOverload<>(&QTimer::start));
    connect(filter_timer_, &QTimer::timeout, this, [this]() { model_->setFilter(filter_edit_->text()); });

    layout->addWidget(filter_edit_);

    table_view_ = new QTableView(panel);
    table_view_->setObjectName(QStringLiteral("functionsView"));
    model_ = new FunctionTableModel(bridge, table_view_);
    table_view_->setModel(model_);

    table_view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_view_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_view_->horizontalHeader()->setStretchLastSection(false);
    table_view_->setColumnWidth(0, 100);
    table_view_->setColumnWidth(1, 210);
    table_view_->setColumnWidth(2, 64);
    table_view_->setColumnWidth(3, 260);
    table_view_->verticalHeader()->setVisible(false);
    table_view_->setAlternatingRowColors(true);
    table_view_->setSortingEnabled(true);
    table_view_->sortByColumn(0, Qt::AscendingOrder);

    connect(table_view_, &QTableView::activated, this, [this](const QModelIndex &index) {
        const QString addr = model_->data(model_->index(index.row(), 0)).toString();
        if (!addr.isEmpty()) {
            emit addressSelected(addr, true);
        }
    });
    connect(model_, &FunctionTableModel::addressResolved, this,
            [this](const QString &entry, int row, bool reveal) {
        if (entry != function_address_)
            return;
        if (row < 0) {
            table_view_->clearSelection();
            table_view_->setCurrentIndex({});
            return;
        }
        const auto index = model_->index(row, 0);
        table_view_->selectionModel()->setCurrentIndex(
            index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        if (reveal)
            table_view_->scrollTo(index, QAbstractItemView::EnsureVisible);
    });

    layout->addWidget(table_view_, 1);
    setWidget(panel);
}

void FunctionsDock::setProgram(const QString &program) {
    function_address_.clear();
    model_->setProgram(program);
}

void FunctionsDock::setFilter(const QString &filter) {
    filter_edit_->setText(filter);
    model_->setFilter(filter);
}

void FunctionsDock::setFunction(const FunctionRowView &function, const QString &cursor) {
    if (function_address_ != function.address) {
        table_view_->clearSelection();
        table_view_->setCurrentIndex({});
    }
    function_address_ = function.address;
    model_->seekAddress(function_address_);
    if (function_address_.isEmpty()) {
        emit functionContextChanged(cursor, cursor);
        return;
    }
    QString name = function.name;
    bool cursor_ok = false, entry_ok = false;
    const auto offset = cursor.toULongLong(&cursor_ok, 16);
    const auto entry = function.address.toULongLong(&entry_ok, 16);
    if (cursor_ok && entry_ok && offset > entry)
        name += QStringLiteral("+0x%1").arg(offset - entry, 0, 16);
    emit functionContextChanged(cursor, name);
}
