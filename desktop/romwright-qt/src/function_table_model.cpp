#include "function_table_model.h"

#include "core_bridge.h"
#include "json_util.h"
#include <QPointer>
#include <limits>

FunctionTableModel::FunctionTableModel(CoreBridge *bridge, QObject *parent)
    : QAbstractTableModel(parent), bridge_(bridge) {}

int FunctionTableModel::rowCount(const QModelIndex &parent) const {
    return parent.isValid() ? 0
                           : static_cast<int>(qMin(total_, qint64{std::numeric_limits<int>::max()}));
}

int FunctionTableModel::columnCount(const QModelIndex &parent) const { return parent.isValid() ? 0 : 4; }

QVariant FunctionTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
        return {};
    }
    static const QStringList labels = {QStringLiteral("Address"), QStringLiteral("Name"),
                                       QStringLiteral("Size"), QStringLiteral("Signature")};
    return labels.value(section);
}

QVariant FunctionTableModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= rowCount() || role != Qt::DisplayRole)
        return {};
    const auto *view = cachedRow(index.row());
    if (!view) {
        const int page = index.row() / page_size_ * page_size_;
        if (!failed_pages_.contains(page))
            const_cast<FunctionTableModel *>(this)->requestPage(page);
        return index.column() == 1
                   ? QVariant(failed_pages_.contains(page) ? QStringLiteral("Page unavailable")
                                                          : QStringLiteral("Loading…"))
                   : QVariant();
    }
    switch (index.column()) {
    case 0:
        return view->address;
    case 1:
        return view->name;
    case 2:
        return view->size;
    case 3:
        return view->signature;
    default:
        return {};
    }
}

const FunctionRowView *FunctionTableModel::cachedRow(int row) const {
    const int offset = row / page_size_ * page_size_;
    const auto page = pages_.constFind(offset);
    if (row < 0 || page == pages_.cend() || row - offset >= page->size())
        return nullptr;
    touchPage(offset);
    return &page->at(row - offset);
}

int FunctionTableModel::cachedAddress(const QString &address) const {
    for (auto page = pages_.cbegin(); page != pages_.cend(); ++page) {
        for (int row = 0; row < page->size(); ++row) {
            if (sameAddress(page->at(row).address, address)) {
                touchPage(page.key());
                return page.key() + row;
            }
        }
    }
    return -1;
}

void FunctionTableModel::touchPage(int offset) const {
    if (!recent_pages_.isEmpty() && recent_pages_.last() == offset)
        return;
    recent_pages_.removeAll(offset);
    recent_pages_.append(offset);
}

void FunctionTableModel::seekAddress(const QString &address, bool reveal) {
    if (anchor_address_ != address) {
        anchor_address_ = address;
        anchor_resolved_ = false;
        anchor_row_ = -1;
        pending_anchor_.clear();
        ++seek_generation_;
    }
    if (address.isEmpty()) {
        emit addressResolved(address, -1, reveal);
        return;
    }
    if (!anchor_resolved_) {
        anchor_row_ = cachedAddress(address);
        anchor_resolved_ = anchor_row_ >= 0;
    }
    if (anchor_resolved_) {
        emit addressResolved(address, anchor_row_, reveal);
        return;
    }
    requestPage(0, address, reveal);
}

void FunctionTableModel::setFilter(const QString &filter) {
    if (filter_ == filter) {
        return;
    }
    filter_ = filter;
    refresh(true);
}

QString FunctionTableModel::filter() const { return filter_; }

void FunctionTableModel::sort(int column, Qt::SortOrder order) {
    if (column < 0 || column > 2 || (sort_column_ == column && sort_order_ == order))
        return;
    sort_column_ = column;
    sort_order_ = order;
    refresh(true);
}

Qt::ItemFlags FunctionTableModel::flags(const QModelIndex &index) const {
    Qt::ItemFlags result = QAbstractTableModel::flags(index);
    if (index.isValid() && index.column() == 1 && cachedRow(index.row()))
        result |= Qt::ItemIsEditable;
    return result;
}

bool FunctionTableModel::setData(const QModelIndex &index, const QVariant &value, int role) {
    if (role != Qt::EditRole || !index.isValid() || index.column() != 1)
        return false;
    const auto *row = cachedRow(index.row());
    const QString name = value.toString().trimmed();
    if (!row || name.isEmpty())
        return false;
    emit renameRequested(row->address, name);
    return true;
}

void FunctionTableModel::setProgram(const QString &program) {
    if (program_ != program)
        anchor_address_.clear();
    program_ = program;
    refresh();
}

QString FunctionTableModel::program() const { return program_; }
qint64 FunctionTableModel::total() const { return total_; }
qint64 FunctionTableModel::revision() const { return revision_; }

void FunctionTableModel::refresh(bool reveal) {
    ++generation_;
    ++seek_generation_;
    beginResetModel();
    pages_.clear();
    recent_pages_.clear();
    pending_pages_.clear();
    failed_pages_.clear();
    pending_anchor_.clear();
    anchor_resolved_ = false;
    anchor_row_ = -1;
    total_ = 0;
    revision_ = 0;
    endResetModel();
    requestPage(0, anchor_address_, reveal);
}

void FunctionTableModel::requestPage(int offset, const QString &anchor, bool reveal) {
    if (program_.isEmpty())
        return;
    if (anchor.isEmpty()) {
        if (pages_.contains(offset) || pending_pages_.contains(offset) || failed_pages_.contains(offset))
            return;
        pending_pages_.insert(offset);
    } else {
        if (pending_anchor_ == anchor) {
            anchor_reveal_ |= reveal;
            return;
        }
        pending_anchor_ = anchor;
        anchor_reveal_ = reveal;
    }
    const quint64 generation = generation_, seek = seek_generation_;
    static const char *sort_keys[] = {"entry", "name", "size"};
    const QString sort = QString::fromLatin1(sort_keys[sort_column_]) +
                         (sort_order_ == Qt::AscendingOrder ? QStringLiteral(":asc")
                                                           : QStringLiteral(":desc"));
    QJsonObject request{{"method", "functions_page"}, {"program", program_},
                        {"offset", offset}, {"limit", page_size_}, {"sort", sort}};
    if (!filter_.isEmpty())
        request["filter"] = filter_;
    if (!anchor.isEmpty())
        request["address"] = anchor;
    bridge_->request(request, [this, guard = QPointer<FunctionTableModel>(this),
                               generation, seek, offset, anchor](const QJsonObject &response) {
        if (!guard || generation != generation_ || (!anchor.isEmpty() && seek != seek_generation_))
            return;
        if (anchor.isEmpty())
            pending_pages_.remove(offset);
        else
            pending_anchor_.clear();
        QString error;
        if (!successful(response, &error)) {
            if (anchor.isEmpty())
                failed_pages_.insert(offset);
            else
                emit addressResolved(anchor, -1, anchor_reveal_);
            emit requestError(error);
            return;
        }
        const QJsonObject result = response.value("result").toObject();
        const qint64 start = result.value("offset").toVariant().toLongLong();
        if (start < 0 || start > std::numeric_limits<int>::max()) {
            emit requestError(QStringLiteral("Function index exceeds desktop row capacity"));
            return;
        }
        const qint64 revision = result.value("revision").toVariant().toLongLong();
        const bool changed = revision_ != 0 && revision_ != revision;
        if (changed) {
            ++generation_;
            pages_.clear();
            recent_pages_.clear();
            pending_pages_.clear();
            failed_pages_.clear();
            pending_anchor_.clear();
            anchor_resolved_ = false;
            anchor_row_ = -1;
        }
        const QJsonArray incoming = result.value("rows").toArray();
        QVector<FunctionRowView> page;
        page.reserve(incoming.size());
        for (const auto &row : incoming)
            page.append(FunctionRowView::fromJson(row.toObject()));
        const int first = static_cast<int>(start);
        const int count = page.size();
        const qint64 total = qMax(qint64{0}, result.value("total").toVariant().toLongLong());
        const int old_count = rowCount();
        const int new_count = static_cast<int>(qMin(total, qint64{std::numeric_limits<int>::max()}));
        if (new_count > old_count)
            beginInsertRows({}, old_count, new_count - 1);
        else if (new_count < old_count)
            beginRemoveRows({}, new_count, old_count - 1);
        total_ = total;
        revision_ = revision;
        pages_.insert(first, std::move(page));
        touchPage(first);
        while (recent_pages_.size() > cached_pages_)
            pages_.remove(recent_pages_.takeFirst());
        if (new_count > old_count)
            endInsertRows();
        else if (new_count < old_count)
            endRemoveRows();
        if (changed && new_count > 0)
            emit dataChanged(index(0, 0), index(new_count - 1, 3));
        else if (count > 0 && first < new_count)
            emit dataChanged(index(first, 0), index(first + qMin(count, new_count - first) - 1, 3));
        if (!anchor.isEmpty()) {
            anchor_row_ = cachedAddress(anchor);
            anchor_resolved_ = true;
            emit addressResolved(anchor, anchor_row_, anchor_reveal_);
        } else if (changed && !anchor_address_.isEmpty()) {
            seekAddress(anchor_address_, false);
        }
        emit refreshed();
    });
}
