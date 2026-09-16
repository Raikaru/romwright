#pragma once

#include <QAbstractTableModel>

#include "views.h"
#include <QHash>
#include <QList>
#include <QSet>
class CoreBridge;

/// Paged model over the functions_page core request. Rows are fetched in
/// windows of page_size_ as the view scrolls; the full function list is
/// never materialized.
class FunctionTableModel final : public QAbstractTableModel {
    Q_OBJECT

public:
    explicit FunctionTableModel(CoreBridge *bridge, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    void setProgram(const QString &program);
    QString program() const;
    qint64 total() const;
    qint64 revision() const;
    void refresh(bool reveal = false);
    /// Resolves a function directly under the active filter and ordering.
    void seekAddress(const QString &address, bool reveal = true);

    /// Server-side name filter: case-insensitive substring, or regex when
    /// the text carries a `re:` prefix. Empty text clears the filter.
    void setFilter(const QString &filter);
    QString filter() const;

    /// Header-driven sort; column 3 (signature) is not sortable.
    void sort(int column, Qt::SortOrder order) override;

    /// Column 1 (name) is editable in place; the actual rename command is
    /// issued by the window via renameRequested so the undo journal and
    /// job list stay in one place.
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    bool setData(const QModelIndex &index, const QVariant &value,
                 int role = Qt::EditRole) override;

signals:
    void requestError(const QString &message);
    void refreshed();
    void renameRequested(const QString &address, const QString &name);
    void addressResolved(const QString &address, int row, bool reveal);

private:
    void requestPage(int offset, const QString &anchor = {}, bool reveal = false);
    const FunctionRowView *cachedRow(int row) const;
    int cachedAddress(const QString &address) const;
    void touchPage(int offset) const;

    CoreBridge *bridge_;
    QString program_;
    QString filter_;
    int sort_column_ = 0;
    Qt::SortOrder sort_order_ = Qt::AscendingOrder;
    qint64 total_ = 0;
    qint64 revision_ = 0;
    QHash<int, QVector<FunctionRowView>> pages_;
    mutable QList<int> recent_pages_;
    QSet<int> pending_pages_;
    QSet<int> failed_pages_;
    QString anchor_address_;
    QString pending_anchor_;
    int anchor_row_ = -1;
    bool anchor_resolved_ = false;
    bool anchor_reveal_ = false;
    quint64 generation_ = 0;
    quint64 seek_generation_ = 0;
    static constexpr int page_size_ = 256;
    static constexpr int cached_pages_ = 8;
};
