#pragma once

#include <QVector>
#include <QWidget>

#include "views.h"

class QKeyEvent;
class QMouseEvent;
class QContextMenuEvent;
class QResizeEvent;
class QScrollBar;

/// Paint-based, virtualized listing view over the core-007 listing-window
/// API. The canvas holds one window of rows (window + overscan); the
/// cursor is the current address. Window refetches and navigation flow
/// through the window owner via signals — the canvas never talks to the
/// bridge or to other docks.
class ListingCanvas final : public QWidget {
    Q_OBJECT

  public:
    explicit ListingCanvas(QWidget *parent = nullptr);

    /// Replaces the visible window; an empty result displays the supplied state.
    void setWindow(const QVector<ListingRowView> &rows,
                   const QString &emptyMessage = QStringLiteral("No instructions at this address"));
    /// Resets the window and pending address when the program context changes.
    void clear();
    /// Highlights the row at `address`; requests a window recentered there
    /// when the address is outside the current window.
    void setAddress(const QString &address);
    void setFunctionName(const QString &address, const QString &name);
    QString currentAddress() const;
    void setBytesVisible(bool on);
    bool bytesVisible() const;
    QSize sizeHint() const override;

  signals:
    /// Emitted for every navigation the canvas initiates (click, keyboard,
    /// operand jump). `record` feeds the history stack.
    void addressSelected(const QString &address, bool record);
    /// The cursor needs rows around `start_address`.
    void windowNeeded(const QString &start_address);
    void backRequested();
    void forwardRequested();
    /// Right-click at a row address; the owner builds the menu.
    void contextMenuRequested(const QPoint &global_pos, const QString &address);

  protected:
    void paintEvent(QPaintEvent *) override;
    void wheelEvent(QWheelEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseDoubleClickEvent(QMouseEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;

  private:
    int rowHeight() const;
    int visibleRows() const;
    int cursorIndex() const;
    void moveCursor(int delta, bool record);
    void ensureWindowAround(int index);
    void revealCursor();
    void updateContentWidth();
    void updateScrollRange();
    QString addressAt(int row) const;
    QString operandTokenAt(int row, const QPoint &pos) const;

    QVector<ListingRowView> rows_;
    int cursor_ = -1;
    int first_visible_ = 0;
    QString requested_address_;
    QString empty_message_ = QStringLiteral("No listing loaded");
    bool bytes_visible_ = true;
    int address_columns_ = 10;
    int byte_columns_ = 0;
    int content_width_ = 0;
    QScrollBar *horizontal_scroll_;
};
