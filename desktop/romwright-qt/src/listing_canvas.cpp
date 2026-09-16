#include "listing_canvas.h"

#include "json_util.h"
#include "theme.h"
#include <QContextMenuEvent>

#include <QFontDatabase>
#include <QKeyEvent>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QRegularExpression>
 #include <QResizeEvent>
 #include <QScrollBar>
#include <QWheelEvent>

namespace {

constexpr int kMargin = 8;

/// Returns the hex token of `text` spanning character column `column`,
/// or empty when the click is not on an address-like token.
QString hexTokenAtColumn(const QString &text, int column) {
    static const QRegularExpression address(QStringLiteral("\\b0[xX][0-9a-fA-F]+\\b"));
    auto matches = address.globalMatch(text);
    while (matches.hasNext()) {
        const auto match = matches.next();
        if (column >= match.capturedStart() && column < match.capturedEnd())
            return match.captured();
    }
    return {};
}

bool isSelectableRow(const ListingRowView &row) {
    return row.kind == QStringLiteral("instruction") || row.kind == QStringLiteral("data") ||
           row.kind == QStringLiteral("label");
}

} // namespace

ListingCanvas::ListingCanvas(QWidget *parent)
    : QWidget(parent), horizontal_scroll_(new QScrollBar(Qt::Horizontal, this)) {
    horizontal_scroll_->setRange(0, 0);
    horizontal_scroll_->setAccessibleName(QStringLiteral("Listing horizontal scroll"));
    horizontal_scroll_->setSingleStep(
        QFontMetrics(Theme::codeFont()).horizontalAdvance(QLatin1Char('0')) * 3);
    horizontal_scroll_->hide();
    connect(horizontal_scroll_, &QScrollBar::valueChanged, this, [this]() { update(); });
    setMinimumHeight(180);
    setAccessibleName(QStringLiteral("Disassembly"));
    setAccessibleDescription(empty_message_);
    setFocusPolicy(Qt::StrongFocus);
    setFocus();
}

void ListingCanvas::setWindow(const QVector<ListingRowView> &rows, const QString &emptyMessage) {
    rows_ = rows;
    empty_message_ = rows_.isEmpty() ? emptyMessage : QString{};
    setAccessibleDescription(empty_message_);
    cursor_ = -1;
    first_visible_ = 0;
    address_columns_ = 10;
    byte_columns_ = 0;
    for (const auto &row : rows_) {
        address_columns_ = qMax(address_columns_, int(row.address.size()));
        byte_columns_ = qMax(byte_columns_, int(row.bytes.size()));
    }
    updateContentWidth();
    update();
}

void ListingCanvas::clear() {
    requested_address_.clear();
    setWindow({}, QStringLiteral("No listing loaded"));
}

void ListingCanvas::setAddress(const QString &address) {
    if (address.isEmpty())
        return;
    // Structural rows share addresses with instructions; select code first.
    for (int pass = 0; pass < 2; ++pass) {
        for (int i = 0; i < rows_.size(); ++i) {
            const auto &row = rows_.at(i);
            if (sameAddress(row.address, address) &&
                (pass == 1 || row.kind == QStringLiteral("instruction"))) {
                cursor_ = i;
                requested_address_.clear();
                revealCursor();
                update();
                return;
            }
        }
    }
    cursor_ = -1;
    update();
    if (!sameAddress(requested_address_, address)) {
        requested_address_ = address;
        emit windowNeeded(address);
    }
}

void ListingCanvas::setFunctionName(const QString &address, const QString &name) {
    for (auto &row : rows_) {
        if (row.kind == QStringLiteral("function_header") && sameAddress(row.address, address))
            row.text = name;
    }
    updateContentWidth();
    update();
}

QString ListingCanvas::currentAddress() const {
    return cursorIndex() >= 0 ? addressAt(cursorIndex()) : QString();
}

void ListingCanvas::setBytesVisible(bool on) {
    bytes_visible_ = on;
    updateContentWidth();
    update();
}

bool ListingCanvas::bytesVisible() const { return bytes_visible_; }

QSize ListingCanvas::sizeHint() const { return {640, 260}; }

int ListingCanvas::rowHeight() const {
    QFontMetrics metrics(Theme::codeFont());
    return metrics.lineSpacing();
}

int ListingCanvas::visibleRows() const {
    const int scroll_height = horizontal_scroll_->maximum() > 0 ? horizontal_scroll_->height() : 0;
    return qMax(0, (height() - scroll_height - 2 * kMargin) / rowHeight());
}

void ListingCanvas::updateContentWidth() {
    const QFontMetrics metrics(Theme::codeFont());
    const int char_width = metrics.horizontalAdvance(QLatin1Char('0'));
    const int text_start = kMargin + address_columns_ * char_width + 8 +
                           (bytes_visible_ ? (byte_columns_ + 2) * char_width : 0);
    content_width_ = 0;
    for (const auto &row : rows_) {
        int row_width;
        if (row.kind == QStringLiteral("function_header")) {
            row_width = kMargin + metrics.horizontalAdvance(QStringLiteral("Function  @ ")) +
                        metrics.horizontalAdvance(row.text) + metrics.horizontalAdvance(row.address);
        } else if (row.kind == QStringLiteral("bb_separator")) {
            row_width = kMargin + metrics.horizontalAdvance(QStringLiteral("---- basic block  ----")) +
                        metrics.horizontalAdvance(row.address);
        } else {
            row_width = text_start + metrics.horizontalAdvance(row.text) +
                        (row.kind == QStringLiteral("label") ? char_width : 0);
        }
        content_width_ = qMax(content_width_, row_width + kMargin);
    }
    updateScrollRange();
}

void ListingCanvas::updateScrollRange() {
    const int scroll_height = horizontal_scroll_->sizeHint().height();
    horizontal_scroll_->setGeometry(0, qMax(0, height() - scroll_height), width(), scroll_height);
    horizontal_scroll_->setPageStep(width());
    horizontal_scroll_->setRange(0, qMax(0, content_width_ - width()));
    horizontal_scroll_->setVisible(horizontal_scroll_->maximum() > 0);
    revealCursor();
}

void ListingCanvas::resizeEvent(QResizeEvent *event) {
    QWidget::resizeEvent(event);
    updateScrollRange();
}

int ListingCanvas::cursorIndex() const { return cursor_; }

QString ListingCanvas::addressAt(int row) const {
    return row >= 0 && row < rows_.size() ? rows_.at(row).address : QString();
}

void ListingCanvas::moveCursor(int delta, bool record) {
    if (rows_.isEmpty() || delta == 0) {
        return;
    }
    const int direction = delta < 0 ? -1 : 1;
    int remaining = delta < 0 ? -delta : delta;
    int target = cursor_;
    if (target < 0) {
        target = direction > 0 ? -1 : rows_.size();
    }
    while (remaining-- > 0) {
        int next = target;
        do {
            next += direction;
        } while (next >= 0 && next < rows_.size() && !isSelectableRow(rows_.at(next)));
        if (next < 0 || next >= rows_.size())
            break;
        target = next;
    }
    if (target < 0 || target >= rows_.size()) {
        return;
    }
    if (target == cursor_) {
        return;
    }
    cursor_ = target;
    revealCursor();
    emit addressSelected(addressAt(cursor_), record);
    ensureWindowAround(cursor_);
    update();
}

void ListingCanvas::ensureWindowAround(int index) {
    // Refill forward; moving Up must not discard the rows above the cursor.
    if (rows_.size() > visibleRows() && index > rows_.size() - visibleRows())
        emit windowNeeded(addressAt(index));
}

void ListingCanvas::revealCursor() {
    if (cursor_ < first_visible_)
        first_visible_ = qMax(0, cursor_);
    else if (cursor_ >= first_visible_ + visibleRows())
        first_visible_ = qMax(0, cursor_ - visibleRows() + 1);
}

void ListingCanvas::paintEvent(QPaintEvent *) {
    QPainter painter(this);
    painter.fillRect(rect(), Theme::current().background);
    painter.setFont(Theme::codeFont());
    const QFontMetrics metrics = painter.fontMetrics();
    const int line = rowHeight();
    const int char_w = metrics.horizontalAdvance(QLatin1Char('0'));
    const int scroll = horizontal_scroll_->value();
    painter.translate(-scroll, 0);
    const int first = first_visible_;
    int y = kMargin + metrics.ascent();
    for (int i = first; i < rows_.size() && i < first + visibleRows(); ++i, y += line) {
        const ListingRowView &row = rows_.at(i);
        if (i == cursorIndex()) {
            painter.fillRect(QRect(scroll, y - metrics.ascent(), width(), line),
                             Theme::current().cursor_line);
        }
        if (row.kind == QStringLiteral("function_header")) {
            painter.setPen(Theme::current().function_name);
            painter.drawText(kMargin, y, QStringLiteral("Function %1 @ %2").arg(row.text, row.address));
            continue;
        }
        if (row.kind == QStringLiteral("bb_separator")) {
            painter.setPen(Theme::current().empty_text);
            painter.drawText(kMargin, y, QStringLiteral("---- basic block %1 ----").arg(row.address));
            continue;
        }
        int x = kMargin;
        painter.setPen(Theme::current().address_column);
        painter.drawText(x, y, row.address);
        x += address_columns_ * char_w + 8;
        if (bytes_visible_) {
            painter.setPen(Theme::current().bytes_column);
            painter.drawText(x, y, row.bytes);
            x += (byte_columns_ + 2) * char_w;
        }
        // Syntax coloring: mnemonic vs operands, jump targets highlighted.
        if (row.kind == QStringLiteral("label")) {
            painter.setPen(Theme::current().jump_target);
            painter.drawText(x, y, row.text + QLatin1Char(':'));
            continue;
        }
        if (row.kind == QStringLiteral("data")) {
            painter.setPen(Theme::current().bytes_column);
            painter.drawText(x, y, row.text);
            continue;
        }
        const QString text = row.text;
        const int mnemonic_end = text.indexOf(QLatin1Char(' '));
        painter.setPen(Theme::current().mnemonic);
        painter.drawText(x, y, mnemonic_end < 0 ? text : text.left(mnemonic_end));
        if (mnemonic_end >= 0) {
            const QString operands = text.mid(mnemonic_end + 1);
            int ox = x + (mnemonic_end + 1) * char_w;
            int token_begin = 0;
            for (int c = 0; c <= operands.size(); ++c) {
                const bool token_end = c == operands.size() || operands[c].isSpace();
                if (!token_end) {
                    continue;
                }
                const QString token = operands.mid(token_begin, c - token_begin);
                bool is_hex = false;
                token.toULongLong(&is_hex, 16);
                painter.setPen(token.startsWith(QStringLiteral("0x")) && is_hex ? Theme::current().jump_target
                                                                                : Theme::current().operands);
                painter.drawText(ox, y, token);
                ox += (token.size() + 1) * char_w;
                token_begin = c + 1;
            }
        }
    }
    if (rows_.isEmpty()) {
        painter.setPen(Theme::current().empty_text);
        painter.drawText(rect().adjusted(kMargin, kMargin, -kMargin, -kMargin),
                         Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, empty_message_);
    }
}

void ListingCanvas::wheelEvent(QWheelEvent *event) {
    const bool horizontal = event->pixelDelta().x() != 0 || event->angleDelta().x() != 0;
    if (horizontal || event->modifiers() & Qt::ShiftModifier) {
        const int pixels = horizontal ? event->pixelDelta().x() : event->pixelDelta().y();
        const int angle = horizontal ? event->angleDelta().x() : event->angleDelta().y();
        const int delta = pixels != 0 ? pixels : angle * horizontal_scroll_->singleStep() / 120;
        horizontal_scroll_->setValue(horizontal_scroll_->value() - delta);
        event->accept();
        return;
    }
    const int delta = event->angleDelta().y();
    if (delta != 0)
        moveCursor(delta > 0 ? -3 : 3, false);
    event->accept();
}

void ListingCanvas::keyPressEvent(QKeyEvent *event) {
    const int page = qMax(1, visibleRows() - 1);
    switch (event->key()) {
    case Qt::Key_Left:
        horizontal_scroll_->setValue(horizontal_scroll_->value() - horizontal_scroll_->singleStep());
        break;
    case Qt::Key_Right:
        horizontal_scroll_->setValue(horizontal_scroll_->value() + horizontal_scroll_->singleStep());
        break;
    case Qt::Key_Up:
        moveCursor(-1, true);
        break;
    case Qt::Key_Down:
        moveCursor(1, true);
        break;
    case Qt::Key_PageUp:
        moveCursor(-page, true);
        break;
    case Qt::Key_PageDown:
        moveCursor(page, true);
        break;
    case Qt::Key_Home:
        moveCursor(-rows_.size(), true);
        break;
    case Qt::Key_End:
        moveCursor(rows_.size(), true);
        break;
    case Qt::Key_Escape:
        emit backRequested();
        break;
    case Qt::Key_BracketLeft:
        if (event->modifiers() & Qt::ControlModifier) {
            emit backRequested();
        }
        break;
    case Qt::Key_BracketRight:
        if (event->modifiers() & Qt::ControlModifier) {
            emit forwardRequested();
        }
        break;
    default:
        QWidget::keyPressEvent(event);
        return;
    }
    event->accept();
}

void ListingCanvas::mousePressEvent(QMouseEvent *event) {
    if (event->button() != Qt::LeftButton || event->position().y() < kMargin)
        return;
    const int row = first_visible_ + (event->position().y() - kMargin) / rowHeight();
    if (row < 0 || row >= rows_.size() || !isSelectableRow(rows_.at(row)))
        return;
    cursor_ = row;
    emit addressSelected(addressAt(row), true);
    update();
    event->accept();
}

void ListingCanvas::mouseDoubleClickEvent(QMouseEvent *event) {
    if (event->button() != Qt::LeftButton || event->position().y() < kMargin)
        return;
    const int row = first_visible_ + (event->position().y() - kMargin) / rowHeight();
    const QString target = operandTokenAt(row, event->position().toPoint());
    if (!target.isEmpty())
        emit addressSelected(target, true);
    event->accept();
}

QString ListingCanvas::operandTokenAt(int row, const QPoint &pos) const {
    if (row < 0 || row >= rows_.size())
        return {};
    const QFontMetrics metrics(Theme::codeFont());
    const int char_width = metrics.horizontalAdvance(QLatin1Char('0'));
    int text_x = kMargin + address_columns_ * char_width + 8;
    if (bytes_visible_)
        text_x += (byte_columns_ + 2) * char_width;
    const int content_x = pos.x() + horizontal_scroll_->value();
    if (content_x < text_x)
        return {};
    return hexTokenAtColumn(rows_.at(row).text, (content_x - text_x) / char_width);
}

void ListingCanvas::contextMenuEvent(QContextMenuEvent *event) {
    const int line = rowHeight();
    const int first = first_visible_;
    const int row = first + (event->pos().y() - kMargin) / line;
    if (row < 0 || row >= rows_.size()) {
        return;
    }
    cursor_ = row;
    update();
    emit contextMenuRequested(event->globalPos(), addressAt(row));
}
