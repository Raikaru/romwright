#include "decompiler_view.h"
#include "theme.h"

#include <QAction>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QMimeData>
#include <QMouseEvent>
#include <QPainter>
#include <QScopedValueRollback>
#include <QTextBlock>
#include <QTextLayout>
#include <algorithm>

namespace {
QColor colorForKind(const QString &kind) {
    if (kind == "Variable")
        return Theme::current().variable;
    if (kind == "FuncName")
        return Theme::current().function_name;
    if (kind == "Op" || kind == "Syntax")
        return Theme::current().operator_;
    if (kind == "Keyword" || kind == "Type")
        return Theme::current().keyword;
    if (kind == "Hint")
        return Theme::current().empty_text;
    return Theme::current().operands;
}
} // namespace

class SourceGutter final : public QWidget {
  public:
    explicit SourceGutter(DecompilerView *view) : QWidget(view), view_(view) {
        setObjectName("sourceGutter");
        setToolTip("Line numbers; click a block marker to fold or unfold. Ctrl+Shift+[ folds; "
                   "Ctrl+Shift+] expands all.");
    }

  protected:
    void paintEvent(QPaintEvent *event) override { view_->paintGutter(event); }
    void mousePressEvent(QMouseEvent *event) override { view_->clickGutter(event->pos()); }

  private:
    DecompilerView *view_;
};

DecompilerView::DecompilerView(QWidget *parent)
    : QPlainTextEdit(parent), gutter_(new SourceGutter(this)) {
    setObjectName("decompilerView");
    setReadOnly(true);
    setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    setFocusPolicy(Qt::StrongFocus);
    setUndoRedoEnabled(false);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFont(Theme::codeFont());
    setTabStopDistance(fontMetrics().horizontalAdvance(' ') * 4);
    connect(this, &QPlainTextEdit::cursorPositionChanged, this, &DecompilerView::cursorChanged);
    connect(this, &QPlainTextEdit::blockCountChanged, this, &DecompilerView::updateGutter);
    connect(this, &QPlainTextEdit::updateRequest, gutter_,
            [this](const QRect &, int) { gutter_->update(); });
    auto *collapse = new QAction("Fold current block", this);
    collapse->setObjectName("sourceFoldBlock");
    collapse->setShortcut(QKeySequence("Ctrl+Shift+["));
    collapse->setShortcutContext(Qt::WidgetShortcut);
    addAction(collapse);
    connect(collapse, &QAction::triggered, this, [this] {
        int line = textCursor().blockNumber();
        while (line >= 0 && fold_ends_.value(line, -1) <= textCursor().blockNumber())
            --line;
        if (line >= 0)
            toggleFold(line);
    });
    auto *expand = new QAction("Expand all blocks", this);
    expand->setObjectName("sourceExpandAll");
    expand->setShortcut(QKeySequence("Ctrl+Shift+]"));
    expand->setShortcutContext(Qt::WidgetShortcut);
    addAction(expand);
    connect(expand, &QAction::triggered, this, [this] {
        folded_.clear();
        applyFolds();
    });
    auto *hints = new QAction("Argument hints", this);
    hints->setObjectName("sourceArgumentHints");
    hints->setCheckable(true);
    hints->setChecked(true);
    hints->setToolTip("Stored parameter declarations; hints are omitted from copied source.");
    addAction(hints);
    connect(hints, &QAction::toggled, this, [this](bool enabled) {
        const int line = textCursor().blockNumber();
        hints_visible_ = enabled;
        setTokens(tokens_);
        auto block = document()->findBlockByNumber(line);
        if (block.isValid())
            setTextCursor(QTextCursor(block));
    });
    updateGutter();
}

void DecompilerView::setTokens(const QVector<TokenView> &tokens) {
    QScopedValueRollback<bool> loading(loading_, true);
    tokens_ = tokens;
    spans_.clear();
    addresses_.clear();
    folded_.clear();
    highlight_address_.clear();
    QString text;
    for (int i = 0; i < tokens_.size(); ++i) {
        const auto &token = tokens_[i];
        if (token.isBreak()) {
            text += '\n';
            text += QString(static_cast<int>(token.indent), ' ');
        } else if (!token.text.isEmpty() && (hints_visible_ || token.kind != "Hint")) {
            spans_.append({static_cast<int>(text.size()), static_cast<int>(token.text.size()), i});
            if (!token.address.isEmpty())
                addresses_[token.address].append(text.size());
            text += token.text;
        }
    }
    setPlainText(text);
    auto block = document()->firstBlock();
    QVector<QTextLayout::FormatRange> formats;
    for (const auto &span : spans_) {
        while (block.isValid() && span.start >= block.position() + block.length()) {
            block.layout()->setFormats(formats);
            formats.clear();
            block = block.next();
        }
        if (!block.isValid())
            break;
        QTextCharFormat format;
        const auto &token = tokens_[span.token];
        format.setForeground(colorForKind(token.kind));
        if (token.kind == "Hint")
            format.setFontItalic(true);
        formats.append({span.start - block.position(), span.length, format});
    }
    if (block.isValid())
        block.layout()->setFormats(formats);
    findFolds(text);
    updateGutter();
    updateHighlights();
    viewport()->update();
}

void DecompilerView::setPending(const QString &message) {
    setTokens({});
    setPlaceholderText(message);
}

const TokenView *DecompilerView::tokenAtPosition(int position) const {
    auto found = std::upper_bound(spans_.cbegin(), spans_.cend(), position,
                                  [](int pos, const Span &span) { return pos < span.start; });
    if (found == spans_.cbegin())
        return nullptr;
    --found;
    if (position >= found->start + found->length)
        return nullptr;
    return &tokens_[found->token];
}

QString DecompilerView::currentAddress() const {
    if (const auto *token = tokenAtPosition(textCursor().position());
        token && !token->address.isEmpty())
        return token->address;
    const auto block = textCursor().block();
    auto found = std::lower_bound(spans_.cbegin(), spans_.cend(), block.position(),
                                  [](const Span &span, int pos) { return span.start < pos; });
    for (; found != spans_.cend() && found->start < block.position() + block.length(); ++found)
        if (!tokens_[found->token].address.isEmpty())
            return tokens_[found->token].address;
    return {};
}

void DecompilerView::cursorChanged() {
    if (loading_)
        return;
    updateHighlights();
    if (!textCursor().hasSelection()) {
        const auto address = currentAddress();
        if (!address.isEmpty())
            emit addressSelected(address, record_navigation_);
    }
}

void DecompilerView::setAddress(const QString &address) {
    highlight_address_ = address;
    const auto found = addresses_.constFind(address);
    if (found != addresses_.cend() && !found->isEmpty() && currentAddress() != address &&
        !textCursor().hasSelection()) {
        QScopedValueRollback<bool> loading(loading_, true);
        const int pos = found->first();
        const int line = document()->findBlock(pos).blockNumber();
        bool changed = false;
        for (auto it = folded_.begin(); it != folded_.end();) {
            if (*it < line && fold_ends_[*it] >= line) {
                it = folded_.erase(it);
                changed = true;
            } else
                ++it;
        }
        if (changed)
            applyFolds();
        QTextCursor cursor(document());
        cursor.setPosition(pos);
        setTextCursor(cursor);
        ensureCursorVisible();
    }
    updateHighlights();
}

void DecompilerView::updateHighlights() {
    QList<QTextEdit::ExtraSelection> selections;
    QTextEdit::ExtraSelection current;
    current.cursor = textCursor();
    current.cursor.clearSelection();
    current.format.setBackground(Theme::current().cursor_line);
    current.format.setProperty(QTextFormat::FullWidthSelection, true);
    selections.append(current);
    for (int position : addresses_.value(highlight_address_)) {
        const auto *token = tokenAtPosition(position);
        if (!token)
            continue;
        QTextEdit::ExtraSelection selection;
        selection.cursor = QTextCursor(document());
        selection.cursor.setPosition(position);
        selection.cursor.setPosition(position + token->text.size(), QTextCursor::KeepAnchor);
        selection.format.setBackground(Theme::current().highlight);
        selections.append(selection);
    }
    setExtraSelections(selections);
}

void DecompilerView::followToken() {
    const auto cursor = textCursor();
    if (const auto *token = tokenAtPosition(cursor.selectionStart());
        token && !token->function_target.isEmpty() &&
        (!cursor.hasSelection() || cursor.selectedText() == token->text))
        emit functionFollowRequested(token->function_target, true);
}

void DecompilerView::renameToken() {
    const auto cursor = textCursor();
    if (const auto *token = tokenAtPosition(cursor.selectionStart());
        token && !token->function_target.isEmpty() &&
        (!cursor.hasSelection() || cursor.selectedText() == token->text))
        emit renameRequested(token->function_target, token->text);
}

void DecompilerView::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_F2) {
        renameToken();
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_Return && event->modifiers().testFlag(Qt::ControlModifier)) {
        followToken();
        event->accept();
        return;
    }
    QPlainTextEdit::keyPressEvent(event);
}

void DecompilerView::mousePressEvent(QMouseEvent *event) {
    QScopedValueRollback<bool> record(record_navigation_, true);
    QPlainTextEdit::mousePressEvent(event);
    if (event->button() == Qt::LeftButton && event->modifiers().testFlag(Qt::ControlModifier))
        followToken();
}

void DecompilerView::contextMenuEvent(QContextMenuEvent *event) {
    if (event->reason() == QContextMenuEvent::Mouse && !textCursor().hasSelection())
        setTextCursor(cursorForPosition(event->pos()));
    auto *menu = createStandardContextMenu();
    menu->addSeparator();
    auto *follow =
        menu->addAction("Follow function (Ctrl+Enter)", this, &DecompilerView::followToken);
    auto *rename = menu->addAction("Rename function (F2)", this, &DecompilerView::renameToken);
    const auto cursor = textCursor();
    const auto *token = tokenAtPosition(cursor.selectionStart());
    follow->setEnabled(token && !token->function_target.isEmpty() &&
                       (!cursor.hasSelection() || cursor.selectedText() == token->text));
    rename->setEnabled(follow->isEnabled());
    menu->addSeparator();
    menu->addActions(actions());
    menu->exec(event->globalPos());
    delete menu;
}

QMimeData *DecompilerView::createMimeDataFromSelection() const {
    auto *mime = QPlainTextEdit::createMimeDataFromSelection();
    QString text = mime->text();
    const int first = textCursor().selectionStart(), last = textCursor().selectionEnd();
    for (auto it = spans_.crbegin(); it != spans_.crend(); ++it) {
        if (tokens_[it->token].kind != "Hint")
            continue;
        const int start = qMax(first, it->start), end = qMin(last, it->start + it->length);
        if (end > start)
            text.remove(start - first, end - start);
    }
    mime->clear();
    mime->setText(text);
    return mime;
}

void DecompilerView::findFolds(const QString &text) {
    fold_ends_.fill(-1, blockCount());
    QVector<int> stack;
    int line = 0;
    QChar quote;
    bool comment = false, line_comment = false, escaped = false;
    for (int i = 0; i < text.size(); ++i) {
        const QChar c = text[i], next = i + 1 < text.size() ? text[i + 1] : QChar();
        if (c == '\n') {
            ++line;
            line_comment = false;
        }
        if (line_comment)
            continue;
        if (comment) {
            if (c == '*' && next == '/') {
                comment = false;
                ++i;
            }
            continue;
        }
        if (!quote.isNull()) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == quote)
                quote = QChar();
            continue;
        }
        if (c == '/' && next == '*') {
            comment = true;
            ++i;
            continue;
        }
        if (c == '/' && next == '/') {
            line_comment = true;
            ++i;
            continue;
        }
        if (c == '"' || c == '\'') {
            quote = c;
            continue;
        }
        if (c == '{')
            stack.append(line);
        if (c == '}' && !stack.isEmpty()) {
            const int start = stack.takeLast();
            if (line > start)
                fold_ends_[start] = line;
        }
    }
}

void DecompilerView::toggleFold(int line) {
    if (fold_ends_.value(line, -1) <= line)
        return;
    if (folded_.contains(line))
        folded_.remove(line);
    else
        folded_.insert(line);
    const int cursor_line = textCursor().blockNumber();
    if (folded_.contains(line) && cursor_line > line && cursor_line <= fold_ends_[line])
        setTextCursor(QTextCursor(document()->findBlockByNumber(line)));
    applyFolds();
}

void DecompilerView::applyFolds() {
    QVector<int> depth_changes(blockCount() + 1, 0);
    for (int line : folded_) {
        ++depth_changes[line + 1];
        --depth_changes[fold_ends_[line] + 1];
    }
    int depth = 0;
    for (auto block = document()->begin(); block.isValid(); block = block.next()) {
        depth += depth_changes[block.blockNumber()];
        block.setVisible(depth == 0);
        block.setLineCount(depth == 0 ? 1 : 0);
    }
    document()->markContentsDirty(0, document()->characterCount());
    viewport()->update();
    gutter_->update();
}

void DecompilerView::updateGutter() {
    const int width =
        24 + fontMetrics().horizontalAdvance('9') * QString::number(qMax(1, blockCount())).size();
    setViewportMargins(width, 0, 0, 0);
    gutter_->setGeometry(contentsRect().left(), contentsRect().top(), width,
                         contentsRect().height());
    gutter_->update();
}

void DecompilerView::resizeEvent(QResizeEvent *event) {
    QPlainTextEdit::resizeEvent(event);
    updateGutter();
}

void DecompilerView::paintGutter(QPaintEvent *) {
    QPainter painter(gutter_);
    painter.fillRect(gutter_->rect(), Theme::current().background);
    painter.setFont(font());
    painter.setPen(Theme::current().empty_text);
    for (auto block = firstVisibleBlock(); block.isValid(); block = block.next()) {
        const int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
        if (top > viewport()->height())
            break;
        if (!block.isVisible())
            continue;
        const int line = block.blockNumber();
        painter.drawText(0, top, gutter_->width() - 20, fontMetrics().height(), Qt::AlignRight,
                         QString::number(line + 1));
        if (fold_ends_.value(line, -1) > line) {
            const int x = gutter_->width() - 14, y = top + fontMetrics().height() / 2;
            painter.drawRect(x - 4, y - 4, 8, 8);
            painter.drawLine(x - 2, y, x + 2, y);
            if (folded_.contains(line))
                painter.drawLine(x, y - 2, x, y + 2);
        }
    }
}

void DecompilerView::clickGutter(const QPoint &position) {
    const auto cursor = cursorForPosition(QPoint(0, position.y()));
    if (position.x() >= gutter_->width() - 20)
        toggleFold(cursor.blockNumber());
    else {
        auto selected = cursor;
        selected.select(QTextCursor::LineUnderCursor);
        setTextCursor(selected);
    }
}
