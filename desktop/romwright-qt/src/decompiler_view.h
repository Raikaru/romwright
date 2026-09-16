#pragma once

#include "views.h"
#include <QPlainTextEdit>
#include <QSet>

class SourceGutter;

/// Read-only native text editor. Token spans retain semantic navigation while
/// Qt owns selection, clipboard, accessibility and scrolling.
class DecompilerView final : public QPlainTextEdit {
    Q_OBJECT
  public:
    explicit DecompilerView(QWidget *parent = nullptr);
    void setTokens(const QVector<TokenView> &tokens);
    void setPending(const QString &message);
    void setAddress(const QString &address);
    QString currentAddress() const;

  signals:
    void addressSelected(const QString &address, bool record);
    void functionFollowRequested(const QString &address, bool record);
    void renameRequested(const QString &address, const QString &current_name);

  protected:
    void resizeEvent(QResizeEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void contextMenuEvent(QContextMenuEvent *event) override;
    QMimeData *createMimeDataFromSelection() const override;

  private:
    friend class SourceGutter;
    struct Span {
        int start;
        int length;
        int token;
    };
    const TokenView *tokenAtPosition(int position) const;
    void cursorChanged();
    void updateHighlights();
    void paintGutter(QPaintEvent *event);
    void clickGutter(const QPoint &position);
    void updateGutter();
    void toggleFold(int line);
    void applyFolds();
    void findFolds(const QString &text);
    void followToken();
    void renameToken();

    SourceGutter *gutter_;
    QVector<TokenView> tokens_;
    QVector<Span> spans_;
    QHash<QString, QVector<int>> addresses_;
    QVector<int> fold_ends_;
    QSet<int> folded_;
    QString highlight_address_;
    bool loading_ = false;
    bool record_navigation_ = false;
    bool hints_visible_ = true;
};
