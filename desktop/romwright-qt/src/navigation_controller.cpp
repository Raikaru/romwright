#include "navigation_controller.h"

NavigationController::NavigationController(QObject *parent) : QObject(parent) {}

void NavigationController::setProgram(const QString &program) {
    if (program_ == program) {
        return;
    }
    program_ = program;
    address_.clear();
    history_.clear();
    history_index_ = -1;
    emit historyChanged(false, false);
    emit programChanged(program_);
}

QString NavigationController::program() const { return program_; }

void NavigationController::goTo(const QString &address, bool record) {
    if (address.isEmpty()) {
        return;
    }
    bool valid = false;
    const quint64 offset = address.toULongLong(&valid, 16);
    const QString target = valid ? QStringLiteral("0x%1").arg(offset, 0, 16) : address;
    if (record) {
        while (history_.size() > history_index_ + 1) {
            history_.removeLast();
        }
        if (history_.isEmpty() || history_.last() != target) {
            history_.append(target);
        }
        history_index_ = history_.size() - 1;
    }
    address_ = target;
    emit addressChanged(address_);
    emit historyChanged(canGoBack(), canGoForward());
}

QString NavigationController::address() const { return address_; }

bool NavigationController::canGoBack() const { return history_index_ > 0; }

bool NavigationController::canGoForward() const {
    return history_index_ + 1 < history_.size();
}

void NavigationController::back() {
    if (!canGoBack()) {
        return;
    }
    --history_index_;
    address_ = history_.at(history_index_);
    emit addressChanged(address_);
    emit historyChanged(canGoBack(), canGoForward());
}

void NavigationController::forward() {
    if (!canGoForward()) {
        return;
    }
    ++history_index_;
    address_ = history_.at(history_index_);
    emit addressChanged(address_);
    emit historyChanged(canGoBack(), canGoForward());
}
