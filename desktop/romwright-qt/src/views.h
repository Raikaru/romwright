#pragma once

#include "json_util.h"
#include <QHash>

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVector>

/// Typed views over the JSON envelopes the Rust bridge returns. Widgets
/// consume these structs; no QJsonObject indexing happens inside
/// paintEvent or data(). Field names mirror the romwright-model wire contracts
/// (FunctionRow via functions_page, ListingRow via CORE-007, DecompToken
/// via WORKER-004).

/// One functions_page row: address, name, size, signature.
struct FunctionRowView {
    QString address;
    QString name;
    qint64 size = 0;
    QString signature;

    static FunctionRowView fromJson(const QJsonObject &row) {
        FunctionRowView view;
        view.address = addressText(row.value("entry"));
        view.name = row.value("name").toString();
        view.size = row.value("size").toVariant().toLongLong();
        view.signature = row.value("signature").toString();
        return view;
    }
};

/// One listing row (CORE-007): stable id (= instruction address offset),
/// structural kind, display address, rendered mnemonic + operands, and raw
/// instruction bytes.
struct ListingRowView {
    quint64 stable_id = 0;
    QString address;
    QString kind = QStringLiteral("instruction");
    QString text;
    QString bytes;

    static ListingRowView fromJson(const QJsonObject &row) {
        ListingRowView view;
        view.stable_id = row.value("stable_id").toVariant().toULongLong();
        view.address = addressText(row.value("address"));
        view.kind = row.value("kind").toString();
        if (view.kind.isEmpty()) {
            view.kind = QStringLiteral("instruction");
        }
        view.text = row.value("text").toString();
        view.bytes = row.value("bytes").toString();
        return view;
    }
};

/// One memory region row (section table): name, range, permissions.
struct MemoryRegionView {
    QString name;
    QString start;
    quint64 start_offset = 0;
    quint64 size = 0;
    QString permissions;

    static MemoryRegionView fromJson(const QJsonObject &row) {
        MemoryRegionView view;
        view.name = row.value("name").toString();
        view.start = addressText(row.value("start"));
        view.start_offset = row.value("start").toObject().value("offset").toVariant().toULongLong();
        view.size = row.value("size").toVariant().toULongLong();
        view.permissions = row.value("permissions").toString();
        return view;
    }
};

/// One decompiler token (WORKER-004): text, token kind, and the entity
/// address when the packed document carried one. Break tokens end a line
/// and carry the next line's indent.
struct TokenView {
    QString text;
    QString kind;
    QString address;
    quint64 indent = 0;
    QString function_target;
    QStringList parameters;

    bool isBreak() const { return kind == QStringLiteral("Break"); }

    static TokenView fromJson(const QJsonObject &token) {
        TokenView view;
        view.text = token.value("text").toString();
        view.kind = token.value("kind").toString();
        const QJsonValue address = token.value("address");
        view.address = address.isNull() || address.isUndefined() ? QString() : addressText(address);
        if (view.kind == QStringLiteral("FuncName"))
            view.function_target = view.address;
        view.indent = token.value("indent").toVariant().toULongLong();
        return view;
    }

    static QStringList parameterDeclarations(const QString &signature) {
        const int open = signature.indexOf('('), close = signature.lastIndexOf(')');
        if (open < 0 || close <= open || signature.contains('<') || signature.contains('>'))
            return {};
        QStringList result;
        int depth = 0, start = open + 1;
        for (int i = start; i <= close; ++i) {
            const QChar c = signature[i];
            if (i == close || (c == ',' && depth == 0)) {
                if (depth != 0)
                    return {};
                const auto parameter = signature.mid(start, i - start).trimmed();
                if (parameter.isEmpty() || parameter == "void" || parameter == "...")
                    break;
                result.append(parameter);
                start = i + 1;
            } else if (c == '(' || c == '[')
                ++depth;
            else if (c == ')' || c == ']') {
                if (depth == 0)
                    return {};
                --depth;
            }
        }
        return result;
    }

    static QVector<TokenView> withArgumentHints(const QVector<TokenView> &source) {
        QMap<int, QString> hints;
        for (int i = 0; i < source.size(); ++i) {
            if (source[i].parameters.isEmpty())
                continue;
            int open = i + 1;
            while (open < source.size() &&
                   (source[open].isBreak() || source[open].text.trimmed().isEmpty()))
                ++open;
            if (open == source.size() || source[open].text != "(")
                continue;
            int depth = 1, parameter = 0;
            bool first = true;
            for (int j = open + 1; j < source.size() && depth > 0; ++j) {
                const auto &token = source[j];
                if (token.isBreak() || token.text.trimmed().isEmpty())
                    continue;
                if (first && token.text != ")" && parameter < source[i].parameters.size()) {
                    hints[j] += QStringLiteral("/* %1 */ ").arg(source[i].parameters[parameter]);
                    first = false;
                }
                if (token.kind != "Syntax" && token.kind != "Op")
                    continue;
                for (QChar c : token.text) {
                    if (c == '(' || c == '[' || c == '{')
                        ++depth;
                    else if (c == ')' || c == ']' || c == '}')
                        --depth;
                    else if (c == ',' && depth == 1) {
                        ++parameter;
                        first = true;
                    }
                }
            }
        }
        QVector<TokenView> result;
        result.reserve(source.size() + hints.size());
        for (int i = 0; i < source.size(); ++i) {
            if (const auto found = hints.constFind(i); found != hints.cend()) {
                TokenView hint;
                hint.kind = "Hint";
                hint.text = found.value();
                result.append(std::move(hint));
            }
            result.append(source[i]);
        }
        return result;
    }

    static QVector<TokenView> fromDocument(const QJsonObject &document) {
        const QJsonArray source = document.value("tokens").toArray();
        QHash<quint64, QJsonObject> operations;
        for (const auto &value : source) {
            const auto operation = value.toObject().value("operation");
            if (operation.isDouble())
                operations.insert(operation.toVariant().toULongLong(), {});
        }
        const auto ir = document.value("function_ir").toObject();
        const auto signatures = document.value("call_signatures").toObject();
        const auto function_entry = document.value("function_entry");
        const QString entry = function_entry.isNull() || function_entry.isUndefined()
                                  ? QString()
                                  : addressText(function_entry);
        for (const auto &block : ir.value("blocks").toArray())
            for (const auto &value : block.toObject().value("operations").toArray()) {
                const auto operation = value.toObject();
                auto found = operations.find(operation.value("id").toVariant().toULongLong());
                if (found != operations.end())
                    found.value() = operation;
            }
        const auto values = ir.value("values").toObject();
        QVector<TokenView> result;
        result.reserve(source.size());
        bool declaration_seen = false;
        for (const auto &value : source) {
            const auto token = value.toObject();
            auto view = fromJson(token);
            const auto reference = token.value("operation");
            if (reference.isDouble()) {
                const auto found = operations.constFind(reference.toVariant().toULongLong());
                if (found != operations.cend()) {
                    const auto &operation = found.value();
                    if (view.address.isEmpty() && operation.contains("address"))
                        view.address = addressText(operation.value("address"));
                    if (view.kind == QStringLiteral("FuncName") &&
                        operation.value("opcode") == "CALL") {
                        const auto inputs = operation.value("inputs").toArray();
                        if (!inputs.isEmpty()) {
                            const auto input = inputs.first().toObject();
                            if (input.value("kind") == "value") {
                                const auto target =
                                    values
                                        .value(QString::number(
                                            input.value("value").toVariant().toULongLong()))
                                        .toObject()
                                        .value("offset");
                                if (!target.isNull() && !target.isUndefined())
                                    view.function_target = QStringLiteral("0x%1").arg(
                                        target.toVariant().toULongLong(), 0, 16);
                            }
                        }
                        view.parameters = parameterDeclarations(
                            signatures.value(view.function_target).toString());
                    }
                }
            } else if (view.kind == QStringLiteral("FuncName") && !declaration_seen) {
                declaration_seen = true;
                if (view.address.isEmpty()) {
                    view.address = entry.isEmpty() ? addressText(document.value("address")) : entry;
                    view.function_target = entry;
                }
            }
            result.append(std::move(view));
        }
        return withArgumentHints(result);
    }
};
