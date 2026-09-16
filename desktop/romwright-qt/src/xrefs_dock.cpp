#include "xrefs_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QComboBox>
#include <QHeaderView>
#include <QJsonObject>
#include <QPointer>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

XrefsDock::XrefsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Xrefs"), parent), bridge_(bridge) {
    setObjectName(QStringLiteral("xrefsDock"));

    auto *tabs = new QTabWidget(this);
    tabs_ = tabs;
    auto make_xrefs_table = [this](QTabWidget *parent_widget, const QString &object_name,
                                   int address_column) {
        auto *table = new QTableWidget(0, 5, parent_widget);
        table->setObjectName(object_name);
        table->setHorizontalHeaderLabels({QStringLiteral("Address"), QStringLiteral("Function"),
                                          QStringLiteral("Kind"), QStringLiteral("Target"),
                                          QStringLiteral("Evidence")});
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->setVisible(false);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(table, &QTableWidget::itemActivated, this,
                [this, table, address_column](QTableWidgetItem *item) {
                    const auto *address_item = table->item(item->row(), address_column);
                    const QString addr = address_item ? address_item->text() : QString();
                    if (!addr.isEmpty()) {
                        emit addressDoubleClicked(addr);
                    }
                });
        return table;
    };
    xrefs_to_ = make_xrefs_table(tabs, QStringLiteral("xrefsToView"), 0);
    xrefs_from_ = make_xrefs_table(tabs, QStringLiteral("xrefsFromView"), 3);
    tabs->addTab(xrefs_to_, QStringLiteral("Incoming"));
    tabs->addTab(xrefs_from_, QStringLiteral("Outgoing"));

    evidence_box_ = new QComboBox(this);
    evidence_box_->setObjectName(QStringLiteral("xrefsEvidenceFilter"));
    evidence_box_->addItem(QStringLiteral("All evidence"), QString());
    for (const QString &kind :
         {QStringLiteral("declared"), QStringLiteral("decoded"), QStringLiteral("inferred")}) {
        evidence_box_->addItem(kind, kind);
    }
    connect(evidence_box_, &QComboBox::currentIndexChanged, this,
            [this](int index) { setEvidence(evidence_box_->itemData(index).toString()); });

    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(evidence_box_);
    layout->addWidget(tabs);
    setWidget(panel);
}

void XrefsDock::setEvidence(const QString &kind) {
    if (evidence_ == kind) {
        return;
    }
    evidence_ = kind;
    if (evidence_box_ != nullptr) {
        const int index = evidence_box_->findData(kind);
        if (index >= 0 && index != evidence_box_->currentIndex()) {
            evidence_box_->setCurrentIndex(index);
        }
    }
    if (!program_.isEmpty() && !address_.isEmpty()) {
        loadXrefs(program_, address_);
    }
}

void XrefsDock::loadXrefs(const QString &program, const QString &address) {
    const quint64 generation = ++generation_;
    xrefs_to_->setRowCount(0);
    xrefs_from_->setRowCount(0);
    program_ = program;
    address_ = address;
    rendered_rows_ = 0;
    unexplained_rows_ = 0;
    pending_ = 0;
    tabs_->setTabText(0, QStringLiteral("Incoming"));
    tabs_->setTabText(1, QStringLiteral("Outgoing"));
    if (program.isEmpty() || address.isEmpty())
        return;
    tabs_->setTabText(0, QStringLiteral("Incoming…"));
    tabs_->setTabText(1, QStringLiteral("Outgoing…"));
    pending_ = 2;
    auto fill = [this, program, address, generation](QTableWidget *table, bool incoming) {
        const QString job_name = QStringLiteral("xrefs %1 %2")
                                     .arg(incoming ? QStringLiteral("to") : QStringLiteral("from"))
                                     .arg(address);
        emit jobStarted(job_name);
        QJsonObject request{{"method", "xrefs_page"}, {"program", program}, {"address", address},
                            {"incoming", incoming},   {"offset", 0},        {"limit", 256}};
        if (!evidence_.isEmpty()) {
            request.insert(QStringLiteral("evidence"), evidence_);
        }
        bridge_->request(request, [this, guard = QPointer<XrefsDock>(this), job_name, table, incoming,
                                   generation](const QJsonObject &response) {
            if (!guard)
                return;
            if (generation != generation_) {
                emit jobFinished(job_name, successful(response), QStringLiteral("Superseded references"));
                return;
            }
            QString error;
            if (!successful(response, &error)) {
                tabs_->setTabText(incoming ? 0 : 1, incoming ? QStringLiteral("Incoming: failed")
                                                             : QStringLiteral("Outgoing: failed"));
                emit jobFinished(job_name, false, error);
                if (--pending_ == 0) {
                    emit loadFinished();
                }
                return;
            }
            const QJsonArray rows = response.value("result").toObject().value("rows").toArray();
            table->setRowCount(0);
            for (const QJsonValue &value : rows) {
                const QJsonObject row = value.toObject();
                const int index = table->rowCount();
                table->insertRow(index);
                const QString from = addressText(row.value("from"));
                const QString to = addressText(row.value("to"));
                const QString function = row.value("function").toString();
                table->setItem(index, 0, new QTableWidgetItem(from));
                table->setItem(index, 1,
                               new QTableWidgetItem(function.isEmpty() ? QStringLiteral("—") : function));
                table->setItem(index, 2, new QTableWidgetItem(row.value("kind").toString()));
                table->setItem(index, 3, new QTableWidgetItem(to));
                // The sentence comes from the core's shared
                // table, never from a copy kept here.
                const QJsonObject provenance = row.value("provenance").toObject();
                const QString evidence = provenance.value("explanation").toString();
                auto *item = new QTableWidgetItem(evidence.isEmpty() ? provenance.value("source").toString()
                                                                     : evidence);
                // The class and what kind of evidence it is,
                // both from the core's table.
                const QString evidence_kind = provenance.value("evidence").toString();
                item->setToolTip(evidence_kind.isEmpty()
                                     ? provenance.value("source").toString()
                                     : QStringLiteral("%1 [%2]").arg(provenance.value("source").toString(),
                                                                     evidence_kind));
                table->setItem(index, 4, item);
                rendered_rows_ += 1;
                if (evidence.isEmpty()) {
                    unexplained_rows_ += 1;
                }
            }
            const QString direction = incoming ? QStringLiteral("Incoming") : QStringLiteral("Outgoing");
            tabs_->setTabText(incoming ? 0 : 1, QStringLiteral("%1 (%2)").arg(direction).arg(rows.size()));
            emit jobFinished(job_name, true,
                             QStringLiteral("%1: %2 references").arg(direction).arg(rows.size()));
            if (--pending_ == 0) {
                emit loadFinished();
            }
        });
    };
    fill(xrefs_to_, true);
    fill(xrefs_from_, false);
}
