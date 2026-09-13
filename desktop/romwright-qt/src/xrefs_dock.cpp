#include "xrefs_dock.h"

#include "core_bridge.h"
#include "json_util.h"

#include <QComboBox>
#include <QVBoxLayout>
#include <QWidget>
#include <QHeaderView>
#include <QJsonObject>
#include <QTabWidget>
#include <QTableWidget>

XrefsDock::XrefsDock(CoreBridge *bridge, QWidget *parent)
    : QDockWidget(QStringLiteral("Xrefs"), parent),
      bridge_(bridge) {
    setObjectName(QStringLiteral("xrefsDock"));

    auto *tabs = new QTabWidget(this);
    auto make_xrefs_table = [this](QTabWidget *parent_widget, const QString &object_name) {
        auto *table = new QTableWidget(0, 5, parent_widget);
        table->setObjectName(object_name);
        table->setHorizontalHeaderLabels({QStringLiteral("Address"),
                                          QStringLiteral("Function"),
                                          QStringLiteral("Kind"),
                                          QStringLiteral("Target"),
                                          QStringLiteral("Evidence")});
        table->horizontalHeader()->setStretchLastSection(true);
        table->verticalHeader()->setVisible(false);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(table, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem *item) {
            const QString addr = item->text().split(QLatin1Char(' ')).first();
            if (!addr.isEmpty()) {
                emit addressDoubleClicked(addr);
            }
        });
        return table;
    };
    xrefs_to_ = make_xrefs_table(tabs, QStringLiteral("xrefsToView"));
    xrefs_from_ = make_xrefs_table(tabs, QStringLiteral("xrefsFromView"));
    tabs->addTab(xrefs_to_, QStringLiteral("To"));
    tabs->addTab(xrefs_from_, QStringLiteral("From"));

    evidence_box_ = new QComboBox(this);
    evidence_box_->setObjectName(QStringLiteral("xrefsEvidenceFilter"));
    evidence_box_->addItem(QStringLiteral("All evidence"), QString());
    for (const QString &kind : {QStringLiteral("declared"), QStringLiteral("decoded"),
                                QStringLiteral("inferred")}) {
        evidence_box_->addItem(kind, kind);
    }
    connect(evidence_box_, &QComboBox::currentIndexChanged, this, [this](int index) {
        setEvidence(evidence_box_->itemData(index).toString());
    });

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
    if (program.isEmpty() || address.isEmpty()) {
        return;
    }
    program_ = program;
    address_ = address;
    rendered_rows_ = 0;
    unexplained_rows_ = 0;
    pending_ = 2;
    auto fill = [this, program, address](QTableWidget *table, bool incoming) {
        const QString job_name = QStringLiteral("xrefs %1 %2")
                                     .arg(incoming ? QStringLiteral("to")
                                                   : QStringLiteral("from"))
                                     .arg(address);
        emit jobStarted(job_name);
        QJsonObject request{{"method", "xrefs_page"},
                            {"program", program},
                            {"address", address},
                            {"incoming", incoming},
                            {"offset", 0},
                            {"limit", 256}};
        if (!evidence_.isEmpty()) {
            request.insert(QStringLiteral("evidence"), evidence_);
        }
        bridge_->request(request,
                         [this, job_name, table](const QJsonObject &response) {
                             QString error;
                             if (!successful(response, &error)) {
                                 emit jobFinished(job_name, false, error);
                                 if (--pending_ == 0) {
                                     emit loadFinished();
                                 }
                                 return;
                             }
                             const QJsonArray rows = response.value("result")
                                                         .toObject()
                                                         .value("rows")
                                                         .toArray();
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
                                                new QTableWidgetItem(function.isEmpty()
                                                                         ? QStringLiteral("—")
                                                                         : function));
                                 table->setItem(index, 2,
                                                new QTableWidgetItem(
                                                    row.value("kind").toString()));
                                 table->setItem(index, 3, new QTableWidgetItem(to));
                                 // The sentence comes from the core's shared
                                 // table, never from a copy kept here.
                                 const QJsonObject provenance =
                                     row.value("provenance").toObject();
                                 const QString evidence =
                                     provenance.value("explanation").toString();
                                 auto *item = new QTableWidgetItem(
                                     evidence.isEmpty()
                                         ? provenance.value("source").toString()
                                         : evidence);
                                 // The class and what kind of evidence it is,
                                 // both from the core's table.
                                 const QString evidence_kind =
                                     provenance.value("evidence").toString();
                                 item->setToolTip(
                                     evidence_kind.isEmpty()
                                         ? provenance.value("source").toString()
                                         : QStringLiteral("%1 [%2]")
                                               .arg(provenance.value("source").toString(),
                                                    evidence_kind));
                                 table->setItem(index, 4, item);
                                 rendered_rows_ += 1;
                                 if (evidence.isEmpty()) {
                                     unexplained_rows_ += 1;
                                 }
                             }
                             emit jobFinished(job_name, true,
                                              QStringLiteral("%1 xrefs").arg(rows.size()));
                             if (--pending_ == 0) {
                                 emit loadFinished();
                             }
                         });
    };
    fill(xrefs_to_, true);
    fill(xrefs_from_, false);
}
