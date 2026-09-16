#include <QApplication>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTimer>

#include "main_window.h"
#include "matching_gate.h"
#include "theme.h"

int main(int argc, char **argv) {
    QApplication application(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("Romwright"));
    QCoreApplication::setApplicationName(QStringLiteral("Romwright"));
    Theme::apply(application);

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Native Romwright reverse-engineering UI"));
    parser.addHelpOption();
    QCommandLineOption project_option(QStringList() << "p" << "project", "SQLite project", "dir",
                                      QStringLiteral(".romwright"));
    QCommandLineOption program_option(QStringList() << "n" << "program", "Program name", "name");
    QCommandLineOption binary_option(QStringList() << "b" << "binary", "Binary path", "path");
    QCommandLineOption address_option(QStringList() << "a" << "address", "RAM address", "hex",
                                      QStringLiteral("00400466"));
    QCommandLineOption gate_option(QStringList() << "gate", "Run the offscreen UI gate and exit");
    QCommandLineOption store_only_option(
        QStringList() << "store-only", "Gate the store-facing workflow only: no SLEIGH decode or decompile");
    QCommandLineOption matching_gate_option(QStringList() << "matching-gate",
                                            "Exercise the matching editor, actual compiler, history and pins",
                                            "configuration.json");
    parser.addOption(matching_gate_option);
    parser.addOption(gate_option);
    parser.addOption(store_only_option);
    parser.addOption(project_option);
    parser.addOption(program_option);
    parser.addOption(binary_option);
    parser.addOption(address_option);
    parser.process(application);

    if (parser.isSet(gate_option) || parser.isSet(matching_gate_option)) {
        qputenv("ROMWRIGHT_UI_GATE", "1");
    }
    const QString program = parser.value(program_option);
    MainWindow window(parser.value(project_option), program, parser.value(binary_option),
                      parser.value(address_option));
    window.show();
    if (parser.isSet(matching_gate_option)) {
        QTimer::singleShot(0, &window, [&window, configuration = parser.value(matching_gate_option)]() {
            runMatchingGate(&window, configuration);
        });
    }
    if (parser.isSet(gate_option)) {
        const bool store_only = parser.isSet(store_only_option);
        QTimer::singleShot(0, &window, [&window, store_only]() { window.runGate(store_only); });
    }
    return application.exec();
}
