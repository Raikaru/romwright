/* A deterministic work budget for one decompile.
 *
 * The decompiler is single threaded and deterministic: the same function in
 * the same state makes the same sequence of rule applications on any host.
 * A wall-clock limit is not: under load the same function either finishes or
 * is killed, and a function that is killed leaves no switch tables behind, so
 * two imports of one binary disagreed. The budget counts the work the actions
 * do instead: one unit for every action run and for every op a rule pool
 * visits, and one for every rule tried on it. The limit is set with
 * ROMWRIGHT_WORK_BUDGET (units; unset or 0 is unlimited) by the client that
 * asks for it; ROMWRIGHT_WORK_TRACE prints each decompile's units and time to
 * stderr, which is how the limit is calibrated.
 *
 * Running over is reported as WorkBudgetExceeded, which is deliberately not a
 * LowlevelError: code that catches LowlevelError to carry on without a jump
 * table or a prototype must not turn "ran out of budget" into a quiet,
 * different answer. GhidraCommand::doit passes it to the client as an
 * exception (type "WorkBudgetExceeded").
 */
#ifndef __ROMWRIGHT_BUDGET_HH__
#define __ROMWRIGHT_BUDGET_HH__

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace ghidra {

struct WorkBudgetExceeded {
  std::string explain;
  explicit WorkBudgetExceeded(const std::string &s) : explain(s) {}
};

class WorkBudget {
  uint64_t spent;
  uint64_t limit;			///< 0 is unlimited
  bool armed;				///< false once the limit was passed, until the next decompile begins
  bool trace;
  std::chrono::steady_clock::time_point started;
  WorkBudget(void) {
    const char *raw = getenv("ROMWRIGHT_WORK_BUDGET");
    limit = raw == (const char *)0 ? 0 : strtoull(raw,(char **)0,10);
    trace = getenv("ROMWRIGHT_WORK_TRACE") != (const char *)0;
    spent = 0;
    armed = limit != 0;
  }
  void overrun(void) {
    // Cleanup that runs while the exception unwinds, and the commands after
    // it, charge too and must not throw again.
    armed = false;
    throw WorkBudgetExceeded("decompiler work budget of " + std::to_string((unsigned long long)limit) +
			     " units exceeded");
  }
public:
  static WorkBudget &current(void) { static WorkBudget budget; return budget; }
  /// Start counting a new decompile.
  void begin(void) {
    spent = 0;
    armed = limit != 0;
    started = std::chrono::steady_clock::now();
  }
  /// Add \b units of work, throwing when the limit is passed.
  void charge(uint64_t units) {
    spent += units;
    if (armed && spent > limit) overrun();
  }
  /// Report the decompile that just ended, when tracing.
  void finish(uint64_t address,const char *outcome) const {
    if (!trace) return;
    double ms = std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now() - started).count();
    fprintf(stderr,"work-trace %llx %s units %llu ms %.0f\n",(unsigned long long)address,outcome,
	    (unsigned long long)spent,ms);
  }
};

} // End namespace ghidra

#endif
