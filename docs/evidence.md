# Evidence index

Every gate writes a JSON report under `benchmarks/reports/`; the table
below is generated from those files by `scripts/gen_evidence_index.py`,
so it cannot claim a number no report carries. Intermediate diagnostic
runs live in `benchmarks/reports/diagnostics/` and are not evidence of
anything current: twelve of them record `passed: false`, because they are the
intermediate measurements that diagnosed a problem rather than gates that
held. A report that records a failure at the top of `benchmarks/reports/`
fails the generator, and `tests/m5-012_evidence_index.py` additionally
requires every acceptance test that writes a `--report` to have a committed
report carrying its id -- a measured result cannot live only in a transcript.

<!-- evidence-index:begin -->
| Report | Gate | Milestone | Status | Measured | Produced by |
|---|---|---|---|---|---|
| `acceptance-audit.json` | `acceptance-audit` | - | recorded | `schema_version` 1 | - |
| `cast_diff_stage2.json` | `cast_diff_stage2` | - | recorded | `decompiled` 1600; `identical` 1588 | - |
| `combined_gate_20261012.json` | `combined_gate_20261012` | - | recorded | recorded | - |
| `combined_gate_compiler_rules_20261012.json` | `combined_gate_compiler_rules_20261012` | - | recorded | recorded | - |
| `compiler_detection_accuracy.json` | `compiler_detection_accuracy` | - | recorded | `abstained` 8; `exact` 55; `games` 64; `lineage` 1; `wrong` 0 | `benchmarks/compiler_detection_accuracy.py` |
| `compiler_detection_accuracy_pc_20261015.json` | `compiler_detection_accuracy_pc_20261015` | - | recorded | `abstained` 0; `exact` 8; `games` 8; `lineage` 0; `wrong` 0 | - |
| `compiler_rules_gate_vs_20261012.json` | `compiler_rules_gate_vs_20261012` | - | recorded | recorded | - |
| `compiler_rules_loo.json` | `compiler_rules_loo` | - | recorded | `reach` 60; `sample` 40 | `benchmarks/compiler_rules_loo.py` |
| `console-processors.json` | `console-processors` | - | pass | `processors` 22 | - |
| `console_research.json` | `console_research` | - | recorded | `n` 200; `seed` 20261006 | `benchmarks/console_research.py` |
| `console_research_dwarf1.json` | `console_research_dwarf1` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_final.json` | `console_research_final` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_final2.json` | `console_research_final2` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_integration_20261009.json` | `console_research_integration_20261009` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_pairs_gba.json` | `console_research_pairs_gba` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_pairs_ps2.json` | `console_research_pairs_ps2` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_proto_psv-need-for-speed-most-wanted.json` | `console_research_proto_psv-need-for-speed-most-wanted` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_proto_x360-black-ops-2.json` | `console_research_proto_x360-black-ops-2` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_prototypes.json` | `console_research_prototypes` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_protowork.json` | `console_research_protowork` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_psp.json` | `console_research_psp` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_vita_20261009.json` | `console_research_vita_20261009` | - | recorded | `n` 200; `seed` 20261006 | - |
| `console_research_wave_20261009.json` | `console_research_wave_20261009` | - | recorded | `n` 500 | - |
| `console_research_wave_20261009_newtree.json` | `console_research_wave_20261009_newtree` | - | recorded | `n` 500 | - |
| `console_research_wave_20261010.json` | `console_research_wave_20261010` | - | recorded | `n` 500 | - |
| `console_research_wave_20261011_ps2.json` | `console_research_wave_20261011_ps2` | - | recorded | `n` 500 | - |
| `console_research_wave_20261011_ps2_precision.json` | `console_research_wave_20261011_ps2_precision` | - | recorded | `n` 500 | - |
| `console_research_wave_20261012_other_combined.json` | `console_research_wave_20261012_other_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_20261012_ps2_combined.json` | `console_research_wave_20261012_ps2_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_20261012_psp_n200_combined.json` | `console_research_wave_20261012_psp_n200_combined` | - | recorded | `n` 200 | - |
| `console_research_wave_compiler_rules_20261012_other_combined.json` | `console_research_wave_compiler_rules_20261012_other_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_compiler_rules_20261012_poolrule_off.json` | `console_research_wave_compiler_rules_20261012_poolrule_off` | - | recorded | `n` 500 | - |
| `console_research_wave_compiler_rules_20261012_ps2_combined.json` | `console_research_wave_compiler_rules_20261012_ps2_combined` | - | recorded | `n` 500 | - |
| `console_research_wave_compiler_rules_20261012_psp_n200_combined.json` | `console_research_wave_compiler_rules_20261012_psp_n200_combined` | - | recorded | `n` 200 | - |
| `console_research_wave_old_20261012.json` | `console_research_wave_old_20261012` | - | recorded | `n` 500 | - |
| `console_research_wave_pc_20261015.json` | `console_research_wave_pc_20261015` | - | recorded | `n` 100 | - |
| `cost-envelope.json` | `cost-envelope` | - | recorded | `headroom` 1.2500 | - |
| `dark-workbench.json` | `dark-workbench` | - | recorded | `schema` 1 | - |
| `decompile-envelope.json` | `decompile-envelope` | - | recorded | `headroom` 1.2500 | - |
| `dwarf1_differential.json` | `dwarf1_differential` | - | recorded | `agreement_rate` 1.0000; `arity_agreement` 5221; `compared` 5221; `disagreement_count` 0 | - |
| `evidence-classes.json` | `evidence-classes` | - | recorded | recorded | - |
| `fact_pack_gating.json` | `fact_pack_gating` | - | recorded | recorded | `benchmarks/fact_pack_gating.py` |
| `fact_pack_loo.json` | `fact_pack_loo` | - | recorded | recorded | - |
| `finish_gate_20261015.json` | `finish_gate_20261015` | - | recorded | recorded | - |
| `ghidra_master_trial.json` | `ghidra_master_trial` | - | recorded | `schema` 1 | `benchmarks/ghidra_master_trial.py` |
| `head-to-head-libc.json` | `head-to-head-libc` | - | recorded | recorded | - |
| `import-speed.json` | `import-speed` | - | recorded | `limit_s` 3600; `quality_margin` 0.0100; `speed_tolerance_floor` 0.0500 | - |
| `import_precision_20261015.json` | `import_precision_20261015` | - | recorded | recorded | - |
| `import_precision_20261015_harness_hp.json` | `import_precision_20261015_harness_hp` | - | recorded | `n` 60; `seed` 1 | - |
| `import_precision_20261015_harness_nds.json` | `import_precision_20261015_harness_nds` | - | recorded | `n` 60; `seed` 1 | - |
| `import_precision_20261015_harness_psp.json` | `import_precision_20261015_harness_psp` | - | recorded | `n` 60; `seed` 1 | - |
| `locals_truth.json` | `locals_truth` | - | recorded | recorded | `benchmarks/locals_truth.py` |
| `m22-ps2_p4.json` | `m22-ps2_p4` | - | recorded | recorded | - |
| `m22-ps2_p4_combined_20261012.json` | `m22-ps2_p4_combined_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_combined_compiler_rules_20261012.json` | `m22-ps2_p4_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc.json` | `m22-ps2_p4_eegcc` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_BASELINE_compiler_rules_20261012.json` | `m22-ps2_p4_eegcc_BASELINE_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_combined_20261012.json` | `m22-ps2_p4_eegcc_combined_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_combined_compiler_rules_20261012.json` | `m22-ps2_p4_eegcc_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_pre_ps2cmatch.json` | `m22-ps2_p4_eegcc_pre_ps2cmatch` | - | recorded | recorded | - |
| `m22-ps2_p4_eegcc_sharedwork_compiler_rules_20261012.json` | `m22-ps2_p4_eegcc_sharedwork_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_old_20261012.json` | `m22-ps2_p4_old_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_pre_ps2cmatch.json` | `m22-ps2_p4_pre_ps2cmatch` | - | recorded | recorded | - |
| `m22-ps2_p4_pre_ps2printer.json` | `m22-ps2_p4_pre_ps2printer` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011.json` | `m22-ps2_p4_seed20261011` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_combined_20261012.json` | `m22-ps2_p4_seed20261011_combined_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_combined_compiler_rules_20261012.json` | `m22-ps2_p4_seed20261011_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_pre_ps2cmatch.json` | `m22-ps2_p4_seed20261011_pre_ps2cmatch` | - | recorded | recorded | - |
| `m22-ps2_p4_seed20261011_pre_ps2printer.json` | `m22-ps2_p4_seed20261011_pre_ps2printer` | - | recorded | recorded | - |
| `match_search_20261014.json` | `match_search_20261014` | - | recorded | `budget` 24 | - |
| `matching-workflow.json` | `matching-workflow` | - | recorded | `schema` 1 | - |
| `memory_fix_20261015.json` | `memory-fix` | - | pass | `images.cpu_ratio.max` 0.9790; `images.rows_compared` 784555; `images.wall_ratio.max` 0.9750; `import.entries_over_limit` 0; `import.peak_kb.median.after` 34294.0000; `import.peak_kb.median.before` 246968.0000; `import.peak_over_limit.worst_ratio` 0.9220; `session.entries_over_limit` 1; `session.peak_kb.max.after` 54376; `session.processes_at_end.after` 2 | - |
| `merge_diff_stage3_20261014.json` | `merge_diff_stage3_20261014` | - | recorded | `decompiled` 1600; `identical` 1600 | - |
| `merge_port_measure_stage3.json` | `merge_port_measure_stage3` | - | recorded | `decompiler` 0; `entries` 310769; `explicit` 123545; `functions` 1600; `implied` 54441; `merges` 109767; `named` 9034; `new_ops` 2492; `speculative` 5560; `worker` 1600 | - |
| `merge_verify_stage3_20261014.json` | `merge_verify_stage3_20261014` | - | recorded | `decided` 7619; `declined` 0; `mismatch` 0; `verified` 7619 | - |
| `n64_segments.json` | `n64_segments` | - | recorded | `corroborating_entries` 4942; `truth_named` 4086 | `benchmarks/n64_segments_score.py` |
| `ownership.json` | `ownership` | - | recorded | `n` 200; `seed` 20261006 | `benchmarks/ownership.py` |
| `ownership_corpuswave.json` | `ownership_corpuswave` | - | recorded | `n` 200; `seed` 20261006 | - |
| `ownership_default_coverage.json` | `ownership_default_coverage` | - | recorded | `functions` 400 | - |
| `ownership_expressions.json` | `ownership_expressions` | - | recorded | `n` 200; `seed` 20261006 | - |
| `ownership_final.json` | `ownership_final` | - | recorded | `n` 200; `seed` 20261006 | - |
| `ownership_stock_coverage.json` | `ownership_stock_coverage` | - | recorded | `functions` 400 | `benchmarks/ownership_stock_coverage.py` |
| `ownership_structuring.json` | `ownership_structuring` | - | recorded | `n` 50; `seed` 20261006 | - |
| `ownership_switch_feed.json` | `ownership_switch_feed` | - | recorded | `n` 200; `seed` 20261006 | - |
| `parity-baseline.json` | `parity-baseline` | - | recorded | recorded | - |
| `pc_c_output_20261015.json` | `pc_c_output_20261015` | - | recorded | recorded | - |
| `pc_c_output_20261015_mini_off.json` | `pc_c_output_20261015_mini_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_mini_on2.json` | `pc_c_output_20261015_mini_on2` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-glquake-msvc42_off.json` | `pc_c_output_20261015_pc-glquake-msvc42_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-glquake-msvc42_on.json` | `pc_c_output_20261015_pc-glquake-msvc42_on` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-glquake-msvc42_on2.json` | `pc_c_output_20261015_pc-glquake-msvc42_on2` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-ioq3-ded-mingw32_off.json` | `pc_c_output_20261015_pc-ioq3-ded-mingw32_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-ioq3-ded-mingw32_on2.json` | `pc_c_output_20261015_pc-ioq3-ded-mingw32_on2` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_CALLEE_CONVENTIONS.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_CALLEE_CONVENTIONS` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_LONG_DOUBLE.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_EXPORT_LONG_DOUBLE` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_PE_CONVENTIONS.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_PE_CONVENTIONS` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_PE_IAT_REGIONS.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_PE_IAT_REGIONS` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_no_PE_WINDOWS_SPEC.json` | `pc_c_output_20261015_pc-quake2-msvc8_no_PE_WINDOWS_SPEC` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_off.json` | `pc_c_output_20261015_pc-quake2-msvc8_off` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_on.json` | `pc_c_output_20261015_pc-quake2-msvc8_on` | - | recorded | recorded | - |
| `pc_c_output_20261015_pc-quake2-msvc8_on2.json` | `pc_c_output_20261015_pc-quake2-msvc8_on2` | - | recorded | recorded | - |
| `pc_import_20261015.json` | `pc_import_20261015` | - | recorded | recorded | - |
| `pc_import_discovery_ours_20261015.json` | `pc_import_discovery_ours_20261015` | - | recorded | recorded | - |
| `pc_import_discovery_stock_20261015.json` | `pc_import_discovery_stock_20261015` | - | recorded | recorded | - |
| `pc_rules_loo_20261015.json` | `pc_rules_loo_20261015` | - | recorded | recorded | - |
| `pc_upgrade_20261015.json` | `pc_upgrade_20261015` | - | recorded | recorded | - |
| `printer_diff.json` | `printer_diff` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | `benchmarks/printer_diff.py` |
| `printer_diff_expressions.json` | `printer_diff_expressions` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | - |
| `printer_diff_stage2.json` | `printer_diff_stage2` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | - |
| `printer_diff_stage3_20261014.json` | `printer_diff_stage3_20261014` | - | recorded | `decompiled` 1800; `identical` 1800; `identical_rate` 1.0000 | - |
| `ps2_decompile_success_after_20261011.json` | `ps2_decompile_success_after_20261011` | - | recorded | recorded | - |
| `ps2_decompile_success_before_20261011.json` | `ps2_decompile_success_before_20261011` | - | recorded | recorded | - |
| `ps2_decompile_success_combined_20261012.json` | `ps2_decompile_success_combined_20261012` | - | recorded | recorded | - |
| `ps2_decompile_success_combined_compiler_rules_20261012.json` | `ps2_decompile_success_combined_compiler_rules_20261012` | - | recorded | recorded | - |
| `ps2_decompile_success_handoff_default.json` | `ps2_decompile_success_handoff_default` | - | recorded | recorded | - |
| `ps2_decompile_success_handoff_stock.json` | `ps2_decompile_success_handoff_stock` | - | recorded | recorded | - |
| `ps2_decompile_success_stage2_def.json` | `ps2_decompile_success_stage2_def` | - | recorded | recorded | - |
| `ps2_decompile_success_stage2_followup.json` | `ps2_decompile_success_stage2_followup` | - | recorded | recorded | - |
| `ps2_decompile_success_stage2_off.json` | `ps2_decompile_success_stage2_off` | - | recorded | recorded | - |
| `psp_stock_compare.json` | `psp_stock_compare` | - | recorded | `dwarf_functions` 145; `truth_functions` 622 | `benchmarks/psp_stock_compare.py` |
| `service_memory_20261015-nih.json` | `service-memory` | - | pass | `documents.entries_equal` 16; `documents.entries_tokens_equal` 20; `service.peak_kb.median.after` 12622; `service.peak_kb.median.before` 14584; `session.entries_over_limit.after` 0; `session.entries_over_limit.before` 5; `session.margin_kb.min.after` 717; `session.peak_kb.max.after` 79256; `session.peak_kb.max.before` 95608 | - |
| `service_memory_20261015-smt-cold.json` | `service-memory` | - | pass | `documents.entries_equal` 16; `documents.entries_tokens_equal` 20; `service.peak_kb.median.after` 12498; `service.peak_kb.median.before` 14404; `session.entries_over_limit.after` 0; `session.entries_over_limit.before` 5; `session.margin_kb.min.after` 685; `session.peak_kb.max.after` 79244; `session.peak_kb.max.before` 95504 | - |
| `service_memory_20261015-smt-warm.json` | `service-memory` | - | pass | `documents.entries_equal` 16; `documents.entries_tokens_equal` 20; `service.peak_kb.median.after` 12492; `service.peak_kb.median.before` 14450; `session.entries_over_limit.after` 0; `session.entries_over_limit.before` 5; `session.margin_kb.min.after` 569; `session.peak_kb.max.after` 79432; `session.peak_kb.max.before` 95520 | - |
| `session-envelope.json` | `session-envelope` | - | recorded | `headroom` 1.2500; `rounds` 8; `warmup_rounds` 4 | - |
| `spurious_gotos.json` | `spurious_gotos` | - | recorded | recorded | `benchmarks/spurious_gotos.py` |
| `spurious_gotos_before.json` | `spurious_gotos_before` | - | recorded | recorded | - |
| `spurious_gotos_current_tree.json` | `spurious_gotos_current_tree` | - | recorded | recorded | - |
| `spurious_gotos_final.json` | `spurious_gotos_final` | - | recorded | recorded | - |
| `spurious_gotos_final_before.json` | `spurious_gotos_final_before` | - | recorded | recorded | - |
| `spurious_gotos_final_current_tree.json` | `spurious_gotos_final_current_tree` | - | recorded | recorded | - |
| `spurious_gotos_final_variants.json` | `spurious_gotos_final_variants` | - | recorded | recorded | - |
| `spurious_gotos_variants.json` | `spurious_gotos_variants` | - | recorded | recorded | - |
| `stage2_followup_20261013.json` | `stage2_followup_20261013` | - | recorded | recorded | - |
| `stage2_gates_20261013.json` | `stage2_gates_20261013` | - | recorded | recorded | - |
| `stage3_gates_20261014.json` | `stage3_gates_20261014` | - | recorded | recorded | - |
| `stage4-gate.json` | `stage4-gate` | - | recorded | `median_wall_s` 0.7500; `peak_decompile_kb` 39280; `peak_disasm_kb` 40884; `peak_import_kb` 40876 | - |
| `stage4_gates_20261015.json` | `stage4_gates_20261015` | - | recorded | recorded | - |
| `struct_gate_sweep_20261013.json` | `struct_gate_sweep_20261013` | - | recorded | recorded | - |
| `struct_gate_sweep_qword_20261013.json` | `struct_gate_sweep_qword_20261013` | - | recorded | recorded | - |
| `struct_inference_audit.json` | `struct_inference_audit` | - | recorded | `schema` 1 | `benchmarks/struct_inference_audit.py` |
| `struct_layer_20261013.json` | `struct_layer_20261013` | - | recorded | recorded | - |
| `struct_layer_final_20261013.json` | `struct_layer_final_20261013` | - | recorded | recorded | - |
| `struct_layer_rerun_20261013.json` | `struct_layer_rerun_20261013` | - | recorded | recorded | - |
| `struct_pointer_fields_stage4_20261015.json` | `struct_pointer_fields_stage4_20261015` | - | recorded | `addresses` 200; `functions_with_a_pointer_field` 1; `structs_printed` 9 | - |
| `struct_print_capcom_20261013.json` | `struct_print_capcom_20261013` | - | recorded | `addresses` 1000 | - |
| `struct_print_dungeon_20261013.json` | `struct_print_dungeon_20261013` | - | recorded | `addresses` 324 | - |
| `structure_handoff.json` | `structure_handoff` | - | recorded | `compared` 1600; `functions` 1600; `identical` 1598; `neutral` 2; `rust_else` 1478; `rust_failed` 0; `rust_gotos` 151; `rust_labels` 103; `stock_else` 1478; `stock_failed` 0; `stock_gotos` 151; `stock_labels` 103; `verify_checked` 0; `verify_mismatched` 0 | `benchmarks/structure_handoff.py` |
| `structuring_baseline.json` | `structuring_baseline` | - | recorded | recorded | `benchmarks/structuring_baseline.py` |
| `structuring_compile.json` | `structuring_compile` | - | recorded | recorded | `benchmarks/structuring_compile.py` |
| `structuring_cutover.json` | `structuring_cutover` | - | recorded | recorded | - |
| `structuring_cutover_m22.json` | `structuring_cutover_m22` | - | recorded | recorded | - |
| `structuring_cutover_m22_no_structure.json` | `structuring_cutover_m22_no_structure` | - | recorded | recorded | - |
| `structuring_cutover_no_structure.json` | `structuring_cutover_no_structure` | - | recorded | recorded | - |
| `structuring_goto_passes.json` | `structuring_goto_passes` | - | recorded | recorded | - |
| `structuring_goto_passes_compile.json` | `structuring_goto_passes_compile` | - | recorded | recorded | - |
| `structuring_goto_passes_compile_current_tree.json` | `structuring_goto_passes_compile_current_tree` | - | recorded | recorded | - |
| `structuring_goto_passes_current_tree.json` | `structuring_goto_passes_current_tree` | - | recorded | recorded | - |
| `structuring_goto_passes_m22.json` | `structuring_goto_passes_m22` | - | recorded | recorded | - |
| `structuring_goto_passes_variants.json` | `structuring_goto_passes_variants` | - | recorded | recorded | - |
| `structuring_m22.json` | `structuring_m22` | - | recorded | recorded | `benchmarks/structuring_m22.py` |
| `structuring_models.json` | `structuring_models` | - | recorded | recorded | `benchmarks/structuring_models.py` |
| `structuring_models_ir_none.json` | `structuring_models_ir_none` | - | recorded | recorded | - |
| `structuring_sailr.json` | `structuring_sailr` | - | recorded | recorded | - |
| `structuring_sailr_before.json` | `structuring_sailr_before` | - | recorded | recorded | - |
| `structuring_sailr_budget.json` | `structuring_sailr_budget` | - | recorded | recorded | - |
| `structuring_sailr_compile.json` | `structuring_sailr_compile` | - | recorded | recorded | - |
| `structuring_sailr_ir_none.json` | `structuring_sailr_ir_none` | - | recorded | recorded | - |
| `structuring_sailr_m22.json` | `structuring_sailr_m22` | - | recorded | recorded | - |
| `switch_feed.json` | `switch_feed` | - | recorded | `n` 200; `seed` 20261006 | `benchmarks/switch_feed.py` |
| `symbol_layout_20261015.json` | `symbol_layout_20261015` | - | recorded | recorded | - |
| `type-headtohead-aarch64.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead-mips32be.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead-mips32le.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead-x86_64.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `type-headtohead.json` | `type-headtohead` | - | recorded | `slots` 37 | - |
| `types_port_measure_stage2.json` | `types_port_measure_stage2` | - | recorded | recorded | - |
| `types_port_measure_stage4_20261015.json` | `types_port_measure_stage4_20261015` | - | recorded | recorded | - |
| `upgrade1_failure_classes_def_20261014.json` | `upgrade1_failure_classes_def_20261014` | - | recorded | recorded | - |
| `upgrade1_failure_classes_off_20261014.json` | `upgrade1_failure_classes_off_20261014` | - | recorded | recorded | - |
| `upgrade1_gates_20261014.json` | `upgrade1_gates_20261014` | - | recorded | recorded | - |
| `variant_quality_stage3_20261014.json` | `variant_quality_stage3_20261014` | - | recorded | recorded | - |
| `variant_smoke_stage3_20261014.json` | `variant_smoke_stage3_20261014` | - | recorded | recorded | - |
| `wave_text_diff_stage3_20261014.json` | `wave_text_diff_stage3_20261014` | - | recorded | `compared` 7409; `different` 0; `identical` 7409; `missing` 91; `missing_a` 91; `missing_b` 91 | - |
| `workbench-acceptance.json` | `workbench-acceptance` | - | recorded | recorded | - |
| `workbench-interactions.json` | `workbench-interactions` | - | recorded | `interaction_wall_seconds` 1.8300 | - |
| `workbench-quality.json` | `workbench-quality` | - | recorded | recorded | - |
| `ui-gate.json` | `ui` | M0 | pass | 1 pass, 0 fail, 0 skipped | `benchmarks/ui_gate.py` |
| `discovery-gate.json` | `discovery` | M1 | pass | 20 pass, 0 fail, 0 skipped | `benchmarks/discovery_gate.py` |
| `m1-003.json` | `m1-003` | M1 | pass | recorded | `tests/m1-003_batched_flow.sh` |
| `m1-006.json` | `m1-006` | M1 | recorded | `passed_entries` 20; `skipped_entries` 5; `total_entries` 25 | `tests/m1-006_corpus.sh` |
| `m1-007.json` | `m1-007` | M1 | pass | 20 pass, 0 fail, 0 skipped | `tests/m1-007_oracle_test.py` |
| `oracle-regen.json` | `m1-007` | M1 | pass | 20 pass, 0 fail, 0 skipped | `tests/m1-007_oracle_test.py` |
| `m1-008.json` | `m1-008` | M1 | pass | 6 pass, 0 fail, 0 skipped | `tests/m1-008_languages.py` |
| `m1-008b-classification.json` | `m1-008b` | M1 | recorded | recorded | `tests/m1-008b_pointer_seeds.py` |
| `m1-008b-v1.json` | `m1-008b` | M1 | pass | 2 pass, 0 fail, 0 skipped | `tests/m1-008b_pointer_seeds.py` |
| `m1-008b-scoring.json` | `m1-008b-scoring` | M1 | pass | 20 pass, 0 fail, 0 skipped | `tests/m1-008b_pointer_seeds.py` |
| `m1-009.json` | `m1-009` | M1 | pass | 1 pass, 0 fail, 0 skipped | `tests/m1-009_dol.py` |
| `m1-010.json` | `m1-010` | M1 | pass | recorded | `tests/m1-010_macho.py` |
| `m10-001.json` | `m10-001` | M10 | pass | `images.overlapping_address` 4198400; `images.programs` 2; `images.reads_compared` 16; `images.rows_compared` 607 | `tests/m10-001_multi_image.py` |
| `m10-002.json` | `m10-002` | M10 | pass | `images.follow_facts_compared` 8; `images.followed_programs` 2; `images.ui_programs` 2; `images.ui_switch_functions` 112 | `tests/m10-002_image_navigation.py` |
| `m10-003.json` | `m10-003` | M10 | pass | `edits.reads_compared` 16; `edits.revision_after_second_import` 9; `edits.win_functions` 112 | `tests/m10-003_edit_durability.py` |
| `m10-004.json` | `m10-004` | M10 | pass | `images.methods_excused` 0; `images.methods_program_scoped` 41; `images.reads_discriminating` 13; `images.reads_isolated` 54; `images.writes_inert` 4; `images.writes_isolated` 14 | `tests/m10-004_multi_image_milestone.py` |
| `m10-005.json` | `m10-005` | M10 | recorded | recorded | `tests/m10-005_overlay_isolation.py` |
| `m11-001.json` | `m11-001` | M11 | pass | `session.bounded_analyzed` 1770; `session.decompile_ms` 19.0394; `session.decompiled` 5; `session.edit_survived_reimport` 1.0000; `session.fn_precision` 0.9093; `session.fn_recall` 0.9802; `session.functions_matched` 8353; `session.functions_recovered` 9186; `session.import_peak_kb` 228664; `session.import_wall_s` 45.0100; `session.inference_analyzed` 1770; `session.language_is_powerpc_be32` 1.0000; `session.listing_rows` 16; `session.memory_bytes` 8; `session.oracle_functions` 8522; `session.page_ms` 312.1910; `session.worker_recycles` 10; `session.xrefs_rows` 1 | `tests/m11-001_game_session.py` |
| `m11-002.json` | `m11-002` | M11 | pass | boot.elf: 694 functions in 2.8 s, recall 0.9472 precision 0.8790 over 644 symbols, 5 decompiled (median 25 ms), 1206 inferred; base.elf: 694 functions in 2.8 s, recall 0.9472 precision 0.8790 over 644 symbols, 5 decompiled (median 22 ms), 1206 inferred; Movie.elf: 1678 functions in 7.1 s, recall 0.9550 precision 0.7849 over 1379 symbols, 5 decompiled (median 21 ms), 2415 inferred; driving.elf: 5954 functions in 25.4 s, recall 0.9669 precision 0.9172 over 5648 symbols, 5 decompiled (median 28 ms), 1498 inferred | `tests/m11-002_game_modules.py` |
| `m12-001-modules.json` | `m12-001` | M12 | recorded | recorded | `tests/m12-001_diff.py` |
| `m12-001.json` | `m12-001` | M12 | recorded | recorded | `tests/m12-001_diff.py` |
| `m12-002.json` | `m12-002` | M12 | pass | recorded | `tests/m12-002_cross_compiler.py` |
| `m13-001-rerun-20261008.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-001-rerun-20261009-before-fix.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-001-rerun-20261009.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-001.json` | `m13-001` | M13 | recorded | recorded | `tests/m13-001_vsa_switch.py` |
| `m13-002.json` | `m13-002` | M13 | recorded | `import_wall_s` 74.8000 | `tests/m13-002_manifest_switch.py` |
| `m14-001.json` | `m14-001` | M14 | recorded | recorded | `tests/m14-001_interactive_import.py` |
| `m14-002.json` | `m14-002` | M14 | pass | `batch_seconds` 185.2540; `bodies_inventing_xrefs` 0; `first_open_seconds` 0.3640; `load_seconds` 1.8540; `median_analyse_seconds` 0.0150; `median_decompile_seconds` 0.1820; `median_total_seconds` 0.1990; `sampled` 20; `size_exact_vs_batch` 20; `size_overruns_vs_batch` 0; `walked` 20; `worst_total_seconds` 1.1640; `xref_sets_identical_to_batch` 20 | `tests/m14-002_demand.py` |
| `m14-003.json` | `m14-003` | M14 | pass | `analysed_in_pass` 100; `budgeted_pass_seconds` 4.0740; `libc_functions` 3898; `libc_seeded_at_load` 3898; `load_seconds` 1.3770; `revision_moved` 100; `small_analysed` 405; `small_finish_seconds` 4.6630; `small_functions` 405; `small_rounds_to_finish` 3; `small_undecodable` 0 | `tests/m14-003_facts_so_far.py` |
| `m14-004.json` | `m14-004` | M14 | pass | `analysed` 405; `final_shown` analysed: 405; `first_shown` provisional: 0 analysed, 405 to go; `polls_while_filling` 24; `seconds` 4.3210; `seeded` 0; `stale` False | `tests/m14-004_ui_progress.py` |
| `m15-001.json` | `m15-001` | M15 | pass | `answered` 400; `block_disagreements_without_tables` 0; `comparable` 394; `duplicated_tails` 321; `functions_we_structure_better` 121; `functions_we_structure_worse` 58; `functions_with_gotos` 198; `our_unstructured_edges` 1998; `ours_over_stock` 0.7907; `refused` 0; `scored` 400; `stock_unstructured_edges` 2527; `table_functions_that_agree` 0; `with_tables` 6; `without_tables` 388; `worst_regression` 6 | `tests/m15-001_structuring.py` |
| `m16-001.json` | `m16-001` | M16 | pass | `conservative_rate` 0.9559; `exact` 43; `exact_rate` 0.6324; `scored` 68; `silent` 0; `wrong` 3; `wrong_rate` 0.0441 | `tests/m16-001_types.py` |
| `m16-002.json` | `m16-002` | M16 | recorded | recorded | `tests/m16-002_indirect_calls.py` |
| `m17-001.json` | `m17-001` | M17 | pass | recorded | `tests/m17-001_cfg_functions.py` |
| `m17-002.json` | `m17-002` | M17 | pass | recorded | `tests/m17-002_producer_classes.py` |
| `m18-001.json` | `m18-001` | M18 | recorded | recorded | `tests/m18-001_robust_dispatch.py` |
| `m18-002.json` | `m18-002` | M18 | recorded | recorded | `tests/m18-002_zlib_match.py` |
| `m18-003.json` | `m18-003` | M18 | pass | recorded | `tests/m18-003_scale.py` |
| `m19-001.json` | `m19-001` | M19 | recorded | recorded | `tests/m19-001_pe_import.py` |
| `m19-002.json` | `m19-002` | M19 | recorded | recorded | `tests/m19-002_failure_classes.py` |
| `m19-003.json` | `m19-003` | M19 | recorded | recorded | `tests/m19-003_byte_scan.py` |
| `m19-004.json` | `m19-004` | M19 | recorded | recorded | `tests/m19-004_breadth.py` |
| `m2-002-g8.json` | `m2-002` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-002_context.py` |
| `m2-002-h.json` | `m2-002` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-002_context.py` |
| `m2-003.json` | `m2-003` | M2 | pass | 20 pass, 0 fail, 0 skipped | - |
| `m2-004.json` | `m2-004` | M2 | recorded | recorded | - |
| `m2-005.json` | `m2-005` | M2 | recorded | recorded | `tests/m2-005_prototype.py` |
| `m2-006-aarch64.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006-i386.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006-powerpc.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006-x86_64.json` | `m2-006` | M2 | recorded | `budget_ms` 60000 | `tests/m2-006_inference.py` |
| `m2-006.json` | `m2-006` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-006_inference.py` |
| `m2-006-reference.json` | `m2-006-b2-reference` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-006_inference.py` |
| `m2-007-positive.json` | `m2-007` | M2 | pass | recorded | `tests/m2-007_switches.py` |
| `m2-007.json` | `m2-007` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-007_switches.py` |
| `m2-008-aarch64.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008-i386.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008-positive.json` | `m2-008` | M2 | pass | `asserted_return_controls` 2; `inferred_functions` 5; `removed_call_xrefs` 3; `restored_call_xrefs` 3 | `tests/m2-008_nonreturn.py` |
| `m2-008-powerpc.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008-x86_64.json` | `m2-008` | M2 | recorded | recorded | `tests/m2-008_nonreturn.py` |
| `m2-008.json` | `m2-008` | M2 | pass | 20 pass, 0 fail, 0 skipped | `tests/m2-008_nonreturn.py` |
| `m2-009.json` | `m2-009` | M2 | pass | 1 pass, 0 fail, 0 skipped | `tests/m2-009_thunks.py` |
| `m2-011.json` | `m2-011` | M2 | pass | 4 pass, 0 fail, 0 skipped | - |
| `m2-012.json` | `m2-012` | M2 | pass | 3 pass, 0 fail, 0 skipped | - |
| `m2-013.json` | `m2-013` | M2 | pass | 8 pass, 0 fail, 1 skipped | - |
| `m2-014.json` | `m2-014` | M2 | pass | 2 pass, 0 fail, 5 skipped | - |
| `m2-015.json` | `m2-015` | M2 | pass | `decompile` 1; `decompile-doc` 1; `disasm` 4; `functions` 12 | `tests/m2-015_native_default.py` |
| `m2-016.json` | `m2-016` | M2 | pass | `flow.seconds` 2.8605; `references.speedup` 2.9409; `total.seconds` 9.2999 | `tests/m2-016_import_budget.py` |
| `m20-001.json` | `m20-001` | M20 | pass | `agreement` 0.9946; `elf_symbols` 11019; `map_rows` 12050; `named_recall` 0.9946 | `tests/m20-001_cw_map.py` |
| `m20-002.json` | `m20-002` | M20 | pass | `map_names` 818; `named_recall` 0.9976 | `tests/m20-002_psyq_map.py` |
| `m20-003.json` | `m20-003` | M20 | pass | `map_names` 5280; `named_recall` 1.0000 | `tests/m20-003_gnuld_map.py` |
| `m20-005.json` | `m20-005` | M20 | pass | `dwarf1_subroutines` 5221; `functions` 8795; `symtab_func` 8794 | `tests/m20-005_flat_map.py` |
| `m20-006.json` | `m20-006` | M20 | pass | `bare_functions` 572; `mapped_functions` 29488 | `tests/m20-006_dtk_roundtrip.py` |
| `m20-012.json` | `m20-012` | M20 | pass | `scalar` 849/849; `vector` 64/64 | `tests/m20-012_rsp.py` |
| `m20-013.json` | `m20-013` | M20 | pass | `gte` 328/328; `vu` 0/0 | `tests/m20-013_vector.py` |
| `m20-014.json` | `m20-014` | M20 | pass | recorded | `tests/m20-014_rel.py` |
| `m20-015.json` | `m20-015` | M20 | pass | recorded | `tests/m20-015_objdiff_units.py` |
| `m20-016.json` | `m20-016` | M20 | pass | recorded | `tests/m20-016_gc_disc.py` |
| `m21-001_combined_20261012.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_combined_compiler_rules_20261012.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_old_20261012.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_stage2.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m21-001_structs_20261013.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `pc_import_m21_gate_20261015.json` | `m21-001` | M21 | recorded | recorded | `tests/m21-001_real_images.py` |
| `m22-003_dc.json` | `m22-003_dc` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dc_fix2.json` | `m22-003_dc_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dc_fix3.json` | `m22-003_dc_fix3` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dds.json` | `m22-003_dds` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dds_fix2.json` | `m22-003_dds_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dds_romonly.json` | `m22-003_dds_romonly` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dk.json` | `m22-003_dk` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dk_fix2.json` | `m22-003_dk_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_dk_fix3.json` | `m22-003_dk_fix3` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_failure_classes.json` | `m22-003_failure_classes` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff.json` | `m22-003_ff` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix2.json` | `m22-003_ff_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix3.json` | `m22-003_ff_fix3` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix4.json` | `m22-003_ff_fix4` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_ff_fix5.json` | `m22-003_ff_fix5` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_gh.json` | `m22-003_gh` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_gh_fix2.json` | `m22-003_gh_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4.json` | `m22-003_p4` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4-eegcc.json` | `m22-003_p4-eegcc` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4-eegcc_fix2.json` | `m22-003_p4-eegcc_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4-eegcc_on_m22-002_sample.json` | `m22-003_p4-eegcc_on_m22-002_sample` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_fix2.json` | `m22-003_p4_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_on_m22-002_sample.json` | `m22-003_p4_on_m22-002_sample` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_on_m22-002_sample_seed20261011.json` | `m22-003_p4_on_m22-002_sample_seed20261011` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_p4_seed20261011.json` | `m22-003_p4_seed20261011` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rc.json` | `m22-003_rc` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rc_fix2.json` | `m22-003_rc_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rcpal.json` | `m22-003_rcpal` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m22-003_rcpal_fix2.json` | `m22-003_rcpal_fix2` | M22 | recorded | recorded | `tests/m22-003_ps2_multigame_c.py` |
| `m23-001_compiler_detection.json` | `m23-001_compiler_detection` | M23 | recorded | recorded | `tests/m23-001_new_project_ps2.py` |
| `m23-001_new_project_ps2.json` | `m23-001_new_project_ps2` | M23 | recorded | recorded | `tests/m23-001_new_project_ps2.py` |
| `m3-001.json` | `m3-001` | M3 | pass | 20 pass, 0 fail, 0 skipped | `tests/m3-001_dwarf_truth.py` |
| `baseline-ghidra-truth.json` | `m3-002` | M3 | recorded | `dwarf.arity_matched` 1640; `dwarf.functions` 1640; `ghidra.arity_correct` 1236; `ghidra.dwarf.fn.recall` 1.0000; `ghidra.dwarf.proto.arity` 0.7537; `ghidra.entries_matched` 1640; `ghidra.functions` 2008 | `tests/m3-002_baseline.py` |
| `m3-003.json` | `m3-003` | M3 | pass | 20 pass, 0 fail | `tests/m3-003_regression.py` |
| `m4-001.json` | `m4-001` | M4 | pass | recorded | `tests/m4-001_register_params.py` |
| `m4-002.json` | `m4-002` | M4 | pass | `improvement.arity_correct_native_default` 1236; `improvement.arity_correct_native_enabled` 1637; `improvement.arity_correct_stock` 1236; `improvement.arity_truth_functions` 1640; `improvement.passes_default_off` 2; `improvement.passes_gated` 2; `improvement.residual_dead_parameters` 3 | `tests/m4-002_improvement_milestone.py` |
| `m4-003.json` | `m4-003` | M4 | pass | `parity.class.data-name-convention` 4; `parity.class.data-type-unknown` 4; `parity.class.language-variant` 3; `parity.class.name-convention` 11; `parity.class.name-rendering` 12; `parity.class.oracle-warning` 23; `parity.class.type-stronger` 66; `parity.functions_compared` 2292; `parity.functions_fact_attributed` 96; `parity.functions_token_identical` 2196; `parity.functions_unattributed` 0; `parity.languages_blocked` 1; `parity.languages_bundled` 9; `parity.languages_measured` 6; `parity.languages_unreached` 2; `parity.rows_measured` 21 | `tests/m4-003_language_parity.py` |
| `m4-004.json` | `m4-004` | M4 | pass | `data.fallback_names` 0; `data.invented_labels` 0; `data.labels_rendered` 1; `data.slots_rendered` 1; `data.strings_rendered` 1 | `tests/m4-004_data_names.py` |
| `m4-005.json` | `m4-005` | M4 | pass | `flow.functions_untouched` 6; `flow.jumptable_warnings` 0; `flow.thunks_direct` 1; `flow.thunks_linkage` 1; `flow.unreachable_warnings` 0 | `tests/m4-005_thunk_flow.py` |
| `m4-006.json` | `m4-006` | M4 | pass | `plt.overrides` 1; `plt.pe_overrides` 0; `plt.resolver_slot` 2111720; `plt.thunks_unchanged` 2 | `tests/m4-006_plt_header.py` |
| `m4-007.json` | `m4-007` | M4 | pass | `got.overlap_warnings` 0; `got.pe_definitions` 0; `got.pointer_width` 8; `got.reserved_definitions` 3 | `tests/m4-007_got_pointers.py` |
| `m4-009.json` | `m4-009` | M4 | pass | `library.declared_functions` 6627; `library.invented_prototypes` 0; `library.typed_imports` 1 | `tests/m4-009_library_prototypes.py` |
| `m4-010.json` | `m4-010` | M4 | pass | `stubs.jumptable_warnings` 0; `stubs.linkage_stubs` 8; `stubs.overrides` 14; `stubs.rows_measured` 3 | `tests/m4-010_stub_transfers.py` |
| `m4-011.json` | `m4-011` | M4 | pass | `render.field_extractions` 0; `render.no_return_facts` 1; `render.pointer_widths` 2; `render.sanitised_names` 2 | `tests/m4-011_widths_exits_names.py` |
| `m4-012.json` | `m4-012` | M4 | pass | `entry` 00201590; `rendered` void processEntry _entry(undefined8 param_1,undefined8 param_2) | `tests/m4-012_remaining_facts.py` |
| `m4-013.json` | `m4-013` | M4 | pass |  | `tests/m4-013_shared_returns.py` |
| `m4-014.json` | `m4-014` | M4 | pass | `broken_sibling` tive runtime: worker failed (exit status: 3): this worker is deliberately broken; `explicit_override` tive runtime: worker failed (exit status: 3): this worker is deliberately broken; `sibling` /* WARNING: Removing unreachable block (ram,0x0040040f) *//* WARNING: Removing u; `workspace_agreement` 14 | `tests/m4-014_worker_resolution.py` |
| `m4-015.json` | `m4-015` | M4 | pass | `named_in_text` 13; `overlap_warnings` 0; `rows` 4; `widths_recorded` 19 | `tests/m4-015_reference_widths.py` |
| `m4-016.json` | `m4-016` | M4 | pass |  | `tests/m4-016_class_direction.py` |
| `m4-017.json` | `m4-017` | M4 | pass | `symbol_wins` _start | `tests/m4-017_entry_names.py` |
| `m4-018.json` | `m4-018` | M4 | pass | `agreed_return_type` int; `oracle_prototypes` 2 | `tests/m4-018_oracle_prototypes.py` |
| `m4-019.json` | `m4-019` | M4 | pass |  | `tests/m4-019_prototype_direction.py` |
| `m4-020.json` | `m4-020` | M4 | pass | `data_labels` 5 | `tests/m4-020_label_prefixes.py` |
| `m4-021.json` | `m4-021` | M4 | pass |  | `tests/m4-021_initializer_slots.py` |
| `m4-023.json` | `m4-023` | M4 | pass | `language.rows_identical_to_stock` 6; `language.rows_measured` 7; `language.rows_stock_unconstrained` 1; `language.rows_unexplained` 0 | `tests/m4-023_language_selection.py` |
| `m4-024.json` | `m4-024` | M4 | pass | `exception.ranges_invented` 0; `exception.ranges_missing` 0; `exception.ranges_recorded` 4; `exception.rows_measured` 8; `exception.rows_with_ranges` 4 | `tests/m4-024_exception_annotations.py` |
| `m4-025.json` | `m4-025` | M4 | pass | `declaration.applied_with_other_types` 0; `declaration.declared_by_stock` 23; `declaration.held` 23; `declaration.noreturn_recorded_as_facts` 5; `declaration.rows_measured` 20; `declaration.signatures_printed_as_stock` 23; `declaration.unexpressible_declarations_refused` 235 | `tests/m4-025_declaration_types.py` |
| `m4-027.json` | `m4-027` | M4 | pass | `pointer.rows_measured` 20; `pointer.slots_held` 37; `pointer.slots_invented` 0; `pointer.slots_missing` 0; `pointer.slots_stock_types` 37 | `tests/m4-027_pointer_slots.py` |
| `m4-028.json` | `m4-028` | M4 | pass | `demangle.mangled_names_kept` 4; `demangle.names_held` 4; `demangle.names_invented` 0; `demangle.names_missing` 0; `demangle.names_stock_derives` 4; `demangle.rows_measured` 20 | `tests/m4-028_demangled_names.py` |
| `m4-029.json` | `m4-029` | M4 | pass | `tags.names_held` 243; `tags.names_invented` 0; `tags.names_missing` 0; `tags.names_stock_holds` 243; `tags.rows_measured` 20 | `tests/m4-029_dynamic_tags.py` |
| `m4-030.json` | `m4-030` | M4 | pass | `pointee.code_pointers` 116; `pointee.plain_pointers` 74; `pointee.rows_measured` 20; `pointee.under_typed` 0; `pointee.unproven` 0 | `tests/m4-030_pointer_targets.py` |
| `m4-031.json` | `m4-031` | M4 | pass | `coined.invented` 0; `coined.misplaced` 0; `coined.names` 14; `coined.rows_measured` 20; `coined.shadowed` 0 | `tests/m4-031_section_names.py` |
| `m5-001.json` | `m5-001` | M5 | pass | `dwarf.fn.recall` 1.0000; `dwarf.functions` 6; `functions` 7; `unattributed` 0 | `tests/m5-001_gba.py` |
| `m5-002.json` | `m5-002` | M5 | pass | imported nds.arm9 natively (5 functions, ARM:LE:32:v5t)
imported nds.arm7 natively (3 functions, ARM:LE:32:v4t) | `tests/m5-002_nds.py` |
| `m5-003.json` | `m5-003` | M5 | pass | `dwarf.fn.recall` 1.0000; `dwarf.functions` 5; `functions` 5; `unattributed` 0 | `tests/m5-003_psx.py` |
| `m5-004.json` | `m5-004` | M5 | pass | `dwarf.fn.recall` 1.0000; `dwarf.functions` 5; `functions` 5; `unattributed` 0 | `tests/m5-004_n64.py` |
| `m5-005.json` | `m5-005` | M5 | pass | `blocked_platforms` 5; `catalog_platforms` 5; `generated_rows` 4 | `tests/m5-005_platform_matrix.py` |
| `m5-006.json` | `m5-006` | M5 | pass | `flow_xref.call.precision` 1.0000; `flow_xref.call.recall` 0.9830; `flow_xref.jump.cross_recall` 1.0000; `flow_xref.jump.precision` 1.0000; `loops_excluded` 2; `transfers_recorded` 1 | `tests/m5-006_tailcall.py` |
| `m5-007.json` | `m5-007` | M5 | pass | `arm7.dwarf.fn.recall` 1.0000; `corpus_unattributed` 0; `promoted` 037f8000 | `tests/m5-007_tailcall_promotion.py` |
| `m5-008.json` | `m5-008` | M5 | pass | `thunk.destination.equal` 114; `thunk.destination.explained` 71; `thunk.destination.unexplained` 0; `thunk.entry.exact` 0.9343; `thunk.entry.precision` 1.0000; `thunk.entry.recall` 1.0000; `thunk.entry.unexplained` 0 | `tests/m5-008_thunk_parity.py` |
| `m5-009.json` | `m5-009` | M5 | pass | `linkage.name.agreement` 1.0000; `linkage.name.missing_import` 0; `linkage.name.presentation` 0; `linkage.name.unexplained` 0; `linkage.name.unsupported` 0 | `tests/m5-009_linkage_names.py` |
| `m5-010.json` | `m5-010` | M5 | pass | `initializer.name.agreement` 0.9553; `initializer.name.equivalent` 74; `initializer.name.missing` 0; `initializer.name.pattern_labels` 11; `initializer.name.unbacked` 0; `initializer.name.unexplained` 0; `initializer.slots` 40 | `tests/m5-010_initializer_names.py` |
| `m5-011.json` | `m5-011` | M5 | pass | `pattern.label.applied` 11; `pattern.label.disagreed` 0; `pattern.label.missing` 0; `pattern.label.spurious` 0 | `tests/m5-011_pattern_labels.py` |
| `m5-012.json` | `m5-012` | M5 | pass | `current_reports` 104; `diagnostic_runs` 12; `generated_rows` 103; `published_ids` 87 | `tests/m5-012_evidence_index.py` |
| `m5-013.json` | `m5-013` | M5 | pass | `arm9.module_bytes` 1122040; `arm9.stored_bytes` 762644; `fn.precision` 0.9909; `fn.recall` 0.6924; `fn.recovered` 7700; `fn.symbols` 11019 | `tests/m5-013_nds.py` |
| `m5-017.json` | `m5-017` | M5 | recorded | `functions` 43487; `language` AARCH64:LE:64:v8A; `stock_ratio` 0.9608; `switch_dispatches` 690; `symbol_precision` 0.9755; `symbol_recall` 1.0000; `symbols` 42423; `wall_seconds` 1333.5000 | `tests/m5-017_switch_module.py` |
| `m6-001.json` | `m6-001` | M6 | pass | `commands` 24; `output_lines` 37; `skipped_blocks` 0; `verbs` 63 | `tests/m6-001_documented_workflow.py` |
| `m6-002.json` | `m6-002` | M6 | pass | `exchanges` 14; `skipped_blocks` 0 | `tests/m6-002_documented_api.py` |
| `m6-003.json` | `m6-003` | M6 | pass | `ui.install.prefix_ok` True; `ui.install.store_only_ok` True; `ui.list.filter_ms` 16.1084; `ui.list.load_ms` 22.6387; `ui.source.fold_reverse_sync` True; `ui.source.follow_rename` True; `ui.source.hints_excluded_from_copy` True; `ui.source.read_only` True; `ui.source.selection_copy` True | `tests/m6-003_desktop_package.py` |
| `m6-004.json` | `m6-004` | M6 | pass | `artifacts` 5; `commands` 6; `listed_platforms` 15; `project_pinned_tools` 2; `sbom_packages` 466 | `tests/m6-004_release_artifacts.py` |
| `m6-005.json` | `m6-005` | M6 | pass | `client_helpers` 23; `commands` 1; `output_lines` 8 | `tests/m6-005_scripting.py` |
| `m6-006.json` | `m6-006` | M6 | pass | `excused_blocks` 51; `gated_pages` 6; `metric_names` 496; `pages` 28; `surfaces` 18 | `tests/m6-006_documentation_coverage.py` |
| `m6-007.json` | `m6-007` | M6 | pass | `ui.match.best_percent` 1.7635; `ui.match.compiled_rows` 7; `ui.match.compiles` 6; `ui.match.decompiles` 7; `ui.match.default_percent` 1.5991; `ui.match.function` FUN_00405380; `ui.match.ms` 11267.2242; `ui.match.rendered_rows` 7; `ui.match.root_follows_project` True; `ui.match.rows` 7; `ui.new_project.config` True; `ui.new_project.files` 13; `ui.new_project.image` project_image; `ui.new_project.job_logged` True; `ui.new_project.ms` 1402.4391; `ui.new_project.readme` True | `tests/m6-007_desktop_projects.py` |
| `m7-001.json` | `m7-001` | M7 | pass | `cost.native.peak_kb.median` 36090.0000; `cost.native.wall_s.median` 0.2670; `cost.peak_ratio.median` 12.0900; `cost.stock.peak_kb.median` 423274.0000; `cost.stock.wall_s.median` 8.4260; `cost.wall_ratio.median` 29.7000 | `tests/m7-001_cost_envelope.py` |
| `m7-002.json` | `m7-002` | M7 | pass | `decompile.native.peak_kb.median` 34594.0000; `decompile.native.wall_s.median` 0.0910; `decompile.peak_ratio.median` 8.3200; `decompile.stock.peak_kb.median` 286368.0000; `decompile.stock.wall_s.median` 5.9330; `decompile.wall_ratio.median` 74.0300 | `tests/m7-002_decompile_envelope.py` |
| `m7-003.json` | `m7-003` | M7 | pass | `session.drift_excess_ms.max` -0.8630; `session.drift_ratio.max` 1.6800; `session.growth_kb.max` 28; `session.growth_kb.median` 14.0000; `session.latency_ms.decompile_doc.median` 6.0020; `session.latency_ms.functions.median` 0.2650; `session.latency_ms.memory_regions.median` 0.2600; `session.latency_ms.search.median` 0.3890; `session.latency_ms.strings.median` 0.4670; `session.latency_ms.symbols.median` 0.1590; `session.latency_ms.xrefs.median` 0.1880; `session.peak_kb.median` 42940.0000 | `tests/m7-003_session_envelope.py` |
| `m8-001.json` | `m8-001` | M8 | pass | `pe.dwarf.fn.recall` 1.0000; `pe.dwarf.fn.unattributed` 0 | `tests/m8-001_pe_unwind.py` |
| `m8-002.json` | `m8-002` | M8 | pass | `ghidra.dwarf.fn.recall` 0.7634; `ghidra.functions` 106; `pe32.dwarf.fn.recall` 0.8065; `pe32.dwarf.fn.unattributed` 0; `pe32.functions` 110; `pe32.undescribed` 35 | `tests/m8-002_pe32_roots.py` |
| `m8-003.json` | `m8-003` | M8 | pass | `body.crossing` 0 | `tests/m8-003_body_extents.py` |
| `m8-004.json` | `m8-004` | M8 | pass | `pe.exports` 3; `pe.exports.forwarded` 0; `pe.exports.forwarder_functions` 0; `pe.exports.misnamed` 0; `pe.exports.missing` 0; `pe.exports.unproven` 0; `pe.tls.callbacks` 8; `pe.tls.missing` 0; `pe.tls.unproven` 0 | `tests/m8-004_pe_roots.py` |
| `m8-005.json` | `m8-005` | M8 | pass | `pe.imports.bound_descriptors` 0; `pe.imports.declared` 166; `pe.imports.libraries` 8; `pe.imports.misnamed` 0; `pe.imports.missing` 0; `pe.imports.not_external` 0; `pe.imports.unnamed_stubs` 0 | `tests/m8-005_pe_imports.py` |
| `m8-006.json` | `m8-006` | M8 | pass | `pe.classes.declared` 4; `pe.classes.unexercised` 0; `pe.classes.unmeasured` 0; `pe.externals` 260; `pe.references` 865 | `tests/m8-006_pe_parity.py` |
| `m9-001.json` | `m9-001` | M9 | pass | `provenance.api_facts_checked` 10; `provenance.classes` 18; `provenance.declared` 18; `provenance.observed` 11; `provenance.unexplained` 0; `ui.xrefs.rows` 19; `ui.xrefs.unexplained` 0 | `tests/m9-001_provenance_explained.py` |
| `m9-002.json` | `m9-002` | M9 | pass | `evidence.attributed.native-analysis:constant-propagation` 1.0000; `evidence.attributed.native-import` 1.0000; `evidence.attributed.native-import:branch` 1.0000; `evidence.attributed.native-import:elf-got` 1.0000; `evidence.attributed.native-import:elf-pointer` 1.0000; `evidence.attributed.native-import:elf-reloc` 1.0000; `evidence.attributed.native-import:elf-unwind` 1.0000; `evidence.attributed.native-import:pe-export` 1.0000; `evidence.attributed.native-import:pe-reloc` 1.0000; `evidence.attributed.native-import:pe-tls` 1.0000; `evidence.attributed.native-import:pe-unwind` 1.0000; `evidence.attributed.native-import:thunk` 1.0000; `evidence.classes` 31; `evidence.declared` 19; `evidence.declared_elsewhere` 11; `evidence.declared_exercised` 8; `evidence.references` 4669; `evidence.unbacked_confidence` 0 | `tests/m9-002_fact_confidence.py` |
| `m9-003.json` | `m9-003` | M9 | pass | `filter.addresses` 20; `filter.facts_matched` 104; `filter.images` 5; `filter.kinds` 3; `filter.symbols_matched` 135 | `tests/m9-003_evidence_filter.py` |
| `m9-004.json` | `m9-004` | M9 | pass | `surface.cli_rows_checked` 12; `surface.committed_ui_declared_rows` 13; `surface.narrowing_addresses` 2; `surface.ui_declared_rows` 0; `surface.ui_rows` 1 | `tests/m9-004_filter_surfaces.py` |
| `m9-005.json` | `m9-005` | M9 | pass | `explanation.methods_answered` 28; `explanation.methods_published` 52; `explanation.printed_sources` 5; `explanation.silent_facts` 0; `explanation.window_declared_rows` 13; `explanation.window_unexplained` 0 | `tests/m9-005_explanation_milestone.py` |
<!-- evidence-index:end -->
