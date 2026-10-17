//! Discovery over the programs of one container.
//!
//! A container's programs (a DS cartridge's processors and overlays, a GBA
//! cartridge's overlay programs, a disc's REL modules, an N64 ROM's overlay
//! segments) are independent analyses: each has its own mapped bytes, its own
//! decoder lanes, its own contexts and its own result. The only dependency
//! between them is an image its siblings call into (`sibling_call_host`),
//! which is seeded from their finished results and so runs last. Each
//! program's analysis is a pure function of its own image and the
//! configuration, so running programs side by side changes the wall time and
//! nothing else: the results, and the order they are stored in, are the
//! container's.
//!
//! How many programs run at once is the one number that depends on the host,
//! and it is not an input to any result; `ROMWRIGHT_PROGRAM_JOBS` fixes it.
//! The switch stage's worker processes are bounded process-wide
//! (`switch_tables::SwitchSlots`), so side-by-side programs do not multiply
//! the peak memory of the decompiler workers.
use super::{NativeImport, Result, discover, seed_from_siblings};
use romwright_model::ProgramInput;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The most programs analysed at once when the host has the cores for it.
const MOST_JOBS: usize = 4;

/// Stack of a program thread: discovery recurses over control flow, and the
/// main thread's own stack is what it has always had.
const STACK_BYTES: usize = 64 << 20;

/// Programs analysed at once: `ROMWRIGHT_PROGRAM_JOBS`, else half the cores,
/// between one and `MOST_JOBS`.
fn jobs() -> usize {
    std::env::var("ROMWRIGHT_PROGRAM_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|&jobs| jobs > 0)
        .unwrap_or_else(|| {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            (cores / 2).clamp(1, MOST_JOBS)
        })
}

/// `discover`, with the program's whole analysis time as its own phase (the
/// stage phases do not add up to it: decoder construction, stores and the
/// switch workers' setup sit between them).
fn analyse_program(imp: &mut NativeImport) -> Result<()> {
    let started = std::time::Instant::now();
    let outcome = discover(imp);
    imp.phases.push(romwright_model::PhaseTiming {
        phase: "discover-wall".into(),
        seconds: started.elapsed().as_secs_f64(),
    });
    outcome
}

/// Binds every image of a container to its input and, when `analyse`, analyses
/// it, in place. Images whose siblings call into them are seeded from those
/// siblings and discovered after everything else; the rest are independent and
/// run on up to `jobs()` threads. The first error in container order is the one
/// returned.
pub(crate) fn discover_all(
    images: &mut [(String, NativeImport)],
    project: &Path,
    input: &ProgramInput,
    analyse: bool,
) -> Result<()> {
    for (suffix, imp) in images.iter_mut() {
        let mut selected = input.clone();
        selected.image_selector = suffix.clone();
        imp.input_context = Some(std::sync::Arc::new((project.to_path_buf(), selected)));
        if analyse {
            imp.analysed = true;
            // The loader's "not analysed" note no longer holds.
            imp.diagnostics
                .retain(|diagnostic| !diagnostic.message.starts_with("loaded without analysis"));
        }
    }
    if !analyse {
        return Ok(());
    }
    crate::native_runtime::set_single_program(images.len() == 1);
    let hosts: Vec<usize> = (0..images.len()).filter(|&index| images[index].1.sibling_call_host).collect();
    let independent: Vec<&mut (String, NativeImport)> = images
        .iter_mut()
        .filter(|(_, imp)| !imp.sibling_call_host)
        .collect();
    run_independent(independent, jobs())?;
    for index in hosts {
        let mut host = std::mem::take(&mut images[index].1);
        let siblings: Vec<&NativeImport> = images
            .iter()
            .enumerate()
            .filter(|&(other, _)| other != index)
            .map(|(_, (_, sibling))| sibling)
            .collect();
        seed_from_siblings(&mut host, &siblings);
        images[index].1 = host;
        analyse_program(&mut images[index].1)?;
    }
    if images.len() == 1 {
        // Nothing analyses after this program: its decoders are done, and
        // their tables are memory the store that follows can use.
        crate::native_runtime::release_idle_decoders();
    }
    Ok(())
}


/// Discovers `programs` side by side. The largest programs start first, so
/// the one that takes longest is not left for the end; each thread takes the
/// next from that order. Results are collected per program and the first error
/// in container order wins, as it did when they ran one after another.
fn run_independent(programs: Vec<&mut (String, NativeImport)>, jobs: usize) -> Result<()> {
    let jobs = jobs.min(programs.len());
    if jobs <= 1 {
        for (_, imp) in programs {
            analyse_program(imp)?;
        }
        return Ok(());
    }
    let mut queue: Vec<usize> = (0..programs.len()).collect();
    let weight = |index: usize| programs[index].1.mappings.iter().map(|mapping| mapping.bytes.len()).sum::<usize>();
    queue.sort_by_cached_key(|&index| (std::cmp::Reverse(weight(index)), index));
    let slots: Vec<Mutex<Option<&mut (String, NativeImport)>>> =
        programs.into_iter().map(|program| Mutex::new(Some(program))).collect();
    let outcomes: Vec<Mutex<Option<Result<()>>>> = slots.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            std::thread::Builder::new()
                .stack_size(STACK_BYTES)
                .spawn_scoped(scope, || while let Some(&index) = queue.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let program = slots[index].lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
                    let Some((_, imp)) = program else { continue };
                    let outcome = analyse_program(imp);
                    *outcomes[index].lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(outcome);
                })
                .expect("a program thread starts");
        }
    });
    for outcome in outcomes {
        if let Some(Err(error)) = outcome.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner()) {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ProgramInput {
        ProgramInput {
            source_path: "container".into(),
            binary_digest: "0".repeat(64),
            image_selector: String::new(),
            map_digest: None,
            raw: None,
            keys_digest: None,
        }
    }

    /// Every program of a container is analysed once whatever the number of
    /// threads, bound to its own selector, with the loader's "not analysed"
    /// note withdrawn; an image the others call into is analysed too.
    #[test]
    fn every_program_is_analysed_once_whatever_the_thread_count() {
        for jobs in [1, 3, 16] {
            let mut images: Vec<(String, NativeImport)> = (0..7)
                .map(|index| {
                    let mut imp = NativeImport::default();
                    imp.diagnose(romwright_model::DiagnosticSeverity::Info, "load", "loaded without analysis: a symbol table");
                    imp.sibling_call_host = index == 2;
                    (format!("ov{index}"), imp)
                })
                .collect();
            let independent: Vec<&mut (String, NativeImport)> =
                images.iter_mut().filter(|(_, imp)| !imp.sibling_call_host).collect();
            run_independent(independent, jobs).unwrap();
            let host = images.iter().position(|(_, imp)| imp.sibling_call_host).unwrap();
            assert!(images[host].1.phases.is_empty(), "the host waits for the others (jobs {jobs})");
            discover_all(&mut images, Path::new("project"), &input(), true).unwrap();
            for (suffix, imp) in &images {
                let walks = imp.phases.iter().filter(|phase| phase.phase == "discover-wall").count();
                // Run once by `run_independent` and again by `discover_all`,
                // except the host, which only the second did.
                assert_eq!(walks, if imp.sibling_call_host { 1 } else { 2 }, "{suffix} (jobs {jobs})");
                assert!(imp.analysed);
                let context = imp.input_context.as_ref().expect("bound to its input");
                assert_eq!(&context.1.image_selector, suffix);
                assert!(!imp.diagnostics.iter().any(|d| d.message.starts_with("loaded without analysis")));
            }
        }
    }

    /// Without analysis the images are bound to their input and nothing runs.
    #[test]
    fn a_load_without_analysis_only_binds_the_input() {
        let mut images = vec![("arm9".to_string(), NativeImport::default())];
        discover_all(&mut images, Path::new("project"), &input(), false).unwrap();
        assert!(!images[0].1.analysed && images[0].1.phases.is_empty());
        assert_eq!(images[0].1.input_context.as_ref().unwrap().1.image_selector, "arm9");
    }
}
