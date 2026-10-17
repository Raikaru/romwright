//! libstdc++'s `std::sort` (introsort, threshold 16, final insertion sort),
//! step for step: `Merge::mergeLinear` sorts HighVariables with a comparator
//! that has ties, and the order of tied elements is whatever the library's
//! partitioning leaves. A function whose sort would run out of depth (heap
//! sort) is refused instead of guessed.

const THRESHOLD: usize = 16;

pub fn sort_cxx<T: Clone>(v: &mut [T], less: &mut dyn FnMut(&T, &T) -> bool) -> Result<(), String> {
    let n = v.len();
    if n < 2 {
        return Ok(());
    }
    let depth = 2 * (usize::BITS - 1 - n.leading_zeros()) as usize;
    introsort_loop(v, 0, n, depth, less)?;
    final_insertion_sort(v, 0, n, less);
    Ok(())
}

fn introsort_loop<T: Clone>(
    v: &mut [T],
    first: usize,
    mut last: usize,
    mut depth: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) -> Result<(), String> {
    while last - first > THRESHOLD {
        if depth == 0 {
            partial_sort(v, first, last, less);
            return Ok(());
        }
        depth -= 1;
        let cut = unguarded_partition_pivot(v, first, last, less);
        introsort_loop(v, cut, last, depth, less)?;
        last = cut;
    }
    Ok(())
}

fn unguarded_partition_pivot<T: Clone>(
    v: &mut [T],
    first: usize,
    last: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) -> usize {
    let mid = first + (last - first) / 2;
    move_median_to_first(v, first, first + 1, mid, last - 1, less);
    unguarded_partition(v, first + 1, last, first, less)
}

fn move_median_to_first<T: Clone>(
    v: &mut [T],
    result: usize,
    a: usize,
    b: usize,
    c: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) {
    if less(&v[a], &v[b]) {
        if less(&v[b], &v[c]) {
            v.swap(result, b);
        } else if less(&v[a], &v[c]) {
            v.swap(result, c);
        } else {
            v.swap(result, a);
        }
    } else if less(&v[a], &v[c]) {
        v.swap(result, a);
    } else if less(&v[b], &v[c]) {
        v.swap(result, c);
    } else {
        v.swap(result, b);
    }
}

fn unguarded_partition<T: Clone>(
    v: &mut [T],
    mut first: usize,
    mut last: usize,
    pivot: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) -> usize {
    loop {
        while less(&v[first], &v[pivot]) {
            first += 1;
        }
        last -= 1;
        while less(&v[pivot], &v[last]) {
            last -= 1;
        }
        if first >= last {
            return first;
        }
        v.swap(first, last);
        first += 1;
    }
}

fn final_insertion_sort<T: Clone>(
    v: &mut [T],
    first: usize,
    last: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) {
    if last - first > THRESHOLD {
        insertion_sort(v, first, first + THRESHOLD, less);
        for i in first + THRESHOLD..last {
            unguarded_linear_insert(v, i, less);
        }
    } else {
        insertion_sort(v, first, last, less);
    }
}

fn insertion_sort<T: Clone>(
    v: &mut [T],
    first: usize,
    last: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) {
    if first == last {
        return;
    }
    for i in first + 1..last {
        if less(&v[i], &v[first]) {
            let val = v[i].clone();
            for k in (first..i).rev() {
                v[k + 1] = v[k].clone();
            }
            v[first] = val;
        } else {
            unguarded_linear_insert(v, i, less);
        }
    }
}

fn unguarded_linear_insert<T: Clone>(
    v: &mut [T],
    last: usize,
    less: &mut dyn FnMut(&T, &T) -> bool,
) {
    let val = v[last].clone();
    let mut last = last;
    let mut next = last - 1;
    while less(&val, &v[next]) {
        v[last] = v[next].clone();
        last = next;
        if next == 0 {
            break;
        }
        next -= 1;
    }
    v[last] = val;
}

// ---- heap sort (the fallback when introsort runs out of depth) ----

fn partial_sort<T: Clone>(v: &mut [T], first: usize, last: usize, less: &mut dyn FnMut(&T, &T) -> bool) {
    // __partial_sort(first, last, last) = __heap_select (a make_heap) + __sort_heap
    make_heap(v, first, last, less);
    sort_heap(v, first, last, less);
}

fn make_heap<T: Clone>(v: &mut [T], first: usize, last: usize, less: &mut dyn FnMut(&T, &T) -> bool) {
    if last - first < 2 {
        return;
    }
    let len = last - first;
    let mut parent = (len - 2) / 2;
    loop {
        let value = v[first + parent].clone();
        adjust_heap(v, first, parent, len, value, less);
        if parent == 0 {
            return;
        }
        parent -= 1;
    }
}

fn adjust_heap<T: Clone>(
    v: &mut [T],
    first: usize,
    hole: usize,
    len: usize,
    value: T,
    less: &mut dyn FnMut(&T, &T) -> bool,
) {
    let top = hole;
    let mut hole = hole;
    let mut second = hole;
    while second < len.saturating_sub(1) / 2 {
        second = 2 * (second + 1);
        if less(&v[first + second], &v[first + second - 1]) {
            second -= 1;
        }
        v[first + hole] = v[first + second].clone();
        hole = second;
    }
    if len & 1 == 0 && second == (len - 2) / 2 {
        second = 2 * (second + 1);
        v[first + hole] = v[first + second - 1].clone();
        hole = second - 1;
    }
    // __push_heap
    let mut parent = if hole == 0 { 0 } else { (hole - 1) / 2 };
    while hole > top && less(&v[first + parent], &value) {
        v[first + hole] = v[first + parent].clone();
        hole = parent;
        parent = if hole == 0 { 0 } else { (hole - 1) / 2 };
    }
    v[first + hole] = value;
}

fn sort_heap<T: Clone>(v: &mut [T], first: usize, last: usize, less: &mut dyn FnMut(&T, &T) -> bool) {
    let mut last = last;
    while last - first > 1 {
        last -= 1;
        // __pop_heap(first, last, last)
        let value = v[last].clone();
        v[last] = v[first].clone();
        adjust_heap(v, first, 0, last - first, value, less);
    }
}
