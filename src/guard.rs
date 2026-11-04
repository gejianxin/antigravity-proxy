use std::cell::Cell;

std::thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

pub struct Guard;

impl Guard {
    pub fn enter() -> Self {
        DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Guard
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

pub fn in_hook() -> bool {
    DEPTH.with(|d| d.get() > 0)
}
