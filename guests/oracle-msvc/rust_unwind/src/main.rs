//! Windows-oracle probe: Rust panics on `x86_64-pc-windows-msvc`, which
//! unwind as MSVC C++ exceptions (`_CxxThrowException` and
//! `__CxxFrameHandler3`): drops during unwinding, `catch_unwind`,
//! `resume_unwind` payloads, nested catches, and thread panics observed by
//! `join`. Built by guests/build-msvc-oracle.sh.
use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};

static DROPS: AtomicUsize = AtomicUsize::new(0);

struct Guard(&'static str);
impl Drop for Guard {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
        println!("drop: {}", self.0);
    }
}

#[inline(never)]
fn deep(depth: u32) {
    let _guard = Guard("deep");
    if depth == 0 {
        panic!("bottom");
    }
    deep(depth - 1);
}

fn message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("?")
}

fn main() {
    println!("probe rust_unwind");
    panic::set_hook(Box::new(|info| println!("hook: {}", message(info.payload()))));
    let caught = panic::catch_unwind(|| {
        let _guard = Guard("outer");
        deep(3);
    });
    println!("catch_unwind: {}", caught.is_err());
    println!("drops: {}", DROPS.load(Ordering::SeqCst));
    let resumed = panic::catch_unwind(|| {
        let inner = panic::catch_unwind(|| panic!("inner"));
        println!("nested: {}", inner.is_err());
        panic::resume_unwind(Box::new(42u32));
    });
    println!(
        "resume_unwind: {:?}",
        resumed.err().and_then(|p| p.downcast::<u32>().ok()).map(|b| *b)
    );
    println!("no_panic: {:?}", panic::catch_unwind(|| 7).ok());
    let joined = std::thread::spawn(|| {
        let _guard = Guard("thread");
        panic!("in thread")
    })
    .join();
    println!("thread_join: {}", joined.is_err());
    println!("END");
}
