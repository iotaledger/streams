#![feature(alloc_error_handler)]
#![no_std]
#![no_main]
// Required to use the `alloc` crate and its types, the `abort` intrinsic, and a
// custom panic handler.
#![feature(core_intrinsics, lang_items)]

extern crate alloc;
extern crate wee_alloc;

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Need to provide a tiny `panic_fmt` lang-item implementation for `#![no_std]`.
// This implementation will translate panics into traps in the resulting
// WebAssembly.
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
// core::intrinsics::abort()
// }
//
// #[alloc_error_handler]
// fn alloc_error(_: core::alloc::Layout) -> ! {
// core::intrinsics::abort()
// }
//
// #[lang = "eh_personality"]
// extern "C" fn eh_personality() {}

#[no_mangle]
pub extern "C" fn WinMainCRTStartup() -> () {
    WinMain()
}

#[no_mangle]
pub extern "C" fn WinMain() -> () {
    minmain()
}

// TODO: fix msvc link error: __chkstk, memcpy, memmove, memset, memcmp symbols not resolved
//
// #[link(name = "libcmt", kind = "static")]
// extern "C" {}
// #[link(name = "libucrt", kind = "static")]
// extern "C" {}
// #[link(name = "libcmt", kind = "static")]
// extern {
// fn memcpy(dest: *mut u8, _src: *const u8, _n: usize) -> *mut u8;
// fn memmove(dest: *mut u8, _src: *const u8, _n: usize) -> *mut u8;
// fn memset(mem: *mut u8, _val: i32, _n: usize) -> *mut u8;
// fn memcmp(_mem1: *const u8, _mem2: *const u8, _n: usize) -> i32;
// }

#[no_mangle]
pub unsafe extern "C" fn __chkstk() {
    // Do not check stack; just crash?
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dest != 0 as *mut u8 && src != 0 as *const u8 {
        for i in 0..n {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dest != 0 as *mut u8 && src != 0 as *const u8 {
        if dest as *const u8 <= src {
            for i in 0..n {
                *dest.add(i) = *src.add(i);
            }
        } else {
            for i in (0..n).rev() {
                *dest.add(i) = *src.add(i);
            }
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(mem: *mut u8, val: i32, n: usize) -> *mut u8 {
    if mem != 0 as *mut u8 {
        for i in 0..n {
            *mem.add(i) = val as u8;
        }
    }
    mem
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(mem1: *const u8, mem2: *const u8, n: usize) -> i32 {
    if mem1 != 0 as *const u8 && mem2 != 0 as *const u8 {
        for i in 0..n {
            use core::cmp::Ordering;
            match (&*mem1.add(i)).cmp(&*mem2.add(i)) {
                Ordering::Equal => continue,
                Ordering::Less => return -1,
                Ordering::Greater => return 1,
            }
        }
    }
    0
}

use iota_streams::app_channels::api::tangle::{
    test::example,
    BucketTransport,
};

fn minmain() {
    let transport = BucketTransport::new();
    let _r = example(transport);
    // assert!(dbg!(r).is_ok());
}
