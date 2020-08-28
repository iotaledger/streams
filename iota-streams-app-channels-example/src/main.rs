#![feature(alloc_error_handler)]
#![no_std]
#![no_main]
// Required to use the `alloc` crate and its types, the `abort` intrinsic, and a
// custom panic handler.
#![feature(core_intrinsics, lang_items)]

#[macro_use]
extern crate alloc;
extern crate wee_alloc;

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Need to provide a tiny `panic_fmt` lang-item implementation for `#![no_std]`.
// This implementation will translate panics into traps in the resulting
// WebAssembly.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::intrinsics::abort() }
}

#[alloc_error_handler]
fn alloc_error(_: core::alloc::Layout) -> ! {
    unsafe { core::intrinsics::abort() }
}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

#[no_mangle]
pub extern "C" fn WinMainCRTStartup() -> () {
    WinMain()
}

#[no_mangle]
pub extern "C" fn WinMain() -> () {
    minmain()
}

//TODO: fix msvc link error: __chkstk, memcpy, memmove, memset, memcmp symbols not resolved

#[no_mangle]
pub unsafe extern "C" fn __chkstk() {
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, _src: *const u8, _n: usize) -> *mut u8 {
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, _src: *const u8, _n: usize) -> *mut u8 {
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(mem: *mut u8, _val: i32, _n: usize) -> *mut u8 {
    mem
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(_mem1: *const u8, _mem2: *const u8, _n: usize) -> i32 {
    0
}

use iota_streams_app::transport::BucketTransport;
use iota_streams_app_channels::api::tangle::test::example;

fn minmain() {
    let mut transport = BucketTransport::new();
    let _r = example(&mut transport);
    // assert!(dbg!(r).is_ok());
}
