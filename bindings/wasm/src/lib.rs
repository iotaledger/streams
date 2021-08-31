// WASM needed imports
pub mod types;

pub mod author;

pub mod subscriber;

pub mod user;

use wasm_bindgen::prelude::*;

// Used for sleep()
use js_sys::Promise;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

#[wasm_bindgen]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
    #[wasm_bindgen(js_namespace = console)]
    pub fn error(s: &str);
}

pub async fn wait(ms: i32) -> Result<(), JsValue> {
    let promise = Promise::new(&mut |yes, _| {
        let win = window().unwrap();
        win.set_timeout_with_callback_and_timeout_and_arguments_0(&yes, ms)
            .unwrap();
    });
    let js_fut = JsFuture::from(promise);
    js_fut.await?;
    Ok(())
}

// Unused currently
// macro_rules! console_log {
// Note that this is using the `log` function imported above during
// `bare_bones`
// ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
// }
