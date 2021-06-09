// WASM needed imports
pub mod types;

pub mod author;

pub mod subscriber;

pub mod user;

use wasm_bindgen::prelude::*;

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

pub async fn wait(ms: u32) {
    let mut date = js_sys::Date::new_0();
    let now = date.get_milliseconds();
    loop {
        date = js_sys::Date::new_0();
        if (date.get_milliseconds() - now) >= ms {
            break;
        }
    }
}

// Unused currently
// macro_rules! console_log {
// Note that this is using the `log` function imported above during
// `bare_bones`
// ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
// }
