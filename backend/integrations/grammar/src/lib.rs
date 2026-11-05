//! Harper's offline English grammar checks for the Huma Mac app (extra/Sources/Huma/GrammarChecker.swift loads this
//! library from the app's Resources/Grammar). Two functions: lint some text, and free the reply.
//!
//! The reply is a JSON array of problems: `{"start", "end", "kind", "message", "fix"}`. `start` and `end` are UTF-16
//! offsets (what AppKit's NSRange counts); `fix` is the text that should replace that range, or null when Harper
//! has no single fix. Spelling and typo checks are left to the Mac, which already underlines misspellings.

use std::ffi::{c_char, CStr, CString};
use std::sync::Mutex;

use harper_core::linting::{LintGroup, Linter, Suggestion};
use harper_core::spell::FstDictionary;
use harper_core::{Dialect, Document};

/// Made once (loading the dictionary takes a moment) and reused for every check.
static LINTER: Mutex<Option<LintGroup>> = Mutex::new(None);

/// Lints UTF-8 `text` and returns a JSON reply, which the caller frees with `huma_grammar_free`.
///
/// # Safety
/// `text` must be a valid, NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn huma_grammar_lint(text: *const c_char) -> *mut c_char {
    let reply = std::panic::catch_unwind(|| {
        if text.is_null() {
            return "[]".to_string();
        }
        let Ok(text) = (unsafe { CStr::from_ptr(text) }).to_str() else { return "[]".to_string() };
        lint(text, false).to_string()
    })
    .unwrap_or_else(|_| "[]".to_string());
    CString::new(reply).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Like `huma_grammar_lint`, with spelling too: for the browser, which has no spell checker of its own to rely on
/// (the Mac underlines misspellings itself). Spelling problems have the kind "Spelling" or "Typo".
///
/// # Safety
/// `text` must be a valid, NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn huma_grammar_lint_spelling(text: *const c_char) -> *mut c_char {
    let reply = std::panic::catch_unwind(|| {
        if text.is_null() {
            return "[]".to_string();
        }
        let Ok(text) = (unsafe { CStr::from_ptr(text) }).to_str() else { return "[]".to_string() };
        lint(text, true).to_string()
    })
    .unwrap_or_else(|_| "[]".to_string());
    CString::new(reply).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Frees a reply from `huma_grammar_lint`.
///
/// # Safety
/// `reply` must come from `huma_grammar_lint` and be freed once.
#[no_mangle]
pub unsafe extern "C" fn huma_grammar_free(reply: *mut c_char) {
    if !reply.is_null() {
        drop(unsafe { CString::from_raw(reply) });
    }
}

/// The browser's copy (huma.social/write, web/write/grammar-worker.mjs) has no C allocator to borrow: the page asks
/// for room for its text here and gives it back after.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn huma_grammar_alloc(length: usize) -> *mut u8 {
    let mut room = Vec::<u8>::with_capacity(length.max(1));
    let pointer = room.as_mut_ptr();
    std::mem::forget(room);
    pointer
}

// Harper draws random numbers (rand's thread generator); in the browser they come from the page (`huma.random`, which
// fills them with crypto.getRandomValues), since WebAssembly has no source of its own.
#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "huma")]
extern "C" {
    fn random(destination: *mut u8, length: usize);
}

/// getrandom's hook for a source of its own (built with `--cfg getrandom_backend="custom"`).
///
/// # Safety
/// `destination` must point to `length` writable bytes.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(destination: *mut u8, length: usize) -> Result<(), getrandom::Error> {
    unsafe { random(destination, length) };
    Ok(())
}

/// Gives back room from `huma_grammar_alloc`.
///
/// # Safety
/// `pointer` must come from `huma_grammar_alloc(length)` and be given back once.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn huma_grammar_dealloc(pointer: *mut u8, length: usize) {
    drop(unsafe { Vec::from_raw_parts(pointer, 0, length.max(1)) });
}

fn lint(text: &str, spelling: bool) -> serde_json::Value {
    let mut guard = LINTER.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let linter = guard.get_or_insert_with(|| LintGroup::new_curated(FstDictionary::curated(), Dialect::American));
    let document = Document::new_plain_english_curated(text);
    // Harper counts characters (Unicode scalars); AppKit counts UTF-16 units.
    let mut utf16 = Vec::with_capacity(text.len() + 1);
    let mut offset = 0;
    for character in text.chars() {
        utf16.push(offset);
        offset += character.len_utf16();
    }
    utf16.push(offset);
    let chars: Vec<char> = text.chars().collect();
    let problems: Vec<serde_json::Value> = linter
        .lint(&document)
        .into_iter()
        .filter(|lint| spelling || !matches!(format!("{:?}", lint.lint_kind).as_str(), "Spelling" | "Typo"))
        .filter(|lint| lint.span.start < lint.span.end && lint.span.end <= chars.len())
        .map(|lint| {
            let original: String = chars[lint.span.start..lint.span.end].iter().collect();
            let fix = lint.suggestions.first().map(|suggestion| match suggestion {
                Suggestion::ReplaceWith(replacement) => replacement.iter().collect::<String>(),
                Suggestion::InsertAfter(insert) => original.clone() + &insert.iter().collect::<String>(),
                Suggestion::Remove => String::new(),
            });
            // Every fix Harper has, best first: a misspelling's first guess is often not the word meant.
            let fixes: Vec<String> = lint.suggestions.iter().take(5).map(|suggestion| match suggestion {
                Suggestion::ReplaceWith(replacement) => replacement.iter().collect::<String>(),
                Suggestion::InsertAfter(insert) => original.clone() + &insert.iter().collect::<String>(),
                Suggestion::Remove => String::new(),
            }).collect();
            serde_json::json!({
                "start": utf16[lint.span.start], "end": utf16[lint.span.end],
                "kind": format!("{:?}", lint.lint_kind), "message": lint.message, "fix": fix, "fixes": fixes,
            })
        })
        .collect();
    serde_json::Value::Array(problems)
}
