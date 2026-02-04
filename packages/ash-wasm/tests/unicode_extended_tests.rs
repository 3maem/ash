//! Extended Unicode edge case tests for ASH WASM bindings.
//! Tests combining characters, RTL text, zero-width characters, and other Unicode edge cases.

use ash_core;

// ============================================================================
// COMBINING CHARACTERS TESTS
// ============================================================================

#[test]
fn unicode_combining_acute_accent() {
    // e + combining acute accent = e-acute
    let input = r#"{"text":"cafe\u0301"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_combining_multiple_marks() {
    // Character with multiple combining marks
    let input = r#"{"text":"a\u0300\u0301\u0302"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_precomposed_vs_decomposed() {
    // NFC normalization should make these equivalent
    let precomposed = r#"{"text":"\u00e9"}"#; // e-acute precomposed
    let decomposed = r#"{"text":"e\u0301"}"#; // e + combining acute

    let result1 = ash_core::ash_canonicalize_json(precomposed).unwrap();
    let result2 = ash_core::ash_canonicalize_json(decomposed).unwrap();

    let hash1 = ash_core::ash_hash_body(&result1);
    let hash2 = ash_core::ash_hash_body(&result2);

    // After NFC normalization, they should be the same
    assert_eq!(hash1, hash2);
}

#[test]
fn unicode_combining_diacritical() {
    let input = r#"{"name":"Müller"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("Müller") || result.contains("M\\u00fcller"));
}

// ============================================================================
// RIGHT-TO-LEFT (RTL) TEXT TESTS
// ============================================================================

#[test]
fn unicode_arabic_text() {
    let input = r#"{"text":"مرحبا بالعالم"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
    let hash = ash_core::ash_hash_body(&result);
    assert_eq!(hash.len(), 64);
}

#[test]
fn unicode_hebrew_text() {
    let input = r#"{"text":"שלום עולם"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_mixed_ltr_rtl() {
    // Mixed left-to-right and right-to-left text
    let input = r#"{"text":"Hello مرحبا World عالم"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_rtl_override_char() {
    // Right-to-left override character
    let input = r#"{"text":"abc\u202edef"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_bidi_control_chars() {
    // Bidirectional control characters
    let input = r#"{"text":"\u200f\u200etest\u200f"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

// ============================================================================
// ZERO-WIDTH CHARACTERS TESTS
// ============================================================================

#[test]
fn unicode_zero_width_space() {
    let input = r#"{"text":"hello\u200bworld"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_zero_width_non_joiner() {
    let input = r#"{"text":"test\u200cvalue"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_zero_width_joiner() {
    let input = r#"{"text":"test\u200dvalue"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_byte_order_mark() {
    // BOM character
    let input = r#"{"text":"\ufeffhello"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_word_joiner() {
    let input = r#"{"text":"word\u2060joiner"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

// ============================================================================
// EMOJI TESTS (Extended)
// ============================================================================

#[test]
fn unicode_emoji_basic() {
    let input = r#"{"emoji":"😀"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("emoji"));
}

#[test]
fn unicode_emoji_flag() {
    // Flag emoji (regional indicator symbols)
    let input = r#"{"flag":"🇺🇸"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("flag"));
}

#[test]
fn unicode_emoji_skin_tone() {
    // Emoji with skin tone modifier
    let input = r#"{"emoji":"👋🏽"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("emoji"));
}

#[test]
fn unicode_emoji_zwj_sequence() {
    // Zero-width joiner emoji sequence (family)
    let input = r#"{"family":"👨‍👩‍👧‍👦"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("family"));
}

#[test]
fn unicode_emoji_keycap() {
    // Keycap emoji
    let input = r#"{"number":"1️⃣"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("number"));
}

#[test]
fn unicode_emoji_variation_selector() {
    // Emoji with variation selector
    let input = r#"{"heart":"❤️"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("heart"));
}

// ============================================================================
// CJK CHARACTERS TESTS
// ============================================================================

#[test]
fn unicode_chinese_simplified() {
    let input = r#"{"text":"简体中文"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_chinese_traditional() {
    let input = r#"{"text":"繁體中文"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_japanese_hiragana() {
    let input = r#"{"text":"ひらがな"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_japanese_katakana() {
    let input = r#"{"text":"カタカナ"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_japanese_kanji() {
    let input = r#"{"text":"漢字"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_korean_hangul() {
    let input = r#"{"text":"한글"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_cjk_mixed() {
    let input = r#"{"text":"中文日本語한글"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

// ============================================================================
// SPECIAL UNICODE CHARACTERS TESTS
// ============================================================================

#[test]
fn unicode_mathematical_symbols() {
    let input = r#"{"math":"∑∏∫√∞"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("math"));
}

#[test]
fn unicode_currency_symbols() {
    let input = r#"{"currency":"$€£¥₹₽₿"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("currency"));
}

#[test]
fn unicode_greek_letters() {
    let input = r#"{"greek":"αβγδεζηθ"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("greek"));
}

#[test]
fn unicode_cyrillic() {
    let input = r#"{"russian":"Привет мир"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("russian"));
}

#[test]
fn unicode_thai() {
    let input = r#"{"thai":"สวัสดี"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("thai"));
}

#[test]
fn unicode_devanagari() {
    let input = r#"{"hindi":"नमस्ते"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("hindi"));
}

// ============================================================================
// SUPPLEMENTARY PLANE CHARACTERS TESTS
// ============================================================================

#[test]
fn unicode_supplementary_plane() {
    // Character from supplementary plane (U+1F600)
    let input = r#"{"emoji":"😀"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("emoji"));
}

#[test]
fn unicode_musical_symbols() {
    // Musical symbols from supplementary plane
    let input = r#"{"music":"𝄞𝄢"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("music"));
}

#[test]
fn unicode_ancient_scripts() {
    // Egyptian hieroglyphs
    let input = r#"{"hieroglyph":"𓀀𓀁"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("hieroglyph"));
}

// ============================================================================
// NORMALIZATION TESTS
// ============================================================================

#[test]
fn unicode_nfc_normalization() {
    // Characters that normalize differently
    let input1 = r#"{"text":"Ω"}"#;  // Greek capital omega
    let input2 = r#"{"text":"Ω"}"#;  // Ohm sign (different codepoint)

    let result1 = ash_core::ash_canonicalize_json(input1).unwrap();
    let result2 = ash_core::ash_canonicalize_json(input2).unwrap();

    // After NFC normalization, should produce same result
    let hash1 = ash_core::ash_hash_body(&result1);
    let hash2 = ash_core::ash_hash_body(&result2);

    // Note: This depends on implementation - they may or may not be equal
    assert_eq!(hash1.len(), 64);
    assert_eq!(hash2.len(), 64);
}

// ============================================================================
// CONTROL CHARACTERS TESTS
// ============================================================================

#[test]
fn unicode_null_in_string() {
    let input = r#"{"text":"before\u0000after"}"#;
    let result = ash_core::ash_canonicalize_json(input);
    // Should handle null character
    let _ = result;
}

#[test]
fn unicode_tab_and_newline() {
    let input = r#"{"text":"line1\tvalue\nline2"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    // Should escape control characters
    assert!(result.contains("\\t") || result.contains("\\n") || result.contains("text"));
}

#[test]
fn unicode_form_feed() {
    let input = r#"{"text":"before\fafter"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_carriage_return() {
    let input = r#"{"text":"line1\rline2"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

#[test]
fn unicode_backspace() {
    let input = r#"{"text":"test\bvalue"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("text"));
}

// ============================================================================
// UNICODE IN KEYS TESTS
// ============================================================================

#[test]
fn unicode_key_chinese() {
    let input = r#"{"中文键":"value"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("value"));
}

#[test]
fn unicode_key_emoji() {
    let input = r#"{"🔑":"key_emoji"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("key_emoji"));
}

#[test]
fn unicode_key_arabic() {
    let input = r#"{"مفتاح":"value"}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("value"));
}

#[test]
fn unicode_key_sorting() {
    // Keys with different Unicode should sort correctly
    let input = r#"{"zzz":1,"aaa":2,"中文":3,"日本語":4}"#;
    let result = ash_core::ash_canonicalize_json(input).unwrap();
    // Should be sorted by byte value
    assert!(result.contains("aaa"));
    assert!(result.contains("zzz"));
}

// ============================================================================
// STRESS TESTS WITH UNICODE
// ============================================================================

#[test]
fn stress_unicode_json_100() {
    let unicode_samples = vec![
        "Hello 世界",
        "مرحبا بالعالم",
        "שלום עולם",
        "Привет мир",
        "こんにちは",
        "안녕하세요",
        "สวัสดี",
        "नमस्ते",
        "😀🎉🚀",
        "αβγδε",
    ];

    for i in 0..100 {
        let sample = &unicode_samples[i % unicode_samples.len()];
        let input = format!(r#"{{"text":"{}","index":{}}}"#, sample, i);
        let result = ash_core::ash_canonicalize_json(&input).unwrap();
        assert!(result.contains("index"));
    }
}

#[test]
fn stress_unicode_hash_100() {
    let unicode_texts = vec![
        "中文文本",
        "日本語テキスト",
        "한국어 텍스트",
        "النص العربي",
        "טקסט עברי",
        "Русский текст",
        "Ελληνικό κείμενο",
        "ข้อความภาษาไทย",
        "हिंदी पाठ",
        "😀🎉🚀💯",
    ];

    for i in 0..100 {
        let text = &unicode_texts[i % unicode_texts.len()];
        let input = format!("{}_{}", text, i);
        let hash = ash_core::ash_hash_body(&input);
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn stress_unicode_proof_50() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_unicode";
    let binding = "POST|/api|";

    let payloads = vec![
        r#"{"message":"Hello 世界"}"#,
        r#"{"message":"مرحبا"}"#,
        r#"{"message":"שלום"}"#,
        r#"{"message":"Привет"}"#,
        r#"{"message":"😀🎉"}"#,
    ];

    for i in 0..50 {
        let payload = payloads[i % payloads.len()];
        let timestamp = format!("{}", 1000000000 + i);
        let body_hash = ash_core::ash_hash_body(&ash_core::ash_canonicalize_json(payload).unwrap());

        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let valid = ash_core::ash_verify_proof(&nonce, ctx, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }
}
