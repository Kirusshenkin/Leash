//! Манифест сверяется с эталоном: лишнее разрешение или ослабленный CSP
//! валит тесты, а не проходит незамеченным.

const MANIFEST: &str = include_str!("../../../extension/manifest.json");

const CSP: &str = "\"extension_pages\": \"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
style-src 'self'; img-src 'self'; connect-src 'self'; \
form-action 'none'; base-uri 'none'\"";

fn count(needle: &str) -> usize {
    MANIFEST.matches(needle).count()
}

#[test]
fn permissions_are_exactly_the_reviewed_set() {
    // nativeMessaging — только мост leash-host (allowed_extensions в его манифесте).
    assert_eq!(
        count("\"permissions\": [\"storage\", \"scripting\", \"nativeMessaging\"]"),
        1
    );
    assert_eq!(count("\"permissions\""), 1);
    // Своей сети у расширения нет: ни API, ни других адресов.
    assert_eq!(count("\"host_permissions\""), 0);
    assert_eq!(count("anthropic"), 0);
    // Сайты — только по одному, по запросу пользователя (permissions.request).
    assert_eq!(count("\"optional_host_permissions\": [\"https://*/*\"]"), 1);
    assert_eq!(count("\"optional_host_permissions\""), 1);
    assert_eq!(count("\"commands\""), 1);
    assert_eq!(count("\"leash-stop\""), 1);
    assert_eq!(count("\"incognito\": \"not_allowed\""), 1);
}

#[test]
fn csp_is_exactly_the_reviewed_policy() {
    assert_eq!(count(CSP), 1, "CSP отличается от эталона");
    assert_eq!(count("\"content_security_policy\""), 1);
}

#[test]
fn nothing_widens_the_surface() {
    for forbidden in [
        "content_scripts",
        "web_accessible_resources",
        "externally_connectable",
        "optional_permissions",
        "<all_urls>",
        "*://",
        "http://",
        "'unsafe-eval'",
        "unsafe-inline",
        "\"tabs\"",
        "activeTab",
        "cookies",
        "webRequest",
        "clipboard",
        "\"downloads\"",
        "\"history\"",
        "\"bookmarks\"",
        "\"webNavigation\"",
        "\"debugger\"",
        "\"proxy\"",
        "\"management\"",
        "http://*",
        "\"world\"",
    ] {
        assert_eq!(count(forbidden), 0, "в манифесте появилось {forbidden}");
    }
}

#[test]
fn publication_metadata_is_reviewed() {
    // ID после первой публикации на AMO не меняется.
    assert_eq!(
        count(&format!("\"id\": \"{}\"", leash_core::EXTENSION_ID)),
        1
    );
    assert_eq!(count("localhost"), 0);
    // AMO требует декларацию передачи данных: страницы и их адреса уходят
    // через мост в Claude, которым управляет пользователь.
    assert_eq!(
        count("\"required\": [\"websiteContent\", \"browsingActivity\"]"),
        1
    );
    assert_eq!(count("\"data_collection_permissions\""), 1);
    assert_eq!(count("\"optional\""), 0);
}
