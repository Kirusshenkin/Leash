//! Манифест сверяется с эталоном: лишнее разрешение или ослабленный CSP
//! валит тесты, а не проходит незамеченным.

const MANIFEST: &str = include_str!("../../../extension/manifest.json");

const CSP: &str = "\"extension_pages\": \"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
style-src 'self'; img-src 'self'; connect-src 'self' https://api.anthropic.com; \
form-action 'none'; base-uri 'none'\"";

fn count(needle: &str) -> usize {
    MANIFEST.matches(needle).count()
}

#[test]
fn permissions_are_exactly_the_reviewed_set() {
    assert_eq!(count("\"permissions\": [\"storage\", \"scripting\"]"), 1);
    assert_eq!(count("\"permissions\""), 1);
    assert_eq!(
        count("\"host_permissions\": [\"https://api.anthropic.com/*\"]"),
        1
    );
    assert_eq!(count("\"host_permissions\""), 1);
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
        "nativeMessaging",
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
