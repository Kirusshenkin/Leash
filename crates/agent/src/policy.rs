//! Политика доступа к сайтам. Решение принимает этот код, а не модель.
//!
//! Сравнение — по точному origin: только https, хост и порт совпадают
//! буквально, без масок. Запрет сильнее разрешения: встроенный список
//! (банки, платежи, почта, менеджеры паролей, облачные консоли, входы в
//! аккаунты) пользователь снять не может. Сайт вне allowlist закрыт.
//!
//! Разбор адреса намеренно строже браузерного: всё, что браузер мог бы
//! прочитать иначе, чем мы (`@`, `\`, `%`, IP-адреса, не-ASCII), отклоняется.

use std::fmt;

/// Предел записей в каждом списке.
pub(crate) const MAX_ENTRIES: usize = 200;
/// Предел длины текста списка (поле ввода и хранилище).
pub(crate) const MAX_LIST_LEN: usize = 64 * 1024;

const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;
const DEFAULT_PORT: u16 = 443;
const SCHEME: &str = "https://";

/// Имена, которые разрешаются в локальной сети, а не в публичном DNS.
const LOCAL_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
    "home.arpa",
    "localdomain",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Category {
    Bank,
    Payment,
    Mail,
    Passwords,
    Cloud,
    Account,
    Government,
}

impl Category {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Bank => "банк",
            Self::Payment => "платежи и криптовалюта",
            Self::Mail => "почта",
            Self::Passwords => "менеджер паролей",
            Self::Cloud => "облачная консоль",
            Self::Account => "вход в аккаунт",
            Self::Government => "госуслуги",
        }
    }
}

/// Встроенный запрет. Хост закрыт вместе со всеми поддоменами.
pub(crate) const BUILTIN_DENY: &[(&str, Category)] = &[
    // Банки. Список не полон: пользователь дополняет его своим.
    ("chase.com", Category::Bank),
    ("bankofamerica.com", Category::Bank),
    ("wellsfargo.com", Category::Bank),
    ("citi.com", Category::Bank),
    ("hsbc.com", Category::Bank),
    ("barclays.co.uk", Category::Bank),
    ("monzo.com", Category::Bank),
    ("sberbank.ru", Category::Bank),
    ("sber.ru", Category::Bank),
    ("tbank.ru", Category::Bank),
    ("tinkoff.ru", Category::Bank),
    ("alfabank.ru", Category::Bank),
    ("vtb.ru", Category::Bank),
    ("gazprombank.ru", Category::Bank),
    ("raiffeisen.ru", Category::Bank),
    // Платежи и криптовалюта.
    ("paypal.com", Category::Payment),
    ("stripe.com", Category::Payment),
    ("wise.com", Category::Payment),
    ("revolut.com", Category::Payment),
    ("payoneer.com", Category::Payment),
    ("klarna.com", Category::Payment),
    ("venmo.com", Category::Payment),
    ("cash.app", Category::Payment),
    ("pay.google.com", Category::Payment),
    ("yoomoney.ru", Category::Payment),
    ("qiwi.com", Category::Payment),
    ("coinbase.com", Category::Payment),
    ("binance.com", Category::Payment),
    ("kraken.com", Category::Payment),
    ("bybit.com", Category::Payment),
    ("metamask.io", Category::Payment),
    // Почта.
    ("mail.google.com", Category::Mail),
    ("gmail.com", Category::Mail),
    ("outlook.live.com", Category::Mail),
    ("outlook.office.com", Category::Mail),
    ("outlook.office365.com", Category::Mail),
    ("mail.yahoo.com", Category::Mail),
    ("proton.me", Category::Mail),
    ("protonmail.com", Category::Mail),
    ("icloud.com", Category::Mail),
    ("fastmail.com", Category::Mail),
    ("tuta.com", Category::Mail),
    ("mail.ru", Category::Mail),
    ("mail.yandex.ru", Category::Mail),
    ("mail.yandex.com", Category::Mail),
    // Менеджеры паролей.
    ("1password.com", Category::Passwords),
    ("bitwarden.com", Category::Passwords),
    ("lastpass.com", Category::Passwords),
    ("dashlane.com", Category::Passwords),
    ("keepersecurity.com", Category::Passwords),
    ("nordpass.com", Category::Passwords),
    // Облачные консоли.
    ("aws.amazon.com", Category::Cloud),
    ("portal.azure.com", Category::Cloud),
    ("console.cloud.google.com", Category::Cloud),
    ("dash.cloudflare.com", Category::Cloud),
    ("cloud.digitalocean.com", Category::Cloud),
    ("console.yandex.cloud", Category::Cloud),
    ("console.anthropic.com", Category::Cloud),
    ("platform.claude.com", Category::Cloud),
    ("platform.openai.com", Category::Cloud),
    // Входы в аккаунты и браузерные сервисы.
    ("accounts.google.com", Category::Account),
    ("myaccount.google.com", Category::Account),
    ("login.microsoftonline.com", Category::Account),
    ("login.live.com", Category::Account),
    ("account.microsoft.com", Category::Account),
    ("appleid.apple.com", Category::Account),
    ("account.apple.com", Category::Account),
    ("passport.yandex.ru", Category::Account),
    ("id.yandex.ru", Category::Account),
    ("accounts.firefox.com", Category::Account),
    ("addons.mozilla.org", Category::Account),
    ("okta.com", Category::Account),
    ("auth0.com", Category::Account),
    // Госуслуги.
    ("gosuslugi.ru", Category::Government),
    ("nalog.gov.ru", Category::Government),
    ("login.gov", Category::Government),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginError {
    Empty,
    NotHttps,
    UserInfo,
    BadChars,
    BadPort,
    IpAddress,
    NotAscii,
    BadHost,
    SingleLabel,
    LocalName,
    HasPath,
}

impl OriginError {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Empty => "Пустой адрес.",
            Self::NotHttps => "Разрешён только https.",
            Self::UserInfo => "Адрес с логином (@) не принимается.",
            Self::BadChars => "Недопустимые символы в адресе сайта.",
            Self::BadPort => "Неверный порт.",
            Self::IpAddress => "IP-адреса не принимаются, только доменные имена.",
            Self::NotAscii => {
                "Национальные домены записываются в punycode (xn--…), как их показывает браузер."
            }
            Self::BadHost => "Неверное доменное имя.",
            Self::SingleLabel => "Имя без точки — это адрес локальной сети.",
            Self::LocalName => "Адреса локальной сети не принимаются.",
            Self::HasPath => "Указывается только сайт, без пути: https://example.com.",
        }
    }
}

/// Origin вида `https://host[:port]`. Хост в нижнем регистре, без точки на конце.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    host: String,
    port: u16,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == DEFAULT_PORT {
            write!(f, "{SCHEME}{}", self.host)
        } else {
            write!(f, "{SCHEME}{}:{}", self.host, self.port)
        }
    }
}

/// Origin адреса страницы. Путь, запрос и фрагмент отбрасываются.
pub(crate) fn parse_url(input: &str) -> Result<Origin, OriginError> {
    split_url(input).and_then(|(authority, _)| parse_authority(authority))
}

/// Делит адрес на authority и хвост (путь, запрос, фрагмент).
fn split_url(input: &str) -> Result<(&str, &str), OriginError> {
    if input.is_empty() {
        return Err(OriginError::Empty);
    }
    let rest = input
        .get(..SCHEME.len())
        .filter(|p| p.eq_ignore_ascii_case(SCHEME))
        .map(|_| &input[SCHEME.len()..])
        .ok_or(OriginError::NotHttps)?;
    // `\` браузер тоже считает разделителем пути, но здесь он остаётся
    // в authority и отклоняется как недопустимый символ.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Ok(rest.split_at(end))
}

fn parse_authority(authority: &str) -> Result<Origin, OriginError> {
    if authority.is_empty() {
        return Err(OriginError::BadHost);
    }
    if authority.contains('@') {
        return Err(OriginError::UserInfo);
    }
    if authority.starts_with('[') {
        return Err(OriginError::IpAddress);
    }
    if !authority.is_ascii() {
        return Err(OriginError::NotAscii);
    }
    if !authority
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(OriginError::BadChars);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, parse_port(port)?),
        None => (authority, DEFAULT_PORT),
    };
    let host = parse_host(host)?;
    if !host.contains('.') {
        return Err(OriginError::SingleLabel);
    }
    if LOCAL_SUFFIXES.iter().any(|s| under(&host, s)) {
        return Err(OriginError::LocalName);
    }
    Ok(Origin { host, port })
}

fn parse_port(port: &str) -> Result<u16, OriginError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OriginError::BadPort);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(OriginError::BadPort),
        Ok(p) => Ok(p),
    }
}

/// Доменное имя: метки из `[a-z0-9-]`, без IP-адресов в любой записи.
fn parse_host(input: &str) -> Result<String, OriginError> {
    if !input.is_ascii() {
        return Err(OriginError::NotAscii);
    }
    let host = input
        .strip_suffix('.')
        .unwrap_or(input)
        .to_ascii_lowercase();
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(OriginError::BadHost);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(OriginError::BadHost);
        }
    }
    // По WHATWG URL хост с числовой последней меткой (127.1, 0x7f.1)
    // разбирается как IPv4, а не как имя.
    let last = host.rsplit('.').next().unwrap_or(&host);
    let hex = last
        .strip_prefix("0x")
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    if hex || last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OriginError::IpAddress);
    }
    Ok(host)
}

/// `host` совпадает с `domain` или является его поддоменом.
fn under(host: &str, domain: &str) -> bool {
    host.strip_suffix(domain)
        .is_some_and(|head| head.is_empty() || head.ends_with('.'))
}

fn builtin_category(host: &str) -> Option<Category> {
    BUILTIN_DENY
        .iter()
        .find(|(domain, _)| under(host, domain))
        .map(|&(_, c)| c)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum List {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryError {
    Origin(OriginError),
    Builtin(Category),
    UserDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListError {
    TooLong(List),
    TooMany(List),
    Entry {
        list: List,
        line: usize,
        error: EntryError,
    },
}

impl ListError {
    pub(crate) fn describe(self) -> String {
        let name = |list| match list {
            List::Allow => "Разрешённые сайты",
            List::Deny => "Запрещённые сайты",
        };
        match self {
            Self::TooLong(list) => format!("{}: слишком длинный текст.", name(list)),
            Self::TooMany(list) => format!("{}: больше {MAX_ENTRIES} записей.", name(list)),
            Self::Entry { list, line, error } => {
                let why = match error {
                    EntryError::Origin(e) => e.describe().to_owned(),
                    EntryError::Builtin(c) => {
                        format!("Сайт во встроенном запрете ({}).", c.describe())
                    }
                    EntryError::UserDenied => "Сайт есть в списке запрещённых.".to_owned(),
                };
                format!("{}, строка {line}: {why}", name(list))
            }
        }
    }
}

/// Почему адрес закрыт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denied {
    BadUrl(OriginError),
    Builtin(Category),
    UserList,
    NotAllowed,
    NoPermission,
}

impl Denied {
    pub(crate) fn describe(self) -> String {
        match self {
            Self::BadUrl(e) => format!("Адрес не принят: {}", e.describe()),
            Self::Builtin(c) => format!("Закрыто встроенным запретом ({}).", c.describe()),
            Self::UserList => "Закрыто вашим списком запрещённых сайтов.".to_owned(),
            Self::NotAllowed => "Сайта нет в списке разрешённых.".to_owned(),
            Self::NoPermission => {
                "Firefox не выдал доступ к сайту. Сохраните списки в настройках ещё раз и разрешите доступ."
                    .to_owned()
            }
        }
    }
}

/// Доступ к сайту: запись в списке **и** host-разрешение, выданное Firefox.
///
/// Списки лежат в `storage.local`, куда content-скрипт может писать. Разрешение
/// выдаёт только браузер по клику пользователя, поэтому подменённая запись в
/// списке сама по себе доступа не открывает.
#[derive(Debug, Default)]
pub(crate) struct Access {
    policy: Policy,
    granted: Vec<String>,
}

impl Access {
    /// `granted` — `permissions.getAll().origins`. Маски с `*` в имени
    /// игнорируются: доступ даёт только точное имя.
    pub(crate) fn new(policy: Policy, granted: &[String]) -> Self {
        let granted = granted.iter().filter_map(|p| granted_host(p)).collect();
        Self { policy, granted }
    }

    pub(crate) fn check(&self, url: &str) -> Result<Origin, Denied> {
        let origin = self.policy.check(url)?;
        if self.granted.contains(&origin.host) {
            Ok(origin)
        } else {
            Err(Denied::NoPermission)
        }
    }
}

/// Хост из шаблона `https://host/*`.
fn granted_host(pattern: &str) -> Option<String> {
    let host = pattern.strip_prefix(SCHEME)?.strip_suffix("/*")?;
    parse_host(host).ok()
}

/// Шаблон host-разрешения для origin: порт в шаблонах не указывается,
/// точный порт проверяет `Policy`.
pub(crate) fn permission_pattern(origin: &Origin) -> String {
    format!("{SCHEME}{}/*", origin.host)
}

/// Списки доступа. Пустая политика закрывает всё.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    allow: Vec<Origin>,
    deny: Vec<String>,
}

impl Policy {
    /// Разбор текстов списков: по записи на строку, `#` — комментарий.
    /// Любая ошибка отклоняет всё целиком: частично принятых списков нет.
    pub(crate) fn parse(allow_text: &str, deny_text: &str) -> Result<Self, ListError> {
        let mut deny = Vec::new();
        for (line, entry) in entries(List::Deny, deny_text)? {
            let host = parse_deny_entry(entry).map_err(|error| ListError::Entry {
                list: List::Deny,
                line,
                error: EntryError::Origin(error),
            })?;
            if !deny.contains(&host) {
                deny.push(host);
            }
        }
        let mut policy = Self {
            allow: Vec::new(),
            deny,
        };
        for (line, entry) in entries(List::Allow, allow_text)? {
            let fail = |error| ListError::Entry {
                list: List::Allow,
                line,
                error,
            };
            let origin = parse_allow_entry(entry).map_err(|e| fail(EntryError::Origin(e)))?;
            if let Some(c) = builtin_category(&origin.host) {
                return Err(fail(EntryError::Builtin(c)));
            }
            if policy.user_denied(&origin.host) {
                return Err(fail(EntryError::UserDenied));
            }
            if !policy.allow.contains(&origin) {
                policy.allow.push(origin);
            }
        }
        Ok(policy)
    }

    /// Можно ли работать со страницей по этому адресу. Запрет проверяется
    /// раньше разрешения, поэтому ошибка в allowlist его не обходит.
    pub(crate) fn check(&self, url: &str) -> Result<Origin, Denied> {
        let origin = parse_url(url).map_err(Denied::BadUrl)?;
        if let Some(c) = builtin_category(&origin.host) {
            return Err(Denied::Builtin(c));
        }
        if self.user_denied(&origin.host) {
            return Err(Denied::UserList);
        }
        if self.allow.contains(&origin) {
            Ok(origin)
        } else {
            Err(Denied::NotAllowed)
        }
    }

    fn user_denied(&self, host: &str) -> bool {
        self.deny.iter().any(|d| under(host, d))
    }

    /// Канонический текст списка разрешённых: так он и сохраняется.
    pub(crate) fn allow_text(&self) -> String {
        let lines: Vec<String> = self.allow.iter().map(Origin::to_string).collect();
        lines.join("\n")
    }

    /// Канонический текст списка запрещённых.
    pub(crate) fn deny_text(&self) -> String {
        self.deny.join("\n")
    }

    pub(crate) fn allowed(&self) -> &[Origin] {
        &self.allow
    }

    /// Политика из хранилища. Неразборчивые списки закрывают всё.
    pub(crate) fn from_storage(allow: Option<&str>, deny: Option<&str>) -> Self {
        Self::parse(allow.unwrap_or_default(), deny.unwrap_or_default()).unwrap_or_default()
    }
}

/// Значащие строки списка с номерами (с 1).
fn entries(list: List, text: &str) -> Result<Vec<(usize, &str)>, ListError> {
    if text.len() > MAX_LIST_LEN {
        return Err(ListError::TooLong(list));
    }
    let found: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if found.len() > MAX_ENTRIES {
        return Err(ListError::TooMany(list));
    }
    Ok(found)
}

/// Запись allowlist: `https://host[:port]` или просто `host`, без пути.
fn parse_allow_entry(entry: &str) -> Result<Origin, OriginError> {
    let full;
    let url = if entry.contains("://") {
        entry
    } else {
        full = format!("{SCHEME}{entry}");
        &full
    };
    let (authority, tail) = split_url(url)?;
    if !tail.is_empty() && tail != "/" {
        return Err(OriginError::HasPath);
    }
    parse_authority(authority)
}

/// Запись denylist: доменное имя; закрывает его и все поддомены.
fn parse_deny_entry(entry: &str) -> Result<String, OriginError> {
    if entry.contains('@') {
        return Err(OriginError::UserInfo);
    }
    if entry.contains(['/', ':']) {
        return Err(OriginError::HasPath);
    }
    parse_host(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow: &str, deny: &str) -> Policy {
        Policy::parse(allow, deny).unwrap()
    }

    #[test]
    fn urls_are_reduced_to_origin() {
        let cases = [
            ("https://example.com", "https://example.com"),
            ("https://example.com/", "https://example.com"),
            ("HTTPS://Example.COM/Path?q=1#x", "https://example.com"),
            ("https://example.com.", "https://example.com"),
            ("https://example.com:443/", "https://example.com"),
            ("https://example.com:8443", "https://example.com:8443"),
            ("https://a-b.example.co.uk", "https://a-b.example.co.uk"),
            ("https://xn--80ak6aa92e.com", "https://xn--80ak6aa92e.com"),
            // Фрагмент отрезается до разбора: хост тут evil.com, как и у браузера.
            ("https://evil.com#@good.com", "https://evil.com"),
            ("https://evil.com?@good.com", "https://evil.com"),
        ];
        for (url, origin) in cases {
            assert_eq!(
                parse_url(url).map(|o| o.to_string()),
                Ok(origin.into()),
                "{url}"
            );
        }
    }

    #[test]
    fn suspicious_urls_are_rejected() {
        use OriginError::*;
        let cases = [
            ("", Empty),
            ("http://example.com", NotHttps),
            ("ftp://example.com", NotHttps),
            ("https:example.com", NotHttps),
            ("https:/example.com", NotHttps),
            ("javascript:alert(1)", NotHttps),
            ("data:text/html,x", NotHttps),
            ("file:///etc/passwd", NotHttps),
            ("moz-extension://abc/x", NotHttps),
            (" https://example.com", NotHttps),
            ("https://", BadHost),
            ("https:///example.com", BadHost),
            ("https://good.com@evil.com", UserInfo),
            ("https://user:pass@good.com", UserInfo),
            ("https://good.com\\@evil.com", UserInfo),
            ("https://good.com\\.evil.com", BadChars),
            ("https://good.com%2eevil.com", BadChars),
            ("https://good .com", BadChars),
            ("https://good_x.com", BadChars),
            ("https://good.com\t", BadChars),
            ("https://гугл.com", NotAscii),
            ("https://gооgle.com", NotAscii),
            ("https://example.com:", BadPort),
            ("https://example.com:0", BadPort),
            ("https://example.com:65536", BadPort),
            ("https://example.com:+443", BadChars),
            ("https://example.com:44:3", BadPort),
            ("https://127.0.0.1", IpAddress),
            ("https://127.1", IpAddress),
            ("https://0x7f.0.0.1", IpAddress),
            ("https://1.0x1", IpAddress),
            ("https://[::1]", IpAddress),
            ("https://2130706433", IpAddress),
            ("https://example", SingleLabel),
            ("https://0x7f000001", IpAddress),
            ("https://localhost", SingleLabel),
            ("https://app.localhost", LocalName),
            ("https://printer.local", LocalName),
            ("https://router.home.arpa", LocalName),
            ("https://-bad.com", BadHost),
            ("https://bad-.com", BadHost),
            ("https://a..com", BadHost),
            ("https://example.com..", BadHost),
        ];
        for (url, err) in cases {
            assert_eq!(parse_url(url), Err(err), "{url:?}");
        }
        let long_label = format!("https://{}.com", "a".repeat(64));
        assert_eq!(parse_url(&long_label), Err(BadHost));
        let long_host = format!("https://{}com", "a.".repeat(127));
        assert_eq!(parse_url(&long_host), Err(BadHost));
    }

    #[test]
    fn allow_is_exact_origin() {
        let p = policy("https://example.com\nshop.example.org:8443", "");
        assert!(p.check("https://example.com/any/path?x=1").is_ok());
        assert!(p.check("https://EXAMPLE.com.").is_ok());
        assert!(p.check("https://shop.example.org:8443/").is_ok());
        for url in [
            "https://sub.example.com",
            "https://example.com.evil.com",
            "https://evilexample.com",
            "https://example.com:8443",
            "https://shop.example.org",
            "https://example.org:8443",
        ] {
            assert_eq!(p.check(url), Err(Denied::NotAllowed), "{url}");
        }
        assert_eq!(
            p.check("http://example.com"),
            Err(Denied::BadUrl(OriginError::NotHttps))
        );
        assert_eq!(
            p.check("https://evil.com@example.com"),
            Err(Denied::BadUrl(OriginError::UserInfo))
        );
    }

    #[test]
    fn empty_policy_closes_everything() {
        let p = Policy::default();
        assert_eq!(p.check("https://example.com"), Err(Denied::NotAllowed));
        assert_eq!(policy("", ""), Policy::default());
        assert_eq!(policy("# комментарий\n\n   \n", ""), Policy::default());
    }

    #[test]
    fn builtin_deny_covers_subdomains_only() {
        let p = Policy::default();
        assert_eq!(
            p.check("https://www.paypal.com/x"),
            Err(Denied::Builtin(Category::Payment))
        );
        assert_eq!(
            p.check("https://mail.google.com"),
            Err(Denied::Builtin(Category::Mail))
        );
        assert_eq!(
            p.check("https://online.sberbank.ru."),
            Err(Denied::Builtin(Category::Bank))
        );
        for url in [
            "https://notpaypal.com",
            "https://paypal.com.evil.com",
            "https://google.com",
            "https://docs.google.com",
        ] {
            assert_eq!(p.check(url), Err(Denied::NotAllowed), "{url}");
        }
    }

    #[test]
    fn builtin_deny_cannot_be_allowed() {
        for (entry, category) in [
            ("paypal.com", Category::Payment),
            ("https://www.paypal.com", Category::Payment),
            ("MAIL.GOOGLE.COM.", Category::Mail),
        ] {
            assert_eq!(
                Policy::parse(entry, ""),
                Err(ListError::Entry {
                    list: List::Allow,
                    line: 1,
                    error: EntryError::Builtin(category),
                }),
                "{entry}"
            );
        }
    }

    #[test]
    fn user_deny_wins_over_allow() {
        assert_eq!(
            Policy::parse("https://a.example.com", "example.com"),
            Err(ListError::Entry {
                list: List::Allow,
                line: 1,
                error: EntryError::UserDenied,
            })
        );
        let p = policy("https://example.org", "bad.example.org\nexample.net");
        assert!(p.check("https://example.org").is_ok());
        assert_eq!(p.check("https://x.bad.example.org"), Err(Denied::UserList));
        assert_eq!(p.check("https://example.net"), Err(Denied::UserList));
        // Запрет на зону целиком.
        let p = policy("", "ru");
        assert_eq!(p.check("https://example.ru"), Err(Denied::UserList));
    }

    #[test]
    fn list_entries() {
        let p = policy(
            "# мои сайты\nexample.com\n https://example.com/ \nhttps://example.com:8443\n",
            "Evil.COM.\nevil.com",
        );
        assert_eq!(
            p.allow_text(),
            "https://example.com\nhttps://example.com:8443"
        );
        assert_eq!(p.deny_text(), "evil.com");
        // Канонический текст разбирается в ту же политику.
        assert_eq!(policy(&p.allow_text(), &p.deny_text()), p);

        let entry = |list, line, e| {
            Err(ListError::Entry {
                list,
                line,
                error: EntryError::Origin(e),
            })
        };
        assert_eq!(
            Policy::parse("example.com\n\nhttps://example.com/path", ""),
            entry(List::Allow, 3, OriginError::HasPath)
        );
        assert_eq!(
            Policy::parse("example.com?x", ""),
            entry(List::Allow, 1, OriginError::HasPath)
        );
        assert_eq!(
            Policy::parse("http://example.com", ""),
            entry(List::Allow, 1, OriginError::NotHttps)
        );
        assert_eq!(
            Policy::parse("", "https://evil.com"),
            entry(List::Deny, 1, OriginError::HasPath)
        );
        assert_eq!(
            Policy::parse("", "evil.com:443"),
            entry(List::Deny, 1, OriginError::HasPath)
        );
        assert_eq!(
            Policy::parse("", "x@evil.com"),
            entry(List::Deny, 1, OriginError::UserInfo)
        );
        assert_eq!(
            Policy::parse("", "127.0.0.1"),
            entry(List::Deny, 1, OriginError::IpAddress)
        );
    }

    #[test]
    fn list_limits() {
        let many: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("s{i}.com")).collect();
        assert_eq!(
            Policy::parse(&many.join("\n"), ""),
            Err(ListError::TooMany(List::Allow))
        );
        assert!(Policy::parse(&many[..MAX_ENTRIES].join("\n"), "").is_ok());
        assert_eq!(
            Policy::parse("", &many.join("\n")),
            Err(ListError::TooMany(List::Deny))
        );
        let huge = "#".repeat(MAX_LIST_LEN + 1);
        assert_eq!(
            Policy::parse(&huge, ""),
            Err(ListError::TooLong(List::Allow))
        );
    }

    #[test]
    fn access_needs_both_list_and_permission() {
        let granted = |p: &[&str]| p.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let a = Access::new(
            policy("https://example.com\nhttps://example.org", ""),
            &granted(&[
                "https://example.com/*",
                "https://api.anthropic.com/*",
                "https://*.example.org/*",
                "https://*/*",
                "<all_urls>",
            ]),
        );
        assert!(a.check("https://example.com/x").is_ok());
        // В списке, но без разрешения Firefox (маски не считаются).
        assert_eq!(a.check("https://example.org"), Err(Denied::NoPermission));
        // Разрешение есть, но в списке нет.
        assert_eq!(
            a.check("https://api.anthropic.com/v1"),
            Err(Denied::NotAllowed)
        );
        // Подменённые списки без разрешения ничего не открывают.
        let forged = Access::new(policy("https://evil.example", ""), &granted(&[]));
        assert_eq!(
            forged.check("https://evil.example"),
            Err(Denied::NoPermission)
        );
        assert_eq!(
            Policy::from_storage(Some("http://bad"), None),
            Policy::default()
        );
        let o = parse_url("https://example.com:8443/").unwrap();
        assert_eq!(permission_pattern(&o), "https://example.com/*");
    }

    #[test]
    fn builtin_list_is_well_formed() {
        for (i, (domain, _)) in BUILTIN_DENY.iter().enumerate() {
            assert_eq!(parse_host(domain).as_deref(), Ok(*domain), "{domain}");
            assert!(
                !BUILTIN_DENY[..i].iter().any(|(d, _)| d == domain),
                "дубль {domain}"
            );
        }
    }

    #[test]
    fn url_parsing_edge_cases() {
        use OriginError::*;
        // Таб и переводы строк в authority отклоняются.
        assert_eq!(parse_url("https://good.com\t"), Err(BadChars));
        assert_eq!(parse_url("https://good.com\n"), Err(BadChars));
        assert_eq!(parse_url("https://good.com\r"), Err(BadChars));
        // Обратный слеш в authority.
        assert_eq!(parse_url("https://good\\com"), Err(BadChars));
        // Очень длинный хост отклоняется.
        let huge_host = format!("https://{}.com", "a".repeat(MAX_HOST_LEN));
        assert_eq!(parse_url(&huge_host), Err(BadHost));
        // Пустая метка в доме.
        assert_eq!(parse_url("https://example..com"), Err(BadHost));
        // Метка только из дефиса.
        assert_eq!(parse_url("https://--.com"), Err(BadHost));
        // Ведущие нули в порте Firefox читает как то же число: origin совпадает.
        assert_eq!(
            parse_url("https://example.com:0443"),
            parse_url("https://example.com")
        );
        assert_eq!(parse_url("https://example.com:000443"), Err(BadPort));
        // Точка в конце хоста нормализуется.
        assert_eq!(
            parse_url("https://example.com.").map(|o| o.to_string()),
            Ok("https://example.com".into())
        );
        // Валидный punycode принимается.
        assert!(parse_url("https://xn--80akhbyknj4f.xn--p1ai").is_ok());
    }

    #[test]
    fn denylist_edge_cases() {
        use OriginError::*;
        let p = policy("", "example.com");
        // Простой домен закрывает поддомены.
        assert_eq!(p.check("https://example.com"), Err(Denied::UserList));
        assert_eq!(p.check("https://api.example.com"), Err(Denied::UserList));
        // Некорректная запись в запрещённом списке отклоняется при разборе.
        assert!(matches!(
            Policy::parse("", "pa ypal.com"),
            Err(ListError::Entry {
                list: List::Deny,
                error: EntryError::Origin(BadHost),
                ..
            })
        ));
        // Запись со смешанным регистром нормализуется.
        let p = policy("", "EXAMPLE.COM\nPaYpAl.com");
        assert_eq!(p.check("https://EXAMPLE.com"), Err(Denied::UserList));
        // paypal.com во встроенном запрете: он срабатывает раньше пользовательского.
        assert_eq!(
            p.check("https://paypal.com"),
            Err(Denied::Builtin(Category::Payment))
        );
        // Дубли в запрещённом списке создают уникальный набор.
        let p = policy("", "example.com\nEXAMPLE.COM\nexample.com");
        assert_eq!(p.deny_text(), "example.com");
        // TLD сам по себе закрывает все домены с этим TLD.
        let p = policy("", "com");
        assert_eq!(p.check("https://example.com"), Err(Denied::UserList));
        assert_eq!(p.check("https://google.com"), Err(Denied::UserList));
    }

    #[test]
    fn allow_entry_parsing_edge_cases() {
        use OriginError::*;
        // Запись без схемы, только хост — допускается.
        let p = policy("example.com", "");
        assert!(p.check("https://example.com").is_ok());
        // Смешанный регистр нормализуется.
        let p = policy("HTTPS://EXAMPLE.COM", "");
        assert!(p.check("https://example.com").is_ok());
        // Путь в записи запрещён.
        assert!(matches!(
            Policy::parse("https://example.com/path", ""),
            Err(ListError::Entry {
                list: List::Allow,
                error: EntryError::Origin(HasPath),
                ..
            })
        ));
        // Запрос в записи запрещён.
        assert!(matches!(
            Policy::parse("https://example.com?x=1", ""),
            Err(ListError::Entry {
                list: List::Allow,
                error: EntryError::Origin(HasPath),
                ..
            })
        ));
        // Порт 443 явно в записи (вместо 443 по умолчанию).
        let p = policy("https://example.com:443", "");
        assert!(p.check("https://example.com:443").is_ok());
        // Пользовательское число портов допускается.
        let p = policy("https://example.com:8443", "");
        assert!(Policy::parse("https://localhost.local:9000", "").is_err());
        assert!(p.check("https://example.com:8443").is_ok());
    }
}
