# Публикация на addons.mozilla.org

Публикацию выполняет владелец аккаунта AMO; здесь всё, что нужно приложить.

## Перед загрузкой

1. ID расширения — `leash@kirusshenkin.github.io` (после первой публикации не
   меняется). Декларация `data_collection_permissions`: `websiteContent`,
   `browsingActivity` — содержимое и адреса разрешённых страниц передаются
   локальной программе leash-host, а через неё — в Claude Code или Claude
   Desktop пользователя (обязательна на AMO с 03.11.2025).
2. Поднять `version`.
3. `make check && make e2e && make zip` — архив в `dist/leash-<версия>.zip`.
4. `npx -y addons-linter@10.13.0 dist/leash-<версия>.zip`. Ожидается 0 ошибок
   и одно предупреждение `KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION`:
   `data_collection_permissions` есть на Android только с версии 142. Leash
   работает только на десктопе (`sidebar_action` на Android нет), поэтому при
   загрузке платформу «Firefox for Android» не отмечать.

## Исходный код для ревьюеров

AMO требует исходники, если в архиве есть сгенерированный код. Здесь это
`pkg/leash_bg.wasm` и `pkg/leash.js` (wasm-bindgen). Приложить архив
репозитория — `make source` (`dist/leash-src-<версия>.zip`, только файлы из git;
приватные материалы `e2e/private/` туда не попадают) — и инструкцию:

```
Требования: macOS или Linux, rustup, wasm-bindgen-cli 0.2.128.
rustup показывает тулчейн из rust-toolchain.toml и ставит его сам.
cargo install wasm-bindgen-cli --version '=0.2.128' --locked
make build
Сгенерированные файлы: extension/pkg/leash.js, extension/pkg/leash_bg.wasm.
Мост leash-host (не входит в архив дополнения): make host.
Зависимости Rust — только из vendor/ (сборка --offline --locked).
```

## Разрешения и их обоснование (поле «Notes to reviewer»)

- `storage` — списки разрешённых и запрещённых сайтов.
- `scripting` — внедрение content-скрипта по требованию, только в главный фрейм
  вкладки сайта, который пользователь явно разрешил.
- `nativeMessaging` — связь с программой leash-host на компьютере
  пользователя (MCP-сервер для Claude Code и Claude Desktop, исходники в
  `crates/host`, ставится отдельно: готовая сборка из GitHub Releases через
  `scripts/get.sh` или `make install`). Это единственный канал
  наружу: сетевых запросов расширение не делает (`connect-src 'self'`, нет
  `host_permissions`).
- `optional_host_permissions: https://*/*` — запрашиваются по одному сайту
  через `permissions.request` при сохранении списка разрешённых сайтов.
- Удалённый код не загружается; `wasm-unsafe-eval` нужен только для своего WASM.

## Политика конфиденциальности (текст для листинга)

Leash не собирает и не передаёт данные разработчику. Расширение передаёт
содержимое и адреса страниц сайтов, которые вы разрешили в настройках,
программе leash-host на вашем компьютере, а она — приложению Claude (Claude
Code или Claude Desktop), которое вы к ней подключили, и только когда Claude
вызывает инструмент Leash. Дальше на эти данные распространяются условия
Anthropic для вашего аккаунта Claude. Пароли, данные карт и одноразовые коды
в переданные данные не попадают. Списки сайтов хранятся локально в профиле
Firefox.
