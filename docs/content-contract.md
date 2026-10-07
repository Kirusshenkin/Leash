# Контракт content-скрипта

`extension/content/content.js` — единственный код, который исполняется в чужой
вкладке. Он только собирает факты о странице и выполняет примитивные действия.
Все решения (можно ли, нужно ли подтверждение, что показать модели) принимает
Rust в background. Ответы content-скрипта для background — **недоверенные
данные**: Rust заново проверяет типы и длины.

## Внедрение

Background внедряет скрипт по требованию, только во вкладку с разрешённым
origin и только в главный фрейм:

```js
browser.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content/content.js"] })
browser.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: (op) => globalThis.leashRun(op), args: [op] })
```

Файл внедряется перед каждой операцией и обязан быть идемпотентным:
`if (!globalThis.leashRun) { ... }`. Состояние (карта элементов последнего
снимка) живёт в изолированном мире между вызовами. Страница этот мир не видит.

## Запреты (проверяет scripts/check-static.sh)

Нет `browser.*`/`chrome.*` (никакого storage, runtime, сообщений), `fetch`,
`XMLHttpRequest`, `WebSocket`, `postMessage`, слушателей `message`, `eval`,
`Function`, `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`,
`console`, `setTimeout` со строкой, `location =`/`location.assign`/`open(`
(навигация только из background через `tabs.update`). Никаких данных страницы
в URL. Скрипт ничего не создаёт в DOM страницы.

## Операции: `leashRun(op)` → результат (structured clone)

Все ошибки возвращаются значением `{ ok: false, reason }`, а не исключением.

### `{ op: "snapshot" }`

```
{
  ok: true,
  origin: location.origin,
  url: location.href,
  title: document.title,
  version: <целое, растёт на каждый снимок>,
  elements: [Element],      // не больше 400
  text: <видимый текст>,    // не больше 30000 символов
  frames: <число iframe/frame/object/embed в документе>,
  truncated: <true, если что-то обрезано по лимиту>
}
```

Element:

```
{
  id: <целое ≥ 1, уникально в снимке>,
  tag: <localName>,
  role: <роль, см. ниже>,
  name: <доступное имя, ≤ 200 символов>,
  type: <для input: атрибут type в нижнем регистре (по умолчанию "text"), иначе "">,
  value: <для input/textarea/select: текущее значение, ≤ 300; для password всегда "">,
  checked: <true/false для checkbox/radio, иначе false>,
  disabled: <bool>,
  href: <для a[href]/area[href]: абсолютный a.href, иначе "">,
  form: <bool: элемент принадлежит форме (el.form != null)>,
  formAction: <если form: абсолютный form.action, иначе "">,
  submits: <bool: клик отправит форму: button без type или type=submit в форме, input type=submit|image>,
  autocomplete: <атрибут autocomplete в нижнем регистре, иначе "">,
  editable: <bool: textbox/searchbox/contenteditable/textarea>,
  options: [<текст option>],  // для select: до 50 штук по ≤ 100 символов, иначе []
  inView: <bool: пересекается с viewport>
}
```

Отбор интерактивных элементов: `a[href]`, `area[href]`, `button`, `input`
(кроме `type=hidden`), `select`, `textarea`, `summary`, `[contenteditable]`
(не `false`), `[role]` из списка: button, link, checkbox, radio, tab, menuitem,
menuitemcheckbox, menuitemradio, option, switch, textbox, searchbox, combobox.
Обход включает открытые shadow root.

Роль: явный `role` (первый токен, если он из списка выше), иначе неявная:
`a/area[href]`→link, `button`/`summary`→button, `select`→combobox,
`textarea`→textbox, `input`: checkbox→checkbox, radio→radio,
submit/button/reset/image→button, search→searchbox, остальные→textbox;
`[contenteditable]`→textbox.

Имя (одна и та же функция для снимка и для проверки перед действием):
`aria-label` → текст элементов из `aria-labelledby` → `label` (`el.labels`)
→ `alt` → `title` → `placeholder` → `innerText` → `value` для кнопок-input.
Пробелы схлопываются, обрезка до 200 символов.

Видимость (иначе элемент не попадает в снимок вообще):
`el.checkVisibility({ opacityProperty: true, visibilityProperty: true })`,
размер прямоугольника ≥ 4×4 px, `rect.right > 0 && rect.bottom > -scrollY`
(не уведён за левый/верхний край), нет предка с `aria-hidden="true"` или
`inert`.

Текст: обход текстовых узлов `document.body` (TreeWalker), без
script/style/noscript/template; родитель видим по тем же правилам, его
вычисленный `font-size` ≥ 6px. Узлы склеиваются через пробел, блоки — через
`\n`. Комментарии в текст не попадают.

### `{ op: "act", origin, version, id, action, text, submit, expect }`

`expect` — факты элемента из снимка, на которых основано решение политики:
`{ tag, role, name, type, href, form, formAction, submits, autocomplete, editable }`.

`action`: `"click" | "type" | "select"`. Перед действием, по порядку:

1. `location.origin === origin`, иначе `reason: "origin"`.
2. `version` равен версии последнего снимка, иначе `"stale"`.
3. Элемент `id` есть в карте и `isConnected`, иначе `"gone"`.
4. Все факты `expect`, вычисленные заново той же функцией, что и в снимке,
   совпадают (набор ключей тоже), иначе `"changed"`. Так подмена адреса ссылки
   или формы после снимка не проходит.
5. Видимость по правилам снимка, иначе `"hidden"`; `disabled` → `"disabled"`.
6. `scrollIntoView({ block: "center" })`, затем
   `document.elementFromPoint(центр)` должен быть самим элементом или его
   потомком, иначе `"occluded"`.

Действия:
- `click`: `el.click()`.
- `type` (только `editable`): `focus()`; для input/textarea значение через
  нативный сеттер прототипа + события `input` и `change` (bubbles); для
  contenteditable — `textContent`. Если `submit === true` и есть `el.form` —
  `el.form.requestSubmit()`. `type=file` → `"unsupported"`.
- `select` (только `select`): ровно один option, у которого текст (как в снимке)
  равен `text` (value не учитывается); нет такого или их несколько → `"no_option"`; иначе выбрать, `input` и `change`.

Ответ: `{ ok: true }` или `{ ok: false, reason }`.

### `{ op: "scroll", origin, direction: "up" | "down" }`

Проверка origin, затем `scrollBy` на 80% высоты окна.
Ответ `{ ok: true }` или `{ ok: false, reason: "origin" }`.

Неизвестный `op` → `{ ok: false, reason: "unsupported" }`.
