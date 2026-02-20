[![en](https://img.shields.io/badge/lang-en-green.svg)](https://github.com/apostoldevel/module-AppServer/blob/master/README.md)

Сервер приложений
-

**Модуль** для [Апостол](https://github.com/apostoldevel/apostol).

Описание
-

**Сервер приложений** — модуль на C++ для фреймворка [Апостол](https://github.com/apostoldevel/apostol), реализующий HTTP/RESTful сервер. Запускается внутри рабочих процессов Апостола и обрабатывает все входящие HTTP-запросы, путь которых начинается с `/api/`.

Основные характеристики:

* Написан на C++14 с использованием асинхронной неблокирующей модели ввода-вывода на базе **epoll** API — подходит для высоконагруженных систем с низкими задержками.
* Напрямую подключается к **PostgreSQL** через библиотеку `libpq`. Каждый API-запрос передаётся в функцию PL/pgSQL базы данных; вся бизнес-логика находится в БД, а не в самом модуле.
* Реализует принципы **REST** (Representational State Transfer — _передача состояния представления_) для удалённого вызова процедур через HTTP.
* Поддерживает два метода аутентификации: **Bearer JWT** токен и подпись запроса **HMAC-SHA256**.
* Формат ответа всегда `application/json`.
* Встроенные конечные точки (`/ping`, `/time`) не требуют обращения к базе данных и обрабатываются полностью на уровне C++. Все остальные запросы перенаправляются в функции схемы `daemon` в PostgreSQL.

### Место модуля в архитектуре Апостола

Апостол запускает мастер-процесс, который порождает N рабочих процессов. Каждый рабочий процесс загружает набор модулей. `CAppServer` — один из таких модулей: он регистрируется как обработчик запросов, путь которых начинается с `/api/`. При получении подходящего запроса:

1. Цикл событий рабочего процесса (epoll) принимает соединение и читает HTTP-запрос.
2. `CAppServer` проверяет заголовок `Authorization` или заголовки подписи для определения контекста аутентификации.
3. Модуль формирует параметризованный SQL-вызов (`daemon.fetch`, `daemon.unauthorized_fetch` или `daemon.signed_fetch`) и передаёт его в пул соединений PostgreSQL асинхронно.
4. После получения результата запроса модуль сериализует его в JSON и отправляет HTTP-ответ.

Модуль также управляет кратковременным кешем ответов (TTL 1 минута, пути перечислены в `cache.conf`) и перезагружает публичные ключи провайдеров OAuth2 из директории `certs/` каждые 30 минут через метод `Heartbeat`.

Установка
-

Следуйте указаниям по сборке и установке [Апостол](https://github.com/apostoldevel/apostol#building-and-installation).

Документация
-

REST API
-

### Общая информация

* Базовая конечная точка (endpoint): [http://localhost:8080](http://localhost:8080)
* Все конечные точки возвращают **JSON-объект**.
* Все поля, относящиеся ко времени и меткам времени, указаны в **миллисекундах** (Unix epoch).

### HTTP коды возврата

* `2XX` — успех.
* `4XX` — ошибка клиента (некорректный запрос, ошибка аутентификации, ресурс не найден и т.д.).
* `5XX` — внутренняя ошибка сервера. Статус выполнения операции **неизвестен** — не считайте результат неуспешным без дополнительной проверки.

### Формат ответа с ошибкой

Любая конечная точка может вернуть ошибку. Тело ответа будет содержать объект `error`:

```json
{
  "error": {
    "code": 404,
    "message": "Not Found"
  }
}
```

Коды ошибок >= 10000 делятся на 100 для приведения к стандартным HTTP-кодам (например, 40401 → 404).

### Общие правила для конечных точек

* Для конечных точек `GET` все параметры передаются в виде **строки запроса (query string)**.
* Для конечных точек `POST` параметры могут передаваться как в строке запроса, так и в теле запроса. Поддерживаемые типы содержимого тела запроса:
  * `application/json`
  * `application/x-www-form-urlencoded`
  * `multipart/form-data`
* Параметры могут быть отправлены в любом порядке.
* Модуль принимает методы `GET`, `POST` и `OPTIONS`. Все остальные HTTP-методы возвращают `405 Method Not Allowed`.

### Управление форматом ответа (необязательные параметры)

Два необязательных параметра запроса влияют на сериализацию результатов PostgreSQL:

| Параметр | Допустимые значения | Действие |
|----------|---------------------|----------|
| `result_object` | `true`, `false` | При значении `true` оборачивает результат в `{"result": ...}` |
| `result_format` | `object`, `array`, `null` | Задаёт формат сериализации результирующего набора. Пути, содержащие `/list`, по умолчанию используют формат `array`. |

Доступ к API
-

Доступ к API возможен только при наличии **Bearer-токена доступа** или **цифровой подписи** методом HMAC-SHA256.

### Маркер доступа (Bearer JWT)

**Маркер доступа** (`access_token`) **ОБЯЗАН** присутствовать в HTTP-заголовке `Authorization` каждого аутентифицированного запроса.

Формат:

```
Authorization: Bearer <access_token>
```

Маркер доступа — это JSON Web Token ([RFC 7519](https://tools.ietf.org/html/rfc7519)). Он выдаётся модулем [AuthServer](https://github.com/apostoldevel/module-AuthServer), который является частью того же приложения Апостол.

Модуль проверяет токен локально, используя настроенные секреты/ключи провайдеров, прежде чем передать запрос в базу данных. Поддерживаемые алгоритмы: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512.

Токены также принимаются из cookie `__Secure-AT` (устанавливается сервером после входа); сопутствующий токен обновления читается из cookie `__Secure-RT`.

**Пример запроса:**

```http
GET /api/v1/whoami HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnNoaXAtc2FmZXR5LnJ1IiwgImF1ZCIgOiAid2ViLXNoaXAtc2FmZXR5LnJ1IiwgInN1YiIgOiAiZGZlMDViNzhhNzZiNmFkOGUwZmNiZWYyNzA2NzE3OTNiODZhYTg0OCIsICJpYXQiIDogMTU5MzUzMjExMCwgImV4cCIgOiAxNTkzNTM1NzEwfQ.NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg
```

### Цифровая подпись методом HMAC-SHA256

Вместо заголовка `Authorization` запрос может быть аутентифицирован с использованием подписи HMAC-SHA256. Три HTTP-заголовка передают данные аутентификации:

| Заголовок | Описание |
|-----------|----------|
| `Session` | Ключ сессии (40-символьная шестнадцатеричная строка) |
| `Nonce` | Текущее время в **микросекундах** (Unix epoch × 1000) |
| `Signature` | HMAC-SHA256 в шестнадцатеричном представлении |

Подпись вычисляется от конкатенации:

```
<путь><nonce><тело>
```

Где `<тело>` — строковое представление тела запроса в формате JSON или строка `"null"`, если тело отсутствует.

Окно приёма по умолчанию составляет **5000 миллисекунд**; передайте `?receive_window=<мс>` для переопределения.

**Эта функция активна только при компиляции модуля с определённым символом `CALL_SIGNATURE_FETCH`.**

---

<details>
  <summary>Пример создания подписи на JavaScript (без данных в теле сообщения)</summary>

```javascript
// CryptoJS - Standard JavaScript cryptography library

const body = null;

const Session = localStorage.getItem('Session'); // efa885ebde1baa991a3c798fc1141f6bec92fc90
const Secret  = localStorage.getItem('Secret');  // y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC

const Path      = '/whoami';
const Nonce     = (Date.now() * 1000).toString(); // 1589998352818000
const Body      = JSON.stringify(body);           // "null"  (строка, не null)

const sigData   = `${Path}${Nonce}${Body}`;       // /whoami1589998352818000null

const Signature = CryptoJS.HmacSHA256(sigData, Secret).toString();
// 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1

let headers = new Headers();
headers.append('Session',      Session);
headers.append('Nonce',        Nonce);
headers.append('Signature',    Signature);
headers.append('Content-Type', 'application/json');

const init = { method: 'POST', headers, body: Body, mode: 'cors' };

fetch(`/api/v1${Path}`, init)
    .then(r => r.json())
    .then(json => console.log(json))
    .catch(e  => console.log(e.message));
```

Проверка через openssl:

```shell
echo -n "/whoami1589998352818000null" | \
  openssl sha256 -hmac "y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC"
(stdin)= 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1
```

curl:

```shell
curl -X POST \
     -H "Session: efa885ebde1baa991a3c798fc1141f6bec92fc90" \
     -H "Nonce: 1589998352818000" \
     -H "Signature: 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1" \
     http://localhost:8080/api/v1/whoami
```

HTTP-запрос:

```http
POST /api/v1/whoami HTTP/1.1
Host: localhost:8080
Session: efa885ebde1baa991a3c798fc1141f6bec92fc90
Nonce: 1589998352818000
Signature: 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1
```

</details>

<details>
  <summary>Пример создания подписи на JavaScript (с данными в теле сообщения)</summary>

```javascript
// CryptoJS - Standard JavaScript cryptography library

const body = {
  classcode : 'client',
  statecode : 'enabled',
  actioncode: 'invite'
};

const Session = localStorage.getItem('Session'); // efa885ebde1baa991a3c798fc1141f6bec92fc90
const Secret  = localStorage.getItem('Secret');  // y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC

const Path      = '/method/get';
const Nonce     = (Date.now() * 1000).toString(); // 1589998352902000
const Body      = JSON.stringify(body);

// /method/get1589998352902000{"classcode":"client","statecode":"enabled","actioncode":"invite"}
const sigData   = `${Path}${Nonce}${Body}`;

const Signature = CryptoJS.HmacSHA256(sigData, Secret).toString();
// 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b

let headers = new Headers();
headers.append('Session',      Session);
headers.append('Nonce',        Nonce);
headers.append('Signature',    Signature);
headers.append('Content-Type', 'application/json');

const init = { method: 'POST', headers, body: Body, mode: 'cors' };

fetch(`/api/v1${Path}`, init)
    .then(r => r.json())
    .then(json => console.log(json))
    .catch(e  => console.log(e.message));
```

Проверка через openssl:

```shell
echo -n "/method/get1589998352902000{\"classcode\":\"client\",\"statecode\":\"enabled\",\"actioncode\":\"invite\"}" | \
  openssl sha256 -hmac "y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC"
(stdin)= 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b
```

curl:

```shell
curl -X POST \
     -H "Session: efa885ebde1baa991a3c798fc1141f6bec92fc90" \
     -H "Nonce: 1589998352902000" \
     -H "Signature: 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b" \
     -d '{"classcode":"client","statecode":"enabled","actioncode":"invite"}' \
     http://localhost:8080/api/v1/method/get
```

HTTP-запрос:

```http
POST /api/v1/method/get HTTP/1.1
Host: localhost:8080
Session: efa885ebde1baa991a3c798fc1141f6bec92fc90
Nonce: 1589998352902000
Signature: 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b

{"classcode":"client","statecode":"enabled","actioncode":"invite"}
```

</details>

Встроенные конечные точки
-

Эти конечные точки обрабатываются полностью на уровне C++ и не требуют обращения к базе данных или аутентификации.

### Тест подключения

```http
GET /api/v1/ping
```

Проверить подключение к REST API.

**Параметры запроса:** НЕТ

**Пример ответа:**

```json
{}
```

### Проверить время сервера

```http
GET /api/v1/time
```

Проверить подключение к REST API и получить текущее время сервера.

**Параметры запроса:** НЕТ

**Пример ответа:**

```json
{
  "serverTime": 1583495795455
}
```

`serverTime` — количество миллисекунд с начала эпохи Unix (UTC).

Конечные точки приложения
-

Все пути, начинающиеся с `/api/`, которые не обрабатываются встроенными конечными точками, перенаправляются в PostgreSQL. Вызываемая функция базы данных зависит от контекста аутентификации:

| Контекст | Функция PostgreSQL |
|----------|--------------------|
| Bearer JWT токен | `daemon.fetch(token, method, path, payload, agent, host)` |
| Заголовки Session + Secret (Basic) | `daemon.session_fetch(session, secret, method, path, payload, agent, host)` |
| Без учётных данных (если включено) | `daemon.unauthorized_fetch(method, path, payload, agent, host)` |
| Подпись HMAC-SHA256 | `daemon.signed_fetch(method, path, payload, session, nonce, signature, agent, host, window)` |

Полный набор конечных точек приложения определяется исключительно в базе данных проекта — в функциях PL/pgSQL схемы `daemon`. **Описание конечных точек смотрите в репозитории вашего проекта.**
