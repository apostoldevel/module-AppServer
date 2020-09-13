Сервер приложений
-
**Модуль** для [Апостол](https://github.com/ufocomp/apostol-aws).

Установка
-
Следуйте указаниям по сборке и установке [Апостол](https://github.com/ufocomp/apostol-aws#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0-%D0%B8-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0)

Описание
-
**Сервер приложений** (HTTP-сервер) используется для удалённого вызова процедур с использованием архитектурного стиля [REST](https://ru.wikipedia.org/wiki/REST) (от англ. Representational State Transfer — _передача состояния представления_).

## REST API

## Общая информация
 * Базовая конечная точка (endpoint): [localhost:8080](http://localhost:8080)
 * Все конечные точки возвращают `JSON-объект`
 * Все поля, относящиеся ко времени и меткам времени, указаны в **миллисекундах**. 

## HTTP коды возврата
 * HTTP `4XX` коды возврата применимы для некорректных запросов - проблема на стороне клиента.
 * HTTP `5XX` коды возврата используются для внутренних ошибок - проблема на стороне сервера. Важно **НЕ** рассматривать это как операцию сбоя. Статус выполнения **НЕИЗВЕСТЕН** и может быть успешным.
 
## Коды ошибок
 * Любая конечная точка может вернуть ошибку.
  
**Пример ответа:**
```json
{
  "error": {
    "code": 404,
    "message": "Not Found"
  }
}
```

## Общая информация о конечных точках
 * Для `GET` конечных точек параметры должны быть отправлены в виде `строки запроса (query string)` .
 * Для `POST` конечных точек, некоторые параметры могут быть отправлены в виде `строки запроса (query string)`, а некоторые в виде `тела запроса (request body)`:
 * При отправке параметров в виде `тела запроса` допустимы следующие типы контента:
    * `application/x-www-form-urlencoded` для `query string`;
    * `multipart/form-data` для `HTML-форм`;
    * `application/json` для `JSON`.
 * Параметры могут быть отправлены в любом порядке.

## Доступ к API

Доступ к API возможен только при наличии _**маркера доступа**_ или **_цифровой подписи_** методом HMAC-SHA256. 

#### Маркер доступа

**Маркера доступа** (`access_token`) **ДОЛЖЕН** присутствовать в HTTP заголовке `Authorization` каждого запроса.
 
Формат:
~~~
Authorization: Bearer <access_token>
~~~

**Маркера доступа** - это `JSON Web Token` [RFC 7519](https://tools.ietf.org/html/rfc7519). 

Выдается он [сервером авторизации](https://github.com/ufocomp/module-AuthServer), роль которого выполняет сама же система.

Пример запроса:
* **http request:**
```http request
GET /api/v1/whoami HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiIDogImFjY291bnRzLnNoaXAtc2FmZXR5LnJ1IiwgImF1ZCIgOiAid2ViLXNoaXAtc2FmZXR5LnJ1IiwgInN1YiIgOiAiZGZlMDViNzhhNzZiNmFkOGUwZmNiZWYyNzA2NzE3OTNiODZhYTg0OCIsICJpYXQiIDogMTU5MzUzMjExMCwgImV4cCIgOiAxNTkzNTM1NzEwfQ.NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg
````

#### Цифровая подпись методом HMAC-SHA256

Вместо HTTP заголовка `Authorization` можно использовать подпись. 

Для передачи данных авторизации в виде подписи используются следующие HTTP заголовки:
  * `Session` - ключ сессии;
  * `Nonce` - данное время в миллисекундах;
  * `Signature` - подпись.

**Примеры:**

<details>
  <summary>Пример создания подписи на JavaScript (без данных в теле сообщения)</summary>
  
~~~javascript
// CryptoJS - Standard JavaScript cryptography library

const body = null;

const Session = localStorage.getItem('Session'); // efa885ebde1baa991a3c798fc1141f6bec92fc90
const Secret = localStorage.getItem('Secret'); // y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC

const Path = '/whoami';
const Nonce = (Date.now() * 1000).toString(); // 1589998352818000
const Body = JSON.stringify(body); // if body === null then Body = "null" <-- string  

const sigData = `${Path}${Nonce}${Body}`; // /whoami1589998352818000null

const Signature = CryptoJS.HmacSHA256(sigData, Secret).toString(); // 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1

let headers = new Headers();

headers.append('Session', Session);
headers.append('Nonce', Nonce);
headers.append('Signature', Signature);
headers.append('Content-Type', 'application/json');

const init = {
    method: 'POST',
    headers: headers,
    body: Body,
    mode: "cors"
};

const apiPath = `/api/v1${Path}`;

fetch(apiPath, init)
    .then((response) => {
        return response.json();
    })
    .then((json) => {
        console.log(json);
    })
    .catch((e) => {
        console.log(e.message);
});
~~~

* **openssl command:**
```shell script
echo -n "/whoami1589998352818000null" | \
openssl sha256 -hmac "y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC"
(stdin)= 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1
```
* **curl command:**
```curl
curl -X POST \
     -H "Session: efa885ebde1baa991a3c798fc1141f6bec92fc90" \
     -H "Nonce: 1589998352818000" \
     -H "Signature: 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1" \
     http://localhost:8080/api/v1/whoami
````     
* **http request:**
```http request
POST /api/v1/whoami HTTP/1.1
Host: localhost:8080
Session: efa885ebde1baa991a3c798fc1141f6bec92fc90
Nonce: 1589998352818000
Signature: 91609292e250fc30c48c2ad387d1121c703853fa88ce027e6ba0efe1fcb50ba1
````
</details>
  
<details>
  <summary>Пример создания подписи на JavaScript (с данными в теле сообщения)</summary>

~~~javascript
// CryptoJS - Standard JavaScript cryptography library

const body = {
  classcode : 'client',
  statecode : 'enabled',
  actioncode: 'invite'
};

const Session = localStorage.getItem('Session'); // efa885ebde1baa991a3c798fc1141f6bec92fc90
const Secret = localStorage.getItem('Secret'); // y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC

const Path = '/method/get';
const Nonce = (Date.now() * 1000).toString(); // 1589998352902000
const Body = JSON.stringify(body); // <-- JSON string  

const sigData = `${Path}${Nonce}${Body}`; // /method/get1589998352902000{"classcode":"client","statecode":"enabled","actioncode":"invite"}

const Signature = CryptoJS.HmacSHA256(sigData, Secret).toString(); // 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b

let headers = new Headers();

headers.append('Session', Session);
headers.append('Nonce', Nonce);
headers.append('Signature', Signature);
headers.append('Content-Type', 'application/json');

const init = {
    method: 'POST',
    headers: headers,
    body: Body,
    mode: "cors"
};

const apiPath = `/api/v1${Path}`;

fetch(apiPath, init)
    .then((response) => {
        return response.json();
    })
    .then((json) => {
        console.log(json);
    })
    .catch((e) => {
        console.log(e.message);
});
~~~

* **openssl command:**
```shell script
echo -n "/method/get1589998352902000{\"classcode\":\"client\",\"statecode\":\"enabled\",\"actioncode\":\"invite\"}" | \
openssl sha256 -hmac "y2WYJRE9f13g6qwFOEOe0rGM/ISlGFEEesUpQadHNd/aJL+ExKRj5E6OSQ9TuJRC"
(stdin)= 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b
````
* **curl command:**
```curl
curl -X POST \
     -H "Session: efa885ebde1baa991a3c798fc1141f6bec92fc90" \
     -H "Nonce: 1589998352902000" \
     -H "Signature: 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b" \
     -d "{\"classcode\":\"client\",\"statecode\":\"enabled\",\"actioncode\":\"invite\"}" \
     http://localhost:8080/api/v1/method/get
````
* **http request:**
```http request
POST /api/v1/method/get HTTP/1.1
Host: localhost:8080
Session: efa885ebde1baa991a3c798fc1141f6bec92fc90
Nonce: 1589998352902000
Signature: 2b2bf5188ea40dfe8207efec56956b6170bdbc2f0ab0bffd8b50acd60979b09b

{"classcode":"client","statecode":"enabled","actioncode":"invite"}
````
</details>

### Конечные точки

#### Тест подключения
```http request
GET /api/v1/ping
```
Проверить подключение к REST API.
 
**Параметры запроса:**
НЕТ
 
**Пример ответа:**
```json
{}
```
 
#### Проверить время сервера
```http request
GET /api/v1/time
```
Проверить подключение к REST API и получить текущее время сервера.
 
**Параметры запроса:**
 НЕТ
  
**Пример ответа:**
```json
{
  "serverTime": 1583495795455
}
```

**Полное описание конечных точек смотрите в репозитории вашего проекта**:

- [ShipSafety](https://github.com/ufocomp/apostol-sss/blob/master/doc/REST-API-ru.md)
- [Plugme](https://github.com/ufocomp/apostol-plugme/blob/master/doc/REST-API-ru.md)
- [Fenomy](https://github.com/ufocomp/apostol-fenomy/blob/master/doc/REST-API-ru.md)
