# MobileMoney App

Simple Mobile Money application with authentication and CRUD functionality

### Installation

To use this template, your computer needs:

- [Python 3](https://python.org)
- Python Flask micro-framework
- [Pip Package Manager](https://pypi.python.org/pypi)
- Docker
- MongoDB =====> create an account here : https://cloud.mongodb.com
   - Create the following mongodb collections:
	  - Payloan
	  - Register
	  - Takeloan
	  - TopUp
	  - Transfer
	  - Withdrawal

### Running the app in docker container

# Using Docker:

- docker-compose up

# CD into Docker
- docker-compose exec -it <name of container> bash


### Running the app locally

```bash
python app.py
```

# momo

# API EndPoints
# POST Request:
 - Body
 {
   "username": "nana",
   "password": "admin123",
   "name":"Golden Rule",
   "to":"worldboss",
   "fromPhone":"0244120126",
   "toPhone":"0243559227",
   "email":"theodondre@gmail.com",
   "amount": 5,
   "network": "MTN"
}

 - http://35.236.211.103/pay
 - http://35.236.211.103/topup
 - http://35.236.211.103/withdraw
 - http://35.236.211.103/pay
 - http://35.236.211.103/register
 - http://35.236.211.103/transfer
 - http://35.236.211.103/balance
 - http://35.236.211.103/loan


# Withdraw POST request
 ![alt text](https://github.com/aerogramme/momo/blob/master/withdraw.png)

# TopUp POST request
 ![alt text](https://github.com/aerogramme/momo/blob/master/topup.png)

 # CURL
 curl -X POST \
  http://35.236.211.103:80/balance \
  -H 'Accept: */*' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Content-Length: 233' \
  -H 'Content-Type: application/json' \
  -H 'Host: 35.236.211.103:80' \
  -H 'Postman-Token: 5fa14877-38f5-4ef7-8216-f107c4ad5e8e,a78417d7-57d1-447a-8287-dcc5e813173f' \
  -H 'User-Agent: PostmanRuntime/7.18.0' \
  -H 'cache-control: no-cache' \
  -d '{
   "username": "mark.garr",
   "password": "admin123",
   "name":"Golden Rule",
   "to":"worldboss",
   "fromPhone":"0244120126",
   "toPhone":"0243559227",
   "email":"theodondre@gmail.com",
   "amount": 150,
   "network": "MTN"
}'

# PYTHON
import requests

url = "http://35.236.211.103:80/balance"

payload = "{\n   \"username\": \"mark.garr\",\n   \"password\": \"admin123\",\n   \"name\":\"Golden Rule\",\n   \"to\":\"worldboss\",\n   \"fromPhone\":\"0244120126\",\n   \"toPhone\":\"0243559227\",\n   \"email\":\"theodondre@gmail.com\",\n   \"amount\": 150,\n   \"network\": \"MTN\"\n}"
headers = {
    'Content-Type': "application/json",
    'User-Agent': "PostmanRuntime/7.18.0",
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    'Postman-Token': "5fa14877-38f5-4ef7-8216-f107c4ad5e8e,cdfe35a2-c7f3-407f-8e4a-c3521e75b9e3",
    'Host': "35.236.211.103:80",
    'Accept-Encoding': "gzip, deflate",
    'Content-Length': "233",
    'Connection': "keep-alive",
    'cache-control': "no-cache"
    }

response = requests.request("POST", url, data=payload, headers=headers)

print(response.text)


# JAVA
OkHttpClient client = new OkHttpClient(); \

MediaType mediaType = MediaType.parse("application/json");
RequestBody body = RequestBody.create(mediaType, "{\n   \"username\": \"mark.garr\",\n   \"password\": \"admin123\",\n   \"name\":\"Golden Rule\",\n   \"to\":\"worldboss\",\n   \"fromPhone\":\"0244120126\",\n   \"toPhone\":\"0243559227\",\n   \"email\":\"theodondre@gmail.com\",\n   \"amount\": 150,\n   \"network\": \"MTN\"\n}"); \
Request request = new Request.Builder() \
  .url("http://35.236.211.103:80/balance") \
  .post(body) \
  .addHeader("Content-Type", "application/json") \
  .addHeader("User-Agent", "PostmanRuntime/7.18.0") \
  .addHeader("Accept", "*/*") \
  .addHeader("Cache-Control", "no-cache") \
  .addHeader("Postman-Token", "5fa14877-38f5-4ef7-8216-f107c4ad5e8e,469c96af-a20a-4814-b39c-32f957bffce2") \
  .addHeader("Host", "35.236.211.103:80") \
  .addHeader("Accept-Encoding", "gzip, deflate") \
  .addHeader("Content-Length", "233") \
  .addHeader("Connection", "keep-alive") \
  .addHeader("cache-control", "no-cache") \
  .build(); \

Response response = client.newCall(request).execute();\

# PHP
<?php

$request = new HttpRequest();\
$request->setUrl('http://35.236.211.103:80/balance');\
$request->setMethod(HTTP_METH_POST);\

$request->setHeaders(array(\
  'cache-control' => 'no-cache',\
  'Connection' => 'keep-alive',\
  'Content-Length' => '233',\
  'Accept-Encoding' => 'gzip, deflate',\
  'Host' => '35.236.211.103:80',\
  'Postman-Token' => '5fa14877-38f5-4ef7-8216-f107c4ad5e8e,112e030d-9470-4e2e-87ed-dc758b0194e3',\
  'Cache-Control' => 'no-cache',\
  'Accept' => '*/*',\
  'User-Agent' => 'PostmanRuntime/7.18.0',\
  'Content-Type' => 'application/json'\
));\

$request->setBody('{\
   "username": "mark.garr",\
   "password": "admin123",\
   "name":"Golden Rule",\
   "to":"worldboss",\
   "fromPhone":"0244120126",\
   "toPhone":"0243559227",\
   "email":"theodondre@gmail.com",\
   "amount": 150,\
   "network": "MTN"\
}');\

try {\
  $response = $request->send();\

  echo $response->getBody();\
} catch (HttpException $ex) {\
  echo $ex;\
}\


# JAVASCRIPT XHR
var data = JSON.stringify({
  "username": "mark.garr",
  "password": "admin123",
  "name": "Golden Rule",
  "to": "worldboss",
  "fromPhone": "0244120126",
  "toPhone": "0243559227",
  "email": "theodondre@gmail.com",
  "amount": 150,
  "network": "MTN"
});

var xhr = new XMLHttpRequest();
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function () {
  if (this.readyState === 4) {
    console.log(this.responseText);
  }
});

xhr.open("POST", "http://35.236.211.103:80/balance");
xhr.setRequestHeader("Content-Type", "application/json");
xhr.setRequestHeader("User-Agent", "PostmanRuntime/7.18.0");
xhr.setRequestHeader("Accept", "*/*");
xhr.setRequestHeader("Cache-Control", "no-cache");
xhr.setRequestHeader("Postman-Token", "5fa14877-38f5-4ef7-8216-f107c4ad5e8e,0441ea12-72bb-4a4a-9984-e78d1ea9dad7");
xhr.setRequestHeader("Host", "35.236.211.103:80");
xhr.setRequestHeader("Accept-Encoding", "gzip, deflate");
xhr.setRequestHeader("Content-Length", "233");
xhr.setRequestHeader("Connection", "keep-alive");
xhr.setRequestHeader("cache-control", "no-cache");

xhr.send(data);

# NODEJS NATIVE
var http = require("http");

var options = {
  "method": "POST",
  "hostname": [
    "35",
    "236",
    "211",
    "103"
  ],
  "port": "80",
  "path": [
    "balance"
  ],
  "headers": {
    "Content-Type": "application/json",
    "User-Agent": "PostmanRuntime/7.18.0",
    "Accept": "*/*",
    "Cache-Control": "no-cache",
    "Postman-Token": "5fa14877-38f5-4ef7-8216-f107c4ad5e8e,22cc33a8-ecd3-4727-8db5-3aa90bb739c4",
    "Host": "35.236.211.103:80",
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "233",
    "Connection": "keep-alive",
    "cache-control": "no-cache"
  }
};

var req = http.request(options, function (res) {
  var chunks = [];

  res.on("data", function (chunk) {
    chunks.push(chunk);
  });

  res.on("end", function () {
    var body = Buffer.concat(chunks);
    console.log(body.toString());
  });
});

req.write(JSON.stringify({ username: 'mark.garr',
  password: 'admin123',
  name: 'Golden Rule',
  to: 'worldboss',
  fromPhone: '0244120126',
  toPhone: '0243559227',
  email: 'theodondre@gmail.com',
  amount: 150,
  network: 'MTN' }));
req.end();
