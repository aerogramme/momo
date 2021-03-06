# MobileMoney App
```
Simple Mobile Money application with authentication and CRUD functionality. Contributors are welcome.
```
![alt text](https://github.com/aerogramme/momo/blob/master/dashboard.png)

# Features
- Users can Pay loan
- Users can signup for an account
- Users can login into a registered account
- Users can Take loan
- Users can Top Up money on their mobile money wallet
- Users can Transfer money to other mobile money wallet
- Users can Withdraw money from their mobile money wallet

# Installation

To use this template, your computer needs:

- [Python 3](https://python.org)
- Python Flask Micro-framework
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
```
- docker-compose up
```
# CD into Docker
```
- docker-compose exec -it <name of container> bash
```

### Running the app locally

```
python app.py
```

# API EndPoints
#### POST Request:
 - Body
 ```
 {
   "username": "freeworldboss",
   "password": "cq#4&Ds6~K+0iwU_",
   "firstname":"THEOPHILUS",
   "lastname":"SIAMEH",
   "fromPhone":"0243559227",
   "toPhone":"0205592278",
   "email":"theodondre@gmail.com",
   "amount": 8749.31,
   "network": "MTN",
   "fromNetwork":"MTN",
   "toNetwork":"TIGO"
}
```

 - http://35.236.211.103/pay
 - http://35.236.211.103/topup
 - http://35.236.211.103/withdraw
 - http://35.236.211.103/transfer
 - http://35.236.211.103/balance
 - http://35.236.211.103/loan
 - http://35.236.211.103/signup
 - http://35.236.211.103/login


# Withdraw POST request
 ![alt text](https://github.com/aerogramme/momo/blob/master/withdraw.png)

# TopUp POST request
 ![alt text](https://github.com/aerogramme/momo/blob/master/topup.png)

# CURL

```
Localhost:

curl -X POST \
  http://127.0.0.1:5000/momo/api/v1.0/balance \
  -H 'Accept: */*' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Authorization: Basic ZnJlZXdvcmxkYm9zczpjcSM0JkRzNn5LKzBpd1Vf' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Content-Length: 307' \
  -H 'Content-Type: application/json' \
  -H 'Host: 127.0.0.1:5000' \
  -H 'Postman-Token: 8154208d-7996-4656-8962-add3e79aa1ed,cb850032-7c79-43ae-bb4a-898af9b813d2' \
  -H 'User-Agent: PostmanRuntime/7.18.0' \
  -H 'cache-control: no-cache' \
  -d '{
   "username": "freeworldboss",
   "password": "cq#4&Ds6~K+0iwU_",
   "firstname":"THEOPHILUS",
   "lastname":"SIAMEH",
   "fromPhone":"0243559227",
   "toPhone":"0205592278",
   "email":"theodondre@gmail.com",
   "amount": 8749.31,
   "network": "MTN",
   "fromNetwork":"MTN",
   "toNetwork":"VODAFONE"
}'


Remote:

 curl -X POST \
  http://35.236.211.103:80/balance \
  -H 'Accept: */*' \
  -H 'Authorization: Basic ZnJlZXdvcmxkYm9zczpjcSM0JkRzNn5LKzBpd1Vf' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Content-Length: 233' \
  -H 'Content-Type: application/json' \
  -H 'Host: 35.236.211.103:80' \
  -H 'User-Agent: PostmanRuntime/7.18.0' \
  -H 'cache-control: no-cache' \
  -d '{
   "username": "freeworldboss",
   "password": "cq#4&Ds6~K+0iwU_",
   "firstname":"THEOPHILUS",
   "lastname":"SIAMEH",
   "fromPhone":"0243559227",
   "toPhone":"0205592278",
   "email":"theodondre@gmail.com",
   "amount": 8749.31,
   "network": "MTN",
   "fromNetwork":"MTN",
   "toNetwork":"VODAFONE"
}'
```

# PYTHON
```
import requests

url = "http://35.236.211.103:80/balance"

payload = "{\n   \"username\": \"freeworldboss\",\n   \"password\": \"cq#4&Ds6~K+0iwU_\",\n   \"firstname\":\"THEOPHILUS\",\n   \"lastname\":\"SIAMEH\",\n   \"fromPhone\":\"0243559227\",\n   \"toPhone\":\"0205592278\",\n   \"email\":\"theodondre@gmail.com\",\n   \"amount\": 8749.31,\n   \"network\": \"MTN\",\n   \"fromNetwork\":\"MTN\",\n   \"toNetwork\":\"VODAFONE\"\n}"

headers = {
    'Content-Type': "application/json",
    'User-Agent': "PostmanRuntime/7.18.0",
    'Accept': "*/*",
    'Cache-Control': "no-cache",
    'Host': "35.236.211.103:80",
    'Accept-Encoding': "gzip, deflate",
    'Content-Length': "233",
    'Connection': "keep-alive",
    'cache-control': "no-cache"
    }

response = requests.request("POST", url, data=payload, headers=headers)

print(response.text)
```

# JAVA
```
public final String BASE_URL = "http://35.236.211.103:80/balance"
OkHttpClient client = new OkHttpClient();

MediaType mediaType = MediaType.parse("application/json");
RequestBody body = RequestBody.create(mediaType,
    "{\n   \"username\": \"freeworldboss\",\n
     \"password\": \"cq#4&Ds6~K+0iwU_\",\n
      \"firstname\":\"THEOPHILUS\",\n
      \"lastname\":\"SIAMEH\",\n
      \"fromPhone\":\"0243559227\",\n
       \"toPhone\":\"0205592278\",\n
       \"email\":\"theodondre@gmail.com\",\n
        \"amount\": 8749.31,\n
         \"network\": \"MTN\",\n
         \"fromNetwork\":\"MTN\",\n
          \"toNetwork\":\"VODAFONE\"\n}");

Request request = new Request.Builder()
  .url(BASE_URL)
  .post(body)
  .addHeader("Content-Type", "application/json")
  .addHeader("User-Agent", "PostmanRuntime/7.18.0")
  .addHeader("Accept", "*/*")
  .addHeader("Cache-Control", "no-cache")
  .addHeader("Host", "35.236.211.103:80")
  .addHeader("Accept-Encoding", "gzip, deflate")
  .addHeader("Content-Length", "233")
  .addHeader("Connection", "keep-alive")
  .addHeader("cache-control", "no-cache")
  .build();

Response response = client.newCall(request).execute();
```

# PHP
```
<?php <br/>
$request = new HttpRequest();
$request->setUrl('http://35.236.211.103:80/balance');
$request->setMethod(HTTP_METH_POST);

$request->setHeaders(array(
  'cache-control' => 'no-cache',
  'Connection' => 'keep-alive',
  'Content-Length' => '233',
  'Accept-Encoding' => 'gzip, deflate',
  'Host' => '35.236.211.103:80',
  'Cache-Control' => 'no-cache',
  'Accept' => '*/*',
  'User-Agent' => 'PostmanRuntime/7.18.0',
  'Content-Type' => 'application/json'
));

$request->setBody('{
   "username": "freeworldboss",
   "password": "cq#4&Ds6~K+0iwU_",
   "firstname":"THEOPHILUS",
   "lastname":"SIAMEH",
   "fromPhone":"0243559227",
   "toPhone":"0205592278",
   "email":"theodondre@gmail.com",
   "amount": 8749.31,
   "network": "MTN",
   "fromNetwork":"MTN",
   "toNetwork":"VODAFONE"
}');

try {
  $response = $request->send();
  echo $response->getBody();
} catch (HttpException $ex) {
  echo $ex;
}
```


# LICENSE
```
	Copyright (C) 2020 https://aerograme.io

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://github.com/aerogramme/momo/LICENSE

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
```

# CONTACT US
```
 	- Please, contact us via support@aerogramme.io if you are using this library, just to let us know :) Thank you! <br/>
```
# CONTRIBUTORS
```
 	- THEOPHILUS SIAMEH | @tsiameh
 ```
