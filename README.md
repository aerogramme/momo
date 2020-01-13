# MobileMoney App

Simple Mobile Money application with authentication and CRUD functionality

![alt text](https://github.com/aerogramme/momo/blob/master/dashboard.png)

# Features
- Users can Pay loan
- Users can Register an account
- Users can Take loan
- Users can Top Up money on their mobile money wallet
- Users can Transfer money to other mobile money wallet
- Users can Withdraw money from their mobile money wallet

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

# API EndPoints
# POST Request:
 - Body
 { <br/>
   "username": "nana",<br/>
   "password": "admin123",<br/>
   "name":"Golden Rule",<br/>
   "to":"worldboss",<br/>
   "fromPhone":"0244120126",<br/>
   "toPhone":"0243559227",<br/>
   "email":"theodondre@gmail.com",<br/>
   "amount": 5,<br/>
   "network": "MTN"<br/>
}<br/>

 - http://35.236.211.103/pay
 - http://35.236.211.103/topup
 - http://35.236.211.103/withdraw
 - http://35.236.211.103/pay
 - http://35.236.211.103/signup
 - http://35.236.211.103/login
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
OkHttpClient client = new OkHttpClient();<br/>

MediaType mediaType = MediaType.parse("application/json"); \
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
  .build();<br/>

Response response = client.newCall(request).execute();\

# PHP
<?php <br/>
$request = new HttpRequest(); <br/>
$request->setUrl('http://35.236.211.103:80/balance'); <br/>
$request->setMethod(HTTP_METH_POST); <br/>

$request->setHeaders(array( <br/>
  'cache-control' => 'no-cache',<br/>
  'Connection' => 'keep-alive',<br/>
  'Content-Length' => '233',<br/>
  'Accept-Encoding' => 'gzip, deflate',<br/>
  'Host' => '35.236.211.103:80',<br/>
  'Postman-Token' => '5fa14877-38f5-4ef7-8216-f107c4ad5e8e,ad50d6e9-550f-4439-8a78-20bdccd39d1c',<br/>
  'Cache-Control' => 'no-cache',<br/>
  'Accept' => '*/*',<br/>
  'User-Agent' => 'PostmanRuntime/7.18.0',<br/>
  'Content-Type' => 'application/json' <br/>
)); <br/>

$request->setBody('{
   "username": "mark.garr",<br/>
   "password": "admin123",<br/>
   "name":"Golden Rule",<br/>
   "to":"worldboss",<br/>
   "fromPhone":"0244120126",<br/>
   "toPhone":"0243559227",<br/>
   "email":"theodondre@gmail.com",<br/>
   "amount": 150,<br/>
   "network": "MTN"<br/>
}'); <br/>

try {
  $response = $request->send(); <br/>

  echo $response->getBody(); <br/>
} catch (HttpException $ex) {
  echo $ex; <br/>
}
<br/>


### License

Copyright (C) 2020 aerograme.io <br/>

Licensed under the Apache License, Version 2.0 (the "License"); <br/>
you may not use this file except in compliance with the License. <br/>
You may obtain a copy of the License at <br/>

https://github.com/aerogramme/momo/LICENSE <br/>

Unless required by applicable law or agreed to in writing, software <br/>
distributed under the License is distributed on an "AS IS" BASIS,<br/>
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.<br/>
See the License for the specific language governing permissions and<br/>
limitations under the License.<br/>

### Contact us
<br/>
Please, contact us via support@aerogramme.io if you are using this library, just to let us know :) Thank you! <br/>
