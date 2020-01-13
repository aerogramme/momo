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
