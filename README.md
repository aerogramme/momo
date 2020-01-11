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
	  - TopUps
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

 # https://github.com/aerogramme/momo/blob/master/withdraw.png
 # https://github.com/aerogramme/momo/blob/master/topup.png
