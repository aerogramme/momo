# pip install pyjwt

import jwt
import datetime

payload = {
    "uid": 23,
    "name": "masnun",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
}

SECRET_KEY = "N0TV3RY53CR3T"

token = jwt.encode(payload=payload, key=SECRET_KEY)

print("Generated Token: {}".format(token.decode()))

decoded_payload = jwt.decode(jwt=token, key=SECRET_KEY)

print(decoded_payload)
