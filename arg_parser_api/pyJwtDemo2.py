import jwt
import datetime
import time

payload = {
    "uid": 23,
    "name": "masnun",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=2)
}

SECRET_KEY = "N0TV3RY53CR3T"

token = jwt.encode(payload=payload, key=SECRET_KEY)

print("Generated Token: {}".format(token.decode()))

time.sleep(10)  # wait 10 secs so the token expires

decoded_payload = jwt.decode(jwt=token, key=SECRET_KEY)

print(decoded_payload)
