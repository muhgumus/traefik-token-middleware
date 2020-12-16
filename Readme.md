#  Traefik Token Middleware

 Traefik JWT Token Middleware for Query parameters 

## Configuration

Start with command
```yaml
command:
  - --experimental.plugins.traefik-token-middleware.modulename=github.com/muhgumus/traefik-token-middleware
  - --experimental.plugins.traefik-token-middleware.version=v0.1.2
```

Activate plugin in your config  

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: my-jwtauth
spec:
  plugin:
    traefik-token-middleware:
      queryParam: token
      proxyHeadernmae: injectPayload
      secret: secret
```
