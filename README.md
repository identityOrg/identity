![Java CI](https://github.com/identityOrg/identity/workflows/Java%20CI/badge.svg)
# identity
A OAuth 2 authorization server implementation conforming to rfc6749

## Implemented Specifications

1. https://tools.ietf.org/html/rfc6749
1. https://tools.ietf.org/html/rfc6750
1. https://tools.ietf.org/html/rfc6819
1. https://tools.ietf.org/html/rfc7009
1. https://tools.ietf.org/html/rfc7662
1. https://tools.ietf.org/html/rfc7636
1. https://tools.ietf.org/html/rfc7519
1. https://tools.ietf.org/html/rfc7591
1. https://tools.ietf.org/html/rfc7592
1. https://tools.ietf.org/html/rfc7521

## Dependency update command

Update parent pom version

```shell script
./mvnw versions:update-parent
```

Update property declared versions
```shell script
./mvnw versions:update-properties
```

Commit the update
```shell script
./mvnw versions:commit
```
