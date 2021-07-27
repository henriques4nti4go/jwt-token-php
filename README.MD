# Class php jwt token generator

php class to generate and validate jwt tokens.

## Run
to execute the project

```bash
docker-compose up
```

## PHP Jwt

first instantiate the object passing the secret key to the class constructor to generate the token signature.

![Alt text](/images/object-instance.png?raw=true "object instance")

the object instance has access to the generate method where you pass the payload and generate the token.

![Alt text](/images/generate-token.png?raw=true "return metodo generate")

the generate method's answer is this:

![Alt text](/images/token.png?raw=true "return method generate")

you also have access to the decode method, where it validates the signature and returns if the token is valid

![Alt text](/images/decode-token.png?raw=true "method decode token")

the response of the decode method is equal to:

![Alt text](/images/return-decode-token.png?raw=true "return method decode token")