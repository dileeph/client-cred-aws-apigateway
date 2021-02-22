# gateway-okta-authorizer

This is the sample POC done to implement security for client credentials flow.
After any changes do a
```bash
sam build --use-containers
sam package --s3-bucket <bucketname> --force-upload
```
The uploaded zip file is then to be installed into a new lambda.
Configure the lambda to have access to SSM.

In API Gateway configure this as a Custom Authorizer. For that, create Custom Authorizer.
Then edit the API path property to set this as the authorizer. Now deploy so that it gets set into Prod.

Ensure that the JWKS is set in System Manager - Parameter Store