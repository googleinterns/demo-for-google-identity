# demo-for-google-identity
##Current Progress

Finish Basic Login Filter using Guice-Servlet

No authentication, just allow, but you need to enter login information.

The default port is 8080

All resources under /resource is protected(currently only have /resource/user)

How to runit:
Use cloud SDK and maven:

locally:
mvn package appengine:run

cloud:
mvn package appengine:deploy 