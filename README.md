# Go 1.21 Windows Schannel Session Ticket Bug

To reproduce:
* Run the server: `go run .`
* Install the .p12 file in the local user's personal certificate store  (password: `password`)
* Browse to `https://127.0.0.1:8081` in Microsoft Edge and select the client certificate
* Edge will produce an error: `ERR_SSL_PROTOCOL_ERROR`

To regenerate the cert:
* Change the `readCert` call to `generateCert`
* Run `openssl pkcs12 -export -inkey key.pem -in cert.pem -out cert.p12`

Workarounds:
* Downgrade to Go 1.20 or earlier
* Or change the `WrapSession` implementation to `return []byte{0}, nil`