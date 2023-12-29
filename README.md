# ssh-pubkey

This is a modifed openssh-portable that allows you to use a public key to authenticate to a remote server without having to store the private key on the client machine. This is useful for situations where you want to authenticate to a remote server without having to store the private key on the client machine.

The ssh client get the signature from the trusted server and send it to the remote server. The detail of the protocol is described in the [RFC4252]<https://www.rfc-editor.org/rfc/rfc4252> .

In this project, I use the ecdsa-sha2-nistp256 algorithm to sign the digest. The server.java is a simple signature server that can be used to test the ssh client. The error handling is not complete, so it is not recommended to use it in production environment. The client communicates with the server via a https connection, so you need to install the certificate of the root CA in the client machine to verify the server certificate.

