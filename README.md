# ssh-pubkey
This is a modifed openssh-portable that allows you to use a public key to authenticate to a remote server without having to store the private key on the client machine. This is useful for situations where you want to authenticate to a remote server without having to store the private key on the client machine. 

The ssh client get the signature from the trusted server and send it to the remote server. The detail of the protocol is described in the [RFC4252]https://www.rfc-editor.org/rfc/rfc4252 .
