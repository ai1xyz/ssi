# did-scraioauth

Rust implementation of a bespoke `did:scraioauth` DID Method, based on the `ssi` library.

Written initially to support GitHub OAuth-based identities in the Scrai app by MIM Holdings, (c) 2023.
Other OAuth-backed DIDs may be added in the future.

## Format
`did:scraioauth:method-specific-identifier`, where:
 - *method-specific-identifier* is further broken down into `provider:identity`
 - *provider* is the identifier of a supported OAuth provider; currently only `github` is supported
 - *identity* is the user identifier within that OAuth system; for `github`, this would be the GitHub username
 
 When providing a `verificationMethod`, an additional fragment *public-key* specifies the public half of the signing key generated during the OAuth web or device flow that gave Scrai permission to the *identity*; this is Btc58 encoded, and generally only specified as part of a `verificationMethod` block in a Verifiable Credential.

 Verification Method Example: 
 > `did:scraioauth:github:octocat#zQ3shYFpUdaX2sBZNXTUgyKWJv8kZvSwt6Ump3xUw7uWpTrrd`

 In this example, the GitHub username is `octocat` and the public signing key is everything following the `#`, starting with `zQ3sh` etc.

 ## Generation
 When a Scrai user imports her GitHub username as a Scrai Identity, Scrai initiates an OAuth flow with GitHub to verify that the user has access to this username and wishes to give Scrai limited access to maintain proof of ownership. During this process, a K-256 Elliptic Curve keypair are generated for signing purposes, and the public half is sent to the Scrai servers to be associated with the GitHub username.

 When the OAuth flow successfully completes, github.com returns a bearer token to the Scrai server, which is used to obtain the confirmed username. This username and the public key are associated together in Secure Credential Storage, and used for secondary VC verification.

 ## Resolution
 Because the public signing key is required to verify LD proofs in Verifiable Credentials, the Scrai DID Resolution server is required. This server takes a DID as input and returns the public signing key in Btc58 encoding, suitable for direct copying into the fragment portion of the `verificationMethod`.

 During development, the URL of this DID Resolution server is https://3wbyu4xc5l.execute-api.us-east-1.amazonaws.com/did/public_key?did=did_to_resolve

 The base URL (up through the "/did" portion) can be overridden with the `SCRAIOAUTH_DID_RESOLUTION_URI` environment variable.


 ## Verification
 The `DIDScraiOAuth::resolve()` method takes care of requesting the public key fragment from the DID Resolution server, and then proceeds with a `Secp251k`-based signature verification of the LD Proof using the returned public key. 