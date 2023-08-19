use async_trait::async_trait;
use remote::get_public_key;
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

use ssi_dids::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    ERROR_NOT_FOUND,
};
use ssi_dids::{
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
#[cfg(feature = "secp256r1")]
use ssi_jwk::p256_parse;
use ssi_jwk::rsa_x509_pub_parse;
#[cfg(feature = "secp256k1")]
use ssi_jwk::secp256k1_parse;
use ssi_jwk::{Base64urlUInt, OctetParams, Params, JWK};

mod remote;

const DID_AI1OAUTH_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];
const DID_AI1OAUTH_SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
const DID_AI1OAUTH_BLS12381_G2_PREFIX: [u8; 2] = [0xeb, 0x01];
const DID_AI1OAUTH_P256_PREFIX: [u8; 2] = [0x80, 0x24];
const DID_AI1OAUTH_P384_PREFIX: [u8; 2] = [0x81, 0x24];
const DID_AI1OAUTH_RSA_PREFIX: [u8; 2] = [0x85, 0x24];

#[derive(Error, Debug)]
pub enum DIDAi1OAuthError {
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Unsupported curve: {0}")]
    UnsupportedCurve(String),
    #[error("Unsupported source")]
    UnsupportedSource,
}

pub struct DIDAi1OAuth;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDAi1OAuth {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let vm_type;
        let vm_type_iri;
        if !did.starts_with(&format!("did:{}:", self.name())) {
            return (
                ResolutionMetadata {
                    error: Some(ERROR_INVALID_DID.to_string()),
                    content_type: None,
                    property_set: None,
                },
                None,
                None,
            );
        }
        let pk_bytes = if let Some(pk) = get_public_key(did).await {pk} else {
            return (ResolutionMetadata::from_error("Unable to resolve public_key from identifier"), None, None);
        };

        let mut context = BTreeMap::new();
        context.insert(
            "publicKeyJwk".to_string(),
            serde_json::json!({
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
            }),
        );

        let jwk = if pk_bytes[0] == DID_AI1OAUTH_ED25519_PREFIX[0] && pk_bytes[1] == DID_AI1OAUTH_ED25519_PREFIX[1] {
            if pk_bytes.len() - 2 != 32 {
                return (
                    ResolutionMetadata {
                        error: Some(ERROR_INVALID_DID.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                );
            }
            vm_type = "Ed25519VerificationKey2018".to_string();
            vm_type_iri = "https://w3id.org/security#Ed25519VerificationKey2018".to_string();
            JWK {
                params: Params::OKP(OctetParams {
                    curve: "Ed25519".to_string(),
                    public_key: Base64urlUInt(pk_bytes[2..].to_vec()),
                    private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            }
        } else if pk_bytes[0] == DID_AI1OAUTH_SECP256K1_PREFIX[0] && pk_bytes[1] == DID_AI1OAUTH_SECP256K1_PREFIX[1] {
            if pk_bytes.len() - 2 != 33 {
                return (
                    ResolutionMetadata::from_error(ERROR_INVALID_DID),
                    None,
                    None,
                );
            }
            #[cfg(feature = "secp256k1")]
            match secp256k1_parse(&pk_bytes[2..]) {
                Ok(jwk) => {
                    vm_type = "EcdsaSecp256k1VerificationKey2019".to_string();
                    vm_type_iri =
                        "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019".to_string();
                    jwk
                }
                Err(err) => return (ResolutionMetadata::from_error(&err.to_string()), None, None),
            }
            #[cfg(not(feature = "secp256k1"))]
            return (
                ResolutionMetadata::from_error("did:key type secp256k1 not supported"),
                None,
                None,
            );
        } else if pk_bytes[0] == DID_AI1OAUTH_P256_PREFIX[0] && pk_bytes[1] == DID_AI1OAUTH_P256_PREFIX[1] {
            #[cfg(feature = "secp256r1")]
            match p256_parse(&pk_bytes[2..]) {
                Ok(jwk) => {
                    vm_type = "EcdsaSecp256r1VerificationKey2019".to_string();
                    vm_type_iri =
                        "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019".to_string();
                    jwk
                }
                Err(err) => return (ResolutionMetadata::from_error(&err.to_string()), None, None),
            }
            #[cfg(not(feature = "secp256r1"))]
            return (
                ResolutionMetadata::from_error("did:key type P-256 not supported"),
                None,
                None,
            );
        } else if pk_bytes[0] == DID_AI1OAUTH_P384_PREFIX[0] && pk_bytes[1] == DID_AI1OAUTH_P384_PREFIX[1] {
            #[cfg(feature = "secp384r1")]
            match ssi_jwk::p384_parse(&pk_bytes[2..]) {
                Ok(jwk) => {
                    vm_type = "JsonWebKey2020".to_string();
                    vm_type_iri = "https://w3id.org/security#JsonWebKey2020".to_string();
                    jwk
                }
                Err(err) => return (ResolutionMetadata::from_error(&err.to_string()), None, None),
            }
            #[cfg(not(feature = "secp384r1"))]
            return (
                ResolutionMetadata::from_error("did:key type P-384 not supported"),
                None,
                None,
            );
        } else if pk_bytes[0] == DID_AI1OAUTH_RSA_PREFIX[0] && pk_bytes[1] == DID_AI1OAUTH_RSA_PREFIX[1] {
            match rsa_x509_pub_parse(&pk_bytes[2..]) {
                Ok(jwk) => {
                    vm_type = "JsonWebKey2020".to_string();
                    vm_type_iri = "https://w3id.org/security#JsonWebKey2020".to_string();
                    jwk
                }
                Err(err) => return (ResolutionMetadata::from_error(&err.to_string()), None, None),
            }
        } else if pk_bytes[0] == DID_AI1OAUTH_BLS12381_G2_PREFIX[0]
            && pk_bytes[1] == DID_AI1OAUTH_BLS12381_G2_PREFIX[1]
        {
            {
                if pk_bytes.len() - 2 != 96 {
                    return (
                        ResolutionMetadata::from_error(ERROR_INVALID_DID),
                        None,
                        None,
                    );
                }
                vm_type = "Bls12381G2Key2020".to_string();
                vm_type_iri = "https://w3id.org/security#Bls12381G2Key2020".to_string();
                // https://datatracker.ietf.org/doc/html/draft-denhartog-pairing-curves-jose-cose-00#section-3.1.3
                JWK::from(Params::OKP(OctetParams {
                    curve: "Bls12381G2".to_string(),
                    public_key: Base64urlUInt(pk_bytes[2..].to_vec()),
                    private_key: None,
                }))
            }
        } else {
            return (
                ResolutionMetadata {
                    error: Some(ERROR_NOT_FOUND.to_string()),
                    content_type: None,
                    property_set: None,
                },
                None,
                None,
            );
        };
        context.insert(vm_type.to_string(), Value::String(vm_type_iri));
        let pk_string = multibase::encode(multibase::Base::Base58Btc, pk_bytes);
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some(pk_string.clone()),
            ..Default::default()
        };
        let doc = Document {
            context: Contexts::Many(vec![
                Context::URI(DEFAULT_CONTEXT.to_string()),
                Context::Object(context),
            ]),
            id: did.to_string(),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: format!("{did}#{pk_string}"),
                type_: vm_type,
                controller: did.to_string(),
                public_key_jwk: Some(jwk),
                ..Default::default()
            })]),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl)]),
            ..Default::default()
        };
        (
            ResolutionMetadata::default(),
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

impl DIDMethod for DIDAi1OAuth {
    fn name(&self) -> &'static str {
        "ai1oauth"
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let pattern = match source {
            Source::Key(_) => { 
                // JWK unneeded, pattern required
                return None;
            },
            Source::KeyAndPattern(_, pattern) => pattern,
            _ => return None,
        };

        // Pattern is format "<provider>:<identifier>"
        let mut split = pattern.splitn(3, ':');

        // Validate that <provider> is present
        let provider = if let Some(prov) = split.next() {prov} else {return None;};

        // Extract <identifier>
        let identifier = if let Some(ident) = split.next() {ident} else {return None;};

        Some(format!("did:{}:{provider}:{identifier}", self.name()))
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

pub fn fragment_from_jwk(jwk: &JWK) -> Option<String> {
    let fragment = match jwk.params {
        Params::OKP(ref params) => {
            match &params.curve[..] {
                "Ed25519" => {
                    multibase::encode(
                            multibase::Base::Base58Btc,
                            [DID_AI1OAUTH_ED25519_PREFIX.to_vec(), params.public_key.0.clone()]
                                .concat(),
                        )
                }
                "Bls12381G2" => {
                    multibase::encode(
                            multibase::Base::Base58Btc,
                            [
                                DID_AI1OAUTH_BLS12381_G2_PREFIX.to_vec(),
                                params.public_key.0.clone(),
                            ]
                            .concat(),
                        )
                }
                //_ => return Some(Err(DIDAi1oauthError::UnsupportedCurve(params.curve.clone()))),
                _ => return None,
            }
        }
        Params::EC(ref params) => {
            let curve = match params.curve {
                Some(ref curve) => curve,
                None => return None,
            };
            match &curve[..] {
                #[cfg(feature = "secp256k1")]
                "secp256k1" => {
                    use k256::elliptic_curve::sec1::ToEncodedPoint;
                    let pk = match k256::PublicKey::try_from(params) {
                        Ok(pk) => pk,
                        Err(_err) => return None,
                    };
                    multibase::encode(
                            multibase::Base::Base58Btc,
                            [
                                DID_AI1OAUTH_SECP256K1_PREFIX.to_vec(),
                                pk.to_encoded_point(true).as_bytes().to_vec(),
                            ]
                            .concat(),
                        )
                }
                #[cfg(feature = "secp256r1")]
                "P-256" => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint;
                    let pk = match p256::PublicKey::try_from(params) {
                        Ok(pk) => pk,
                        Err(_err) => return None,
                    };
                    multibase::encode(
                            multibase::Base::Base58Btc,
                            [
                                DID_AI1OAUTH_P256_PREFIX.to_vec(),
                                pk.to_encoded_point(true).as_bytes().to_vec(),
                            ]
                            .concat(),
                        )
                }
                #[cfg(feature = "secp384r1")]
                "P-384" => {
                    let pk_bytes = match ssi_jwk::serialize_p384(params) {
                        Ok(pk) => pk,
                        Err(_err) => return None,
                    };
                    multibase::encode(
                            multibase::Base::Base58Btc,
                            [DID_AI1OAUTH_P384_PREFIX.to_vec(), pk_bytes].concat(),
                        )
                }
                //_ => return Some(Err(DIDAi1oauthError::UnsupportedCurve(params.curve.clone()))),
                _ => return None,
            }
        }
        Params::RSA(ref params) => {
            let der = simple_asn1::der_encode(&params.to_public()).ok()?;
            multibase::encode(
                    multibase::Base::Base58Btc,
                    [DID_AI1OAUTH_RSA_PREFIX.to_vec(), der.to_vec()].concat(),
                )
        }
        _ => return None, // _ => return Some(Err(DIDAi1oauthError::UnsupportedKeyType)),
    };
    Some(fragment)
}


#[cfg(test)]
mod tests {
    use crate::remote::get_uri;

    use super::*;
    use reqwest::StatusCode;
    use serde_json::json;
    use ssi_dids::did_resolve::{dereference, Content, DereferencingInputMetadata};
    use ssi_dids::Resource;

    #[ctor::ctor]
    fn init() {
        use std::{env, process::Command, thread, time::Duration};

        // set the resolver's URI in the environment if not already set
        if env::var("AI1OAUTH_DID_RESOLUTION_URI").is_err() {
            env::set_var("AI1OAUTH_DID_RESOLUTION_URI", "http://localhost:3000/did/");
        }

        eprintln!("Using resolution URI {}", env::var("AI1OAUTH_DID_RESOLUTION_URI").unwrap());

        // start local did-resolution server
        let path = "../testutils/didresolver";
        let started = Command::new(
            "./start.sh"
        )
        .current_dir(path)
        .spawn();

        thread::sleep(Duration::from_secs(2));

        if started.is_ok() {
            eprintln!("localhost DID resolver started");
        } else {
            eprintln!("Failed to start localhost DID resolver, did-ai1oauth tests will fail.");
            eprintln!("{:?}", started);
        }

    }

    async fn testing_add_did(did: &str, pubkey: &str) {
        let did_resolver_uri = get_uri();
        let client = reqwest::Client::new();
        let full_url = format!("{did_resolver_uri}public_key");
        let body = json!({
            "did": did,
            "pubkey": pubkey,
        });
        eprintln!("Sending request: {full_url}");

        let response = client
            .post(full_url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .expect("Failed to send pubkey for retrieval");

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn from_did_github() {
        let pattern = "github:githubunittestuser";
        let did = format!("did:ai1oauth:{pattern}");
        let pubkey = "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
        testing_add_did(&did, pubkey).await;

        let (res_meta, _doc, _meta) = DIDAi1OAuth
            .resolve(&did, &ResolutionInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);

        let vm = format!("{did}#{pubkey}");
        let (res_meta, object, _meta) =
            dereference(&DIDAi1OAuth, &vm, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);

        let vm = match object {
            Content::Object(Resource::VerificationMethod(vm)) => vm,
            _ => unreachable!(),
        };
        let key = vm.public_key_jwk.unwrap();

        // convert back to DID from JWK
        let did1 = DIDAi1OAuth.generate(&Source::KeyAndPattern(&key, pattern)).unwrap();
        assert_eq!(did1, did);
    }

    #[tokio::test]
    async fn credential_prove_verify_did_ai1oauth_github() {
        use ssi_vc::{get_verification_method, Credential, Issuer, LinkedDataProofOptions, URI};

        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://schema.org/"
            ],
            "type": [
                "VerifiableCredential", 
                "scrai:OAuthUsernameCredential"
            ],
            "issuer": "did:ai1oauth:github:ssiunittest",
            "issuanceDate": "2021-02-18T20:17:46Z",
            "credentialSubject": {
                "id": "did:ai1oauth:github:ssiunittest"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key = JWK::generate_secp256k1().unwrap();
        let pubkey = fragment_from_jwk(&key).unwrap();
        let did = DIDAi1OAuth.generate(&Source::KeyAndPattern(&key, "github:ssiunittest")).unwrap();
        testing_add_did(&did, &pubkey).await;
        
        let verification_method = get_verification_method(&did, &DIDAi1OAuth).await.unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        vc.issuer = Some(Issuer::URI(URI::String(did.clone())));
        
        println!("{}", serde_json::to_string_pretty(&vc).unwrap());

        issue_options.verification_method = Some(URI::String(verification_method));
        let proof = vc
            .generate_proof(&key, &issue_options, &DIDAi1OAuth, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDAi1OAuth, &mut context_loader).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer is verified
        vc.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(!vc
            .verify(None, &DIDAi1OAuth, &mut context_loader)
            .await
            .errors
            .is_empty());
    }

}
