use base64::Engine;
use jwtiny::{AlgorithmPolicy, ClaimsValidation, TokenValidator};

#[tokio::test]
async fn test_synchronous_machine() {
    let token_str: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6IjdNZU5QY0tFa2pnbHZBalB1VFg5S0F0UExkdWwtMGVtYmptMkFwOGNqdWctUlM1MTIifQ.eyJhdWQiOiJteS1hcHAiLCJleHAiOjE3MzU2ODk2MDAsImlhdCI6MTcwNDA2NzIwMCwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTozMDAwIiwibmJmIjoxNzA0MDY3MjAwLCJzdWIiOiJ1c2VyLTEyMzQ1In0.icaMsUMZc0L4eGZgIPBvIst56Gmb7eEdK0JO-On8M9FOn9BANmZB-IJkmAFrD70funYDKDay4wd1FY3VBW8HLGSaMZRusRSSCOTiYT7MMCnaZ3Mtud_aabyOJqZUdNEpOO9fFENe2TPPABYy_Ml-8VEf6USw_C56LVCtxh0ggLQry0fDO75iphgFMskWshGXX3Nko8OMPhbvT6sNJ3KFiqpwCJwP_-rNddJc8Rl97Cf7W9HoUIO6Nbe87c__JFDkKJgSroMgnqcejfYxecXpoQFmnMS5nHj_6bxtQPq1p29mWlqTjWXT0jlTKj45q6QtmtJWKf5S5zh5lqRC7A8yGw";
    let public_key_der = base64::engine::general_purpose::STANDARD
        .decode(r#"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9vd5T8t5E0dMWF9A9oCW1VIsRaD4htkr+NAfF2gh50OmjaDXNZAL4Pb7uRsWChH6aPB1u0BxcBNrOn9w386hhhRrkWQtyeXjWe+LAEY3iROxmf9uqQDq1OtXXZ8MtjEZttXiviDoa0VEiqjTS3eOh8h4zEirCq/2L3pM5MinHLXy7MGMsQ32ujbYH9Aga/QgXMTm0H4EWyMUbR+8yY8TrzacAEOQPGa1+mxX5GPPNmATVJSudmKCgakCIdcQ6qfGPPDw1GRP7TrOG8piXJD2N+q586jYjOiFONem3Q3x5nbiHFB0+HwnvNHgCGIzOxpNeO7ruDaMIAX9ite2KRRlLwIDAQAB"#)
        .unwrap();

    let mut validator = TokenValidator::new();
    validator
        .algorithms(AlgorithmPolicy::rs512_only())
        .validate(
            ClaimsValidation::default()
                .no_iat_validation()
                .no_exp_validation()
                .no_nbf_validation(),
        )
        .key(&public_key_der);

    let result = validator.verify(token_str).await;

    assert!(
        result.is_ok(),
        "Failed to validate token: {}",
        result.err().unwrap()
    );
}
