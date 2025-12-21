//! JWTiny Macros
//!
//! This crate provides the `#[claims]` attribute macro.

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Generate standard JWT claim fields and implement `StandardClaims` trait
///
/// Adds the following fields to the struct:
/// - `issuer` (iss) - principal that issued the JWT
/// - `subject` (sub) - principal that is the subject of the JWT
/// - `audience` (aud) - recipients the JWT is intended for
/// - `expiration` (exp) - expiration time in seconds since Unix epoch
/// - `not_before` (nbf) - time before which the JWT must not be accepted
/// - `issued_at` (iat) - time at which the JWT was issued
/// - `jwt_id` (jti) - unique identifier for the JWT
#[proc_macro_attribute]
pub fn claims(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let struct_name = &input.ident;
    let vis = &input.vis;
    let generics = &input.generics;

    // Extract existing fields if it's a struct
    let existing_fields = if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(fields),
        ..
    }) = &input.data
    {
        &fields.named
    } else {
        return syn::Error::new_spanned(
            struct_name,
            "#[claims] can only be applied to structs with named fields",
        )
        .to_compile_error()
        .into();
    };

    // Generate the expanded struct with standard claims fields
    // Always include Debug, Clone, and Deserialize derives
    let expanded = quote! {
        /// Standard JWT claims
        #[derive(Debug, Clone, miniserde::Deserialize)]
        #vis struct #struct_name #generics {
            /// Issuer (iss) - principal that issued the JWT
            #[serde(rename = "iss")]
            pub issuer: Option<String>,
            /// Subject (sub) - principal that is the subject of the JWT
            #[serde(rename = "sub")]
            pub subject: Option<String>,
            /// Audience (aud) - recipients the JWT is intended for
            #[serde(rename = "aud")]
            pub audience: Option<String>,
            /// Expiration (exp) - expiration time in seconds since Unix epoch
            #[serde(rename = "exp")]
            pub expiration: Option<i64>,
            /// Not Before (nbf) - time before which the JWT must not be accepted
            #[serde(rename = "nbf")]
            pub not_before: Option<i64>,
            /// Issued At (iat) - time at which the JWT was issued
            #[serde(rename = "iat")]
            pub issued_at: Option<i64>,
            /// JWT ID (jti) - unique identifier for the JWT
            #[serde(rename = "jti")]
            pub jwt_id: Option<String>,

            #existing_fields
        }

        impl #generics jwtiny::StandardClaims for #struct_name #generics {
            fn issuer(&self) -> Option<&str> {
                self.issuer.as_deref()
            }

            fn subject(&self) -> Option<&str> {
                self.subject.as_deref()
            }

            fn audience(&self) -> Option<&str> {
                self.audience.as_deref()
            }

            fn expiration(&self) -> Option<i64> {
                self.expiration
            }

            fn not_before(&self) -> Option<i64> {
                self.not_before
            }

            fn issued_at(&self) -> Option<i64> {
                self.issued_at
            }

            fn jwt_id(&self) -> Option<&str> {
                self.jwt_id.as_deref()
            }
        }
    };

    TokenStream::from(expanded)
}
