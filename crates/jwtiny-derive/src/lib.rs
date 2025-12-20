//! JWTiny Macros
//!
//! This crate provides the `#[claims]` attribute macro.

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Generates standard JWT claim fields and implements `StandardClaims` trait.
///
/// Fields included:
/// - Issuer (`iss`)
/// - Subject (`sub`)
/// - Audience (`aud`)
/// - Expiration (`exp`)
/// - Not Before (`nbf`)
/// - Issued At (`iat`)
/// - JWT ID (`jti`)
///
/// And implements the `StandardClaims` trait.
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
        #[derive(Debug, Clone, miniserde::Deserialize)]
        #vis struct #struct_name #generics {
            #[serde(rename = "iss")]
            pub issuer: Option<String>,
            #[serde(rename = "sub")]
            pub subject: Option<String>,
            #[serde(rename = "aud")]
            pub audience: Option<String>,
            #[serde(rename = "exp")]
            pub expiration: Option<i64>,
            #[serde(rename = "nbf")]
            pub not_before: Option<i64>,
            #[serde(rename = "iat")]
            pub issued_at: Option<i64>,
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
