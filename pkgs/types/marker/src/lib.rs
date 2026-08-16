//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Procedural macro definitions.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};
use xxhash_rust::xxh32::xxh32;

/// Derives `__CodecMarker` for types that are not wire-encodable.
///
/// Expands to `impl __CodecMarker` and `impl __UnencodableMarker` on the
/// annotated type. The guard trait has a blanket impl over `BaseCodec`, so
/// applying `Unencodable` to a wire type produces a compiler error.
#[proc_macro_derive(Unencodable)]
pub fn derive_unencodable(input: TokenStream) -> TokenStream {
  let input = parse_macro_input!(input as DeriveInput);
  let name = &input.ident;
  let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

  let expanded = quote! {
    impl #impl_generics ::dash_types::codec::__CodecMarker for #name #ty_generics #where_clause {}
    impl #impl_generics ::dash_types::codec::__UnencodableMarker for #name #ty_generics #where_clause {}
  };

  expanded.into()
}

/// Derives `TypeId` with a compile-time XXH32 hash of the type name.
#[proc_macro_derive(TypeId)]
pub fn derive_type_id(input: TokenStream) -> TokenStream {
  let input = parse_macro_input!(input as DeriveInput);
  let name = &input.ident;
  let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

  let name_str = name.to_string();
  let id = xxh32(name_str.as_bytes(), 0);

  let expanded = quote! {
    impl #impl_generics ::dash_types::type_id::TypeId for #name #ty_generics #where_clause {
      const TYPE_ID: u32 = #id;
    }
  };

  expanded.into()
}
