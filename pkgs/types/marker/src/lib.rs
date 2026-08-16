//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Procedural macro definitions.

use proc_macro::TokenStream;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::token::Plus;
use syn::{parse_macro_input, DeriveInput, Generics, Type, TypeParam, TypeParamBound, WherePredicate};
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

  let codec = quote!(::dash_types::codec);
  quote! {
    impl #impl_generics #codec::__CodecMarker for #name #ty_generics #where_clause {}
    impl #impl_generics #codec::__UnencodableMarker for #name #ty_generics #where_clause {}
  }
  .into()
}

/// Derives `TypeId` from the type name and its type parameters' own ids.
///
/// Each parameter's `TYPE_ID` folds into the XXH32 of the bare name in
/// declaration order. Lifetimes are ignored; const parameters and openly
/// bounded ones are rejected, as neither yields an enumerable set of ids.
#[proc_macro_derive(TypeId)]
pub fn derive_type_id(input: TokenStream) -> TokenStream {
  let input = parse_macro_input!(input as DeriveInput);
  let name = &input.ident;

  if let Some(param) = input.generics.const_params().next() {
    let msg = "cannot derive TypeId on a type with const parameters, as its instantiations would share one id";
    return syn::Error::new_spanned(param, msg).to_compile_error().into();
  }

  for param in input.generics.type_params() {
    if bound_names(param, &input.generics).iter().all(|b| b == "TypeId") {
      let msg = "cannot derive TypeId on openly bounded type params; bound it with a marker trait";
      return syn::Error::new_spanned(param, msg).to_compile_error().into();
    }
  }

  let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

  let tid = quote!(::dash_types::type_id);
  let params: Vec<_> = input.generics.type_params().map(|p| &p.ident).collect();
  let base = xxh32(name.to_string().as_bytes(), 0);
  let id = params.iter().fold(
    quote!(#base),
    |acc, param| quote!(#tid::mix(#acc, <#param as #tid::TypeId>::TYPE_ID)),
  );
  let kept = where_clause.into_iter().flat_map(|w| w.predicates.iter());

  quote! {
    impl #impl_generics #tid::TypeId for #name #ty_generics
    where #(#kept,)* #(#params: #tid::TypeId,)* {
      const TYPE_ID: u32 = #id;
    }
  }
  .into()
}

/// Collects the trait names bounding `param`, inline and in `where`.
fn bound_names(param: &TypeParam, generics: &Generics) -> Vec<String> {
  fn named(bounds: &Punctuated<TypeParamBound, Plus>) -> Vec<String> {
    bounds
      .iter()
      .filter_map(|bound| match bound {
        TypeParamBound::Trait(bound) => Some(bound.path.segments.last()?.ident.to_string()),
        _ => None,
      })
      .collect()
  }

  let mut names = named(&param.bounds);
  for pred in generics.where_clause.iter().flat_map(|w| w.predicates.iter()) {
    let WherePredicate::Type(pred) = pred else {
      continue;
    };
    if let Type::Path(ty) = &pred.bounded_ty {
      if ty.qself.is_none() && ty.path.is_ident(&param.ident) {
        names.extend(named(&pred.bounds));
      }
    }
  }
  names
}
