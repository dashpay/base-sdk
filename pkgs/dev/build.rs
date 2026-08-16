//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Emits a `TypeId` collision-check table from workspace sources.

#![expect(clippy::expect_used, clippy::unwrap_used, clippy::panic, reason = "build script")]

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{visit_item_enum, visit_item_macro, visit_item_struct, Visit};
use syn::{parse_file, Attribute, Generics, Ident, ItemEnum, ItemMacro, ItemStruct};
use xxhash_rust::xxh32::xxh32;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::{env, fs};

const SCAN_DIRS: &[&str] = &[
  "pkgs/num/src",
  "pkgs/types/src",
  "pkgs/primitives/src",
  "pkgs/p2p_core/src",
  "pkgs/pkc/src",
];

fn main() {
  let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
  let ws_root = PathBuf::from(&manifest)
    .parent()
    .unwrap()
    .parent()
    .unwrap()
    .to_path_buf();

  let mut scan = ScanResult::default();

  for dir in SCAN_DIRS {
    let src = ws_root.join(dir);
    if src.is_dir() {
      walk_rs_files(&src, &mut |path| scan_file(path, &mut scan));
    }
    println!("cargo::rerun-if-changed={}", ws_root.join(dir).display());
  }

  for (macro_name, type_name) in &scan.pending {
    if scan.type_id_macros.contains(macro_name) {
      scan.names.push(type_name.clone());
    }
  }

  assert!(!scan.names.is_empty(), "scanner produced no TypeId entries");

  check_unique(&scan.names, "TypeId");
  check_unique(&scan.generics, "generic TypeId base name");

  built::write_built_file().expect("failed to write built.rs metadata");
}

/// Fails the build on a shared id, which would decode one type into
/// another's slot.
///
/// # Panics
///
/// Panics when two distinct names in `names` hash to the same id.
fn check_unique(names: &[String], kind: &str) {
  let mut seen: HashMap<u32, &str> = HashMap::new();
  for name in names {
    let id = xxh32(name.as_bytes(), 0);
    if let Some(prev) = seen.insert(id, name) {
      if prev != name {
        panic!("{kind} collision: {name} and {prev} share id {id:#010x}");
      }
    }
  }
}

#[derive(Default)]
struct ScanResult {
  /// `macro_rules!` names whose body contains `TypeId`.
  type_id_macros: BTreeSet<String>,
  /// Non-generic derive sites, where id is exactly the XXH32 of the name.
  names: Vec<String>,
  /// Generic derive sites, where name hash is only the id's seed.
  generics: Vec<String>,
  /// Unresolved `(macro_name, type_name)` from invocation sites.
  pending: Vec<(String, String)>,
}

fn walk_rs_files(dir: &Path, cb: &mut dyn FnMut(&Path)) {
  let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
  for entry in entries {
    let path = entry
      .unwrap_or_else(|e| panic!("cannot read entry in {}: {e}", dir.display()))
      .path();
    if path.is_dir() {
      walk_rs_files(&path, cb);
    } else if path.extension().is_some_and(|e| e == "rs") {
      cb(&path);
    }
  }
}

fn scan_file(path: &Path, scan: &mut ScanResult) {
  let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
  let Ok(file) = parse_file(&src) else {
    panic!("cannot parse {}", path.display());
  };

  struct V<'a> {
    scan: &'a mut ScanResult,
  }

  impl V<'_> {
    fn has_type_id_derive(attrs: &[Attribute]) -> bool {
      attrs.iter().any(|attr| {
        (attr.path().is_ident("derive") || attr.path().is_ident("cfg_attr")) && attr_contains_ident(attr, "TypeId")
      })
    }

    fn record(&mut self, ident: &Ident, generics: &Generics) {
      let bucket = if generics.type_params().next().is_some() {
        &mut self.scan.generics
      } else {
        &mut self.scan.names
      };
      bucket.push(ident.to_string());
    }
  }

  impl<'ast> Visit<'ast> for V<'_> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
      if Self::has_type_id_derive(&node.attrs) {
        self.record(&node.ident, &node.generics);
      }
      visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
      if Self::has_type_id_derive(&node.attrs) {
        self.record(&node.ident, &node.generics);
      }
      visit_item_enum(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
      if let Some(ident) = &node.ident {
        if tokens_contain_ident(&node.mac.tokens, "TypeId") {
          self.scan.type_id_macros.insert(ident.to_string());
        }
      }
      if let Some((macro_name, type_name)) = extract_macro_invocation(node) {
        self.scan.pending.push((macro_name, type_name));
      }
      visit_item_macro(self, node);
    }
  }

  V { scan }.visit_file(&file);
}

/// Checks whether a token stream contains `target`, recursing into groups.
fn tokens_contain_ident(tokens: &TokenStream, target: &str) -> bool {
  tokens.clone().into_iter().any(|tt| match tt {
    TokenTree::Ident(id) => id == target,
    TokenTree::Group(g) => tokens_contain_ident(&g.stream(), target),
    _ => false,
  })
}

/// Checks whether an attribute contains `target` as a top-level ident.
fn attr_contains_ident(attr: &Attribute, target: &str) -> bool {
  attr
    .meta
    .require_list()
    .ok()
    .into_iter()
    .flat_map(|list| list.tokens.clone())
    .any(|tt| matches!(tt, TokenTree::Ident(ref id) if id == target))
}

/// Returns `(macro_name, last_UpperCamelCase_ident)` from an invocation.
fn extract_macro_invocation(node: &ItemMacro) -> Option<(String, String)> {
  let macro_name = node.mac.path.segments.last()?.ident.to_string();

  let mut last = None;
  for tt in node.mac.tokens.clone() {
    if let TokenTree::Ident(id) = &tt {
      let s = id.to_string();
      if s.starts_with(|c: char| c.is_uppercase()) {
        last = Some(s);
      }
    }
  }
  last.map(|name| (macro_name, name))
}
