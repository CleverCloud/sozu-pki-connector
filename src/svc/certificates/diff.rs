//! # Diff module
//!
//! This module provides a structure and helpers to make a diff between certificates

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    path::PathBuf,
};

use crate::svc::certificates::Metadata;

// -------------------------------------------------------------------------------------
// Diff

#[derive(Debug, Clone)]
pub struct Diff<T>
where
    T: PartialEq + Eq + Debug + Clone,
{
    pub added: HashSet<T>,
    pub deleted: HashSet<T>,
    pub modified: HashSet<T>,
}

impl<T> Diff<T>
where
    T: PartialEq + Eq + Debug + Clone,
{
    pub fn new(added: HashSet<T>, modified: HashSet<T>, deleted: HashSet<T>) -> Diff<T> {
        Self {
            added,
            modified,
            deleted,
        }
    }
}

// -------------------------------------------------------------------------------------
// Helpers

#[tracing::instrument(skip_all)]
pub fn create(
    current: &HashMap<PathBuf, Metadata>,
    new: &HashMap<PathBuf, Metadata>,
) -> Diff<PathBuf> {
    let current_keys: HashSet<&PathBuf> = current.keys().collect();
    let new_keys: HashSet<&PathBuf> = new.keys().collect();

    let deleted_keys: HashSet<PathBuf> = current_keys
        .difference(&new_keys)
        .map(|path| path.to_path_buf())
        .collect();

    let added_keys: HashSet<PathBuf> = new_keys
        .difference(&current_keys)
        .map(|path| path.to_path_buf())
        .collect();

    let modified_keys: HashSet<PathBuf> = current_keys
        .intersection(&new_keys)
        .filter(|path| current.get(**path) != new.get(**path))
        .map(|path| path.to_path_buf())
        .collect();

    Diff::new(added_keys, modified_keys, deleted_keys)
}
