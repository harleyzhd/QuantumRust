use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::CpgError;
use crate::model::Cpg;

pub trait MirProvider {
    fn extract(&self, crate_root: &Path) -> Result<Cpg, CpgError>;
}

pub trait LlvmProvider {
    fn extract(&self, crate_root: &Path) -> Result<Cpg, CpgError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallGraph {
    pub edges: Vec<(u32, u32)>,
}

pub trait CallGraphProvider {
    fn build(&self, cpg: &Cpg) -> Result<CallGraph, CpgError>;
    fn name(&self) -> &'static str;
}

pub trait GraphStore {
    fn put(&mut self, cpg: &Cpg) -> Result<(), CpgError>;
    fn get(&self) -> Result<Cpg, CpgError>;
}
