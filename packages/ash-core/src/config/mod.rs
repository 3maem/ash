//! ASH Configuration Module.
//!
//! Server-side configuration for ASH protocol.

mod scope_policies;

pub use scope_policies::{
    register_scope_policy,
    register_scope_policies,
    get_scope_policy,
    has_scope_policy,
    get_all_scope_policies,
    clear_scope_policies,
};
