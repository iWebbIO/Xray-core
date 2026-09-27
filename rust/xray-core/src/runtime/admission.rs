//! Shared final outbound admission for proxy sessions and internal probes.
use anyhow::Result;

use crate::{address::Destination, config::Outbound, protocol::freedom::Admission};

pub(super) async fn admit(
    outbound: &Outbound,
    origin: &str,
    target: &Destination,
) -> Result<Admission> {
    match outbound {
        Outbound::Freedom {
            redirect,
            final_rules,
            ..
        } => {
            final_rules
                .admit(origin, redirect.as_ref().unwrap_or(target))
                .await
        }
        _ => Ok(Admission::Allowed(None)),
    }
}
