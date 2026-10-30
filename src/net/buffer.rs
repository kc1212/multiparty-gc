//! Allocation accounting shared by queued and in-flight frames.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::{NetError, PartyId};

/// Charge even empty frames for queue entries and the per-stream index. This is
/// deliberately conservative; the limit is an accounting budget, not an allocator measurement.
pub(crate) const FRAME_OVERHEAD: usize = 1024;

pub(crate) struct BufferBudget {
    peer: PartyId,
    limit: usize,
    used: AtomicUsize,
}

impl BufferBudget {
    pub(crate) fn new(peer: PartyId, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            peer,
            limit,
            used: AtomicUsize::new(0),
        })
    }

    fn charge(&self, bytes: usize) -> Result<(), NetError> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .map(|_| ())
            .map_err(|_| NetError::BufferLimit(self.peer))
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        payload_capacity: usize,
    ) -> Result<BufferPermit, NetError> {
        let cost = payload_capacity
            .checked_add(FRAME_OVERHEAD)
            .ok_or(NetError::BufferLimit(self.peer))?;
        self.charge(cost)?;
        Ok(BufferPermit {
            budget: self.clone(),
            cost,
        })
    }
}

/// Owns a reservation until a frame leaves the transport, including on cancellation.
pub(crate) struct BufferPermit {
    budget: Arc<BufferBudget>,
    cost: usize,
}

impl BufferPermit {
    pub(crate) fn cover_capacity(&mut self, capacity: usize) -> Result<(), NetError> {
        let cost = capacity
            .checked_add(FRAME_OVERHEAD)
            .ok_or(NetError::BufferLimit(self.budget.peer))?;
        if cost > self.cost {
            self.budget.charge(cost - self.cost)?;
            self.cost = cost;
        }
        Ok(())
    }
}

impl Drop for BufferPermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.cost, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_bound_pending_writes_and_recover_after_drop() {
        let budget = BufferBudget::new(3, FRAME_OVERHEAD + 8);
        let permit = budget.reserve(8).unwrap();
        assert!(matches!(budget.reserve(0), Err(NetError::BufferLimit(3))));
        drop(permit);
        assert!(budget.reserve(8).is_ok());
        assert!(budget.reserve(usize::MAX).is_err());
    }
}
