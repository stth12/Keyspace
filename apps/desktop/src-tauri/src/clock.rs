use std::time::Instant;

/// A rollback-resistant clock within one process. Persisted state and the OS
/// clock remain controlled by the machine owner; this is not a trust boundary.
pub struct Clock {
    wall: u64,
    started: Instant,
}
impl Clock {
    pub fn new(wall: u64) -> Self {
        Self {
            wall,
            started: Instant::now(),
        }
    }
    pub fn effective(&self, wall: u64, persisted: u64) -> Result<u64, String> {
        checked_time(
            wall,
            persisted,
            self.wall.saturating_add(self.started.elapsed().as_secs()),
        )
    }
}
fn checked_time(wall: u64, persisted: u64, monotonic: u64) -> Result<u64, String> {
    let floor = persisted.max(monotonic);
    if wall.saturating_add(30) < floor {
        return Err("OFFLINE_EXPIRED".into());
    }
    Ok(wall.max(floor))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_rollback_after_restart() {
        assert!(checked_time(900, 1000, 900).is_err());
    }
    #[test]
    fn monotonic_floor_prevents_repeated_small_rollbacks() {
        assert_eq!(checked_time(990, 1000, 1010).unwrap(), 1010);
        assert!(checked_time(990, 1000, 1030).is_err());
    }
}
