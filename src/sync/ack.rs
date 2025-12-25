//! Acknowledgment tracking
//!
//! Tracks which versions have been acknowledged and manages retransmission.

use std::time::{Duration, Instant};

/// Tracks pending acknowledgments for a message
#[derive(Debug, Clone)]
pub struct PendingAck {
    /// Version that needs acknowledgment
    pub version: u64,
    /// Time when the message was sent
    pub sent_at: Instant,
    /// Number of retransmissions
    pub retransmit_count: u32,
    /// Current retransmission timeout
    pub rto: Duration,
}

impl PendingAck {
    /// Create a new pending ack
    pub fn new(version: u64, rto: Duration) -> Self {
        Self {
            version,
            sent_at: Instant::now(),
            retransmit_count: 0,
            rto,
        }
    }

    /// Check if retransmission is needed
    pub fn needs_retransmit(&self) -> bool {
        self.sent_at.elapsed() >= self.rto
    }

    /// Mark as retransmitted with updated timeout
    pub fn retransmit(&mut self, backoff_multiplier: u32, max_rto: Duration) {
        self.sent_at = Instant::now();
        self.retransmit_count += 1;
        // Exponential backoff
        self.rto = (self.rto * backoff_multiplier).min(max_rto);
    }

    /// Time until retransmission is needed
    pub fn time_until_retransmit(&self) -> Duration {
        let elapsed = self.sent_at.elapsed();
        if elapsed >= self.rto {
            Duration::ZERO
        } else {
            self.rto - elapsed
        }
    }
}

/// Default initial retransmission timeout (1 second).
pub const DEFAULT_INITIAL_RTO: Duration = Duration::from_millis(1000);

/// Default minimum retransmission timeout (100ms).
/// Prevents RTO from becoming too aggressive on low-latency networks.
pub const DEFAULT_MIN_RTO: Duration = Duration::from_millis(100);

/// Default maximum retransmission timeout (60 seconds).
/// Caps RTO growth during sustained packet loss.
pub const DEFAULT_MAX_RTO: Duration = Duration::from_secs(60);

/// Default exponential backoff multiplier for RTO (2x).
/// Applied after each retransmission timeout.
pub const DEFAULT_BACKOFF_MULTIPLIER: u32 = 2;

/// Default maximum number of retransmission attempts (10).
/// After this many failures, the sync is considered failed.
pub const DEFAULT_MAX_RETRANSMITS: u32 = 10;

/// Acknowledgment tracker
///
/// Tracks pending acknowledgments and manages retransmission logic.
#[derive(Debug)]
pub struct AckTracker {
    /// Currently pending acknowledgments (version -> pending ack)
    pending: Vec<PendingAck>,

    /// Highest version acknowledged by peer
    highest_acked: u64,

    /// RTO configuration
    initial_rto: Duration,
    min_rto: Duration,
    max_rto: Duration,
    backoff_multiplier: u32,
    max_retransmits: u32,

    /// Smoothed RTT and RTT variance (RFC 6298)
    srtt: Option<Duration>,
    rttvar: Option<Duration>,
}

impl AckTracker {
    /// Create a new ack tracker with default settings
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            highest_acked: 0,
            initial_rto: DEFAULT_INITIAL_RTO,
            min_rto: DEFAULT_MIN_RTO,
            max_rto: DEFAULT_MAX_RTO,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            max_retransmits: DEFAULT_MAX_RETRANSMITS,
            srtt: None,
            rttvar: None,
        }
    }

    /// Create with custom RTO settings
    pub fn with_rto(
        initial_rto: Duration,
        min_rto: Duration,
        max_rto: Duration,
        backoff_multiplier: u32,
        max_retransmits: u32,
    ) -> Self {
        Self {
            pending: Vec::new(),
            highest_acked: 0,
            initial_rto,
            min_rto,
            max_rto,
            backoff_multiplier,
            max_retransmits,
            srtt: None,
            rttvar: None,
        }
    }

    /// Register a sent message that needs acknowledgment
    pub fn register_sent(&mut self, version: u64) {
        // Don't register if already pending
        if self.pending.iter().any(|p| p.version == version) {
            return;
        }

        let rto = self.current_rto();
        self.pending.push(PendingAck::new(version, rto));
    }

    /// Process an incoming acknowledgment
    ///
    /// Returns the RTT sample if this ack is for a pending message.
    pub fn process_ack(&mut self, acked_version: u64) -> Option<Duration> {
        if acked_version <= self.highest_acked {
            return None;
        }

        self.highest_acked = acked_version;

        // Find and remove all pending acks up to this version
        let mut rtt_sample = None;

        self.pending.retain(|pending| {
            if pending.version <= acked_version {
                // Only use as RTT sample if not retransmitted
                if pending.retransmit_count == 0 && rtt_sample.is_none() {
                    rtt_sample = Some(pending.sent_at.elapsed());
                }
                false // Remove from pending
            } else {
                true // Keep in pending
            }
        });

        // Update RTT estimates if we got a sample
        if let Some(rtt) = rtt_sample {
            self.update_rtt(rtt);
        }

        rtt_sample
    }

    /// Update RTT estimates using RFC 6298 algorithm
    fn update_rtt(&mut self, rtt: Duration) {
        let rtt_secs = rtt.as_secs_f64();

        match (self.srtt, self.rttvar) {
            (None, None) => {
                // First measurement
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                // Subsequent measurements
                let srtt_secs = srtt.as_secs_f64();
                let rttvar_secs = rttvar.as_secs_f64();

                // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
                // where beta = 1/4
                let new_rttvar =
                    0.75 * rttvar_secs + 0.25 * (srtt_secs - rtt_secs).abs();

                // SRTT = (1 - alpha) * SRTT + alpha * R'
                // where alpha = 1/8
                let new_srtt = 0.875 * srtt_secs + 0.125 * rtt_secs;

                self.srtt = Some(Duration::from_secs_f64(new_srtt));
                self.rttvar = Some(Duration::from_secs_f64(new_rttvar));
            }
            _ => {}
        }
    }

    /// Get current RTO based on RTT estimates
    pub fn current_rto(&self) -> Duration {
        match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                // RTO = SRTT + max(G, K*RTTVAR) where K=4, G=clock granularity
                // We use 1ms as clock granularity
                let k = 4;
                let g = Duration::from_millis(1);
                let rto = srtt + (g.max(rttvar * k));
                rto.clamp(self.min_rto, self.max_rto)
            }
            _ => self.initial_rto,
        }
    }

    /// Get the smoothed RTT if available
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Get the RTT variance if available
    pub fn rttvar(&self) -> Option<Duration> {
        self.rttvar
    }

    /// Get pending acks that need retransmission
    pub fn needs_retransmit(&self) -> impl Iterator<Item = u64> + '_ {
        self.pending
            .iter()
            .filter(|p| p.needs_retransmit() && p.retransmit_count < self.max_retransmits)
            .map(|p| p.version)
    }

    /// Get versions that have exceeded max retransmits
    pub fn failed_versions(&self) -> impl Iterator<Item = u64> + '_ {
        self.pending
            .iter()
            .filter(|p| p.retransmit_count >= self.max_retransmits)
            .map(|p| p.version)
    }

    /// Mark a version as retransmitted
    pub fn mark_retransmitted(&mut self, version: u64) {
        if let Some(pending) = self.pending.iter_mut().find(|p| p.version == version) {
            pending.retransmit(self.backoff_multiplier, self.max_rto);
        }
    }

    /// Check if there are pending acknowledgments
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get number of pending acknowledgments
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get highest acknowledged version
    pub fn highest_acked(&self) -> u64 {
        self.highest_acked
    }

    /// Get time until next retransmission is needed
    pub fn time_until_retransmit(&self) -> Option<Duration> {
        self.pending
            .iter()
            .filter(|p| p.retransmit_count < self.max_retransmits)
            .map(|p| p.time_until_retransmit())
            .min()
    }

    /// Cancel a pending ack (e.g., on connection close)
    pub fn cancel(&mut self, version: u64) {
        self.pending.retain(|p| p.version != version);
    }

    /// Cancel all pending acks
    pub fn cancel_all(&mut self) {
        self.pending.clear();
    }

    /// Reset tracker state
    pub fn reset(&mut self) {
        self.pending.clear();
        self.highest_acked = 0;
        self.srtt = None;
        self.rttvar = None;
    }
}

impl Default for AckTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_tracker() {
        let tracker = AckTracker::new();
        assert!(!tracker.has_pending());
        assert_eq!(tracker.highest_acked(), 0);
        assert_eq!(tracker.current_rto(), DEFAULT_INITIAL_RTO);
    }

    #[test]
    fn test_register_sent() {
        let mut tracker = AckTracker::new();

        tracker.register_sent(1);
        assert!(tracker.has_pending());
        assert_eq!(tracker.pending_count(), 1);

        // Duplicate registration should not add another
        tracker.register_sent(1);
        assert_eq!(tracker.pending_count(), 1);

        tracker.register_sent(2);
        assert_eq!(tracker.pending_count(), 2);
    }

    #[test]
    fn test_process_ack() {
        let mut tracker = AckTracker::new();

        tracker.register_sent(1);
        tracker.register_sent(2);
        tracker.register_sent(3);

        // Ack version 2 should clear 1 and 2
        tracker.process_ack(2);
        assert_eq!(tracker.highest_acked(), 2);
        assert_eq!(tracker.pending_count(), 1); // Only version 3 remains

        // Lower ack should be ignored
        tracker.process_ack(1);
        assert_eq!(tracker.highest_acked(), 2);
    }

    #[test]
    fn test_rtt_sample() {
        let mut tracker = AckTracker::new();

        tracker.register_sent(1);
        thread::sleep(Duration::from_millis(10));

        let rtt = tracker.process_ack(1);
        assert!(rtt.is_some());
        assert!(rtt.unwrap() >= Duration::from_millis(10));

        // After first sample, we should have RTT estimates
        assert!(tracker.srtt().is_some());
        assert!(tracker.rttvar().is_some());
    }

    #[test]
    fn test_retransmit() {
        let mut tracker = AckTracker::with_rto(
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_secs(1),
            2,
            3,
        );

        tracker.register_sent(1);

        // Initially should not need retransmit
        assert_eq!(tracker.needs_retransmit().count(), 0);

        // Wait for RTO
        thread::sleep(Duration::from_millis(15));

        // Now should need retransmit
        let versions: Vec<_> = tracker.needs_retransmit().collect();
        assert_eq!(versions, vec![1]);

        // Mark as retransmitted
        tracker.mark_retransmitted(1);

        // Should not immediately need retransmit again
        assert_eq!(tracker.needs_retransmit().count(), 0);
    }

    #[test]
    fn test_max_retransmits() {
        let mut tracker = AckTracker::with_rto(
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(10),
            1, // No backoff
            2, // Max 2 retransmits
        );

        tracker.register_sent(1);
        thread::sleep(Duration::from_millis(5));

        // First retransmit
        tracker.mark_retransmitted(1);
        thread::sleep(Duration::from_millis(5));

        // Second retransmit
        tracker.mark_retransmitted(1);
        thread::sleep(Duration::from_millis(5));

        // Should now be in failed state
        let failed: Vec<_> = tracker.failed_versions().collect();
        assert_eq!(failed, vec![1]);

        // Should not show up in needs_retransmit
        assert_eq!(tracker.needs_retransmit().count(), 0);
    }

    #[test]
    fn test_cancel() {
        let mut tracker = AckTracker::new();

        tracker.register_sent(1);
        tracker.register_sent(2);
        tracker.register_sent(3);

        tracker.cancel(2);
        assert_eq!(tracker.pending_count(), 2);

        tracker.cancel_all();
        assert!(!tracker.has_pending());
    }

    #[test]
    fn test_reset() {
        let mut tracker = AckTracker::new();

        tracker.register_sent(1);
        tracker.process_ack(1);

        tracker.reset();

        assert!(!tracker.has_pending());
        assert_eq!(tracker.highest_acked(), 0);
        assert!(tracker.srtt().is_none());
    }

    #[test]
    fn test_time_until_retransmit() {
        let mut tracker = AckTracker::with_rto(
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_secs(1),
            2,
            10,
        );

        assert!(tracker.time_until_retransmit().is_none());

        tracker.register_sent(1);
        let time = tracker.time_until_retransmit();
        assert!(time.is_some());
        assert!(time.unwrap() <= Duration::from_millis(100));
    }
}
