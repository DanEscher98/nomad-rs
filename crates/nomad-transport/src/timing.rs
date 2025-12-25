//! RTT estimation and timing utilities.
//!
//! Implements RFC 6298 RTT estimation algorithm as specified in 2-TRANSPORT.md.

use std::time::{Duration, Instant};

/// RTT timing constants from the protocol specification.
pub mod constants {
    use std::time::Duration;

    /// Initial retransmission timeout before first RTT sample.
    pub const INITIAL_RTO: Duration = Duration::from_millis(1000);

    /// Minimum retransmission timeout.
    pub const MIN_RTO: Duration = Duration::from_millis(100);

    /// Maximum retransmission timeout.
    pub const MAX_RTO: Duration = Duration::from_millis(60000);

    /// Alpha for SRTT smoothing (0.125 = 1/8).
    pub const SRTT_ALPHA: f64 = 0.125;

    /// Beta for RTTVAR smoothing (0.25 = 1/4).
    pub const RTTVAR_BETA: f64 = 0.25;

    /// K multiplier for RTO calculation (4.0 per RFC 6298).
    pub const RTO_K: f64 = 4.0;

    /// Minimum RTT granularity for RTO calculation.
    pub const MIN_RTO_GRANULARITY_MS: f64 = 100.0;
}

/// RTT estimator implementing RFC 6298.
///
/// This struct maintains smoothed RTT (SRTT) and RTT variance (RTTVAR) values,
/// and computes an adaptive Retransmission Timeout (RTO).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT in milliseconds.
    srtt: f64,
    /// RTT variance in milliseconds.
    rttvar: f64,
    /// Current retransmission timeout.
    rto: Duration,
    /// Whether we've received the first RTT sample.
    initialized: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Create a new RTT estimator with initial values.
    pub fn new() -> Self {
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            rto: constants::INITIAL_RTO,
            initialized: false,
        }
    }

    /// Update RTT estimate with a new sample.
    ///
    /// Implements RFC 6298 RTT calculation:
    /// - First measurement: SRTT = sample, RTTVAR = sample / 2
    /// - Subsequent: RTTVAR = 0.75 * RTTVAR + 0.25 * |SRTT - sample|
    /// - SRTT = 0.875 * SRTT + 0.125 * sample
    pub fn update(&mut self, sample: Duration) {
        let sample_ms = sample.as_secs_f64() * 1000.0;

        if !self.initialized {
            // First measurement
            self.srtt = sample_ms;
            self.rttvar = sample_ms / 2.0;
            self.initialized = true;
        } else {
            // Subsequent measurements (RFC 6298 algorithm)
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
            self.rttvar = (1.0 - constants::RTTVAR_BETA) * self.rttvar
                + constants::RTTVAR_BETA * (self.srtt - sample_ms).abs();
            // SRTT = (1 - alpha) * SRTT + alpha * R
            self.srtt =
                (1.0 - constants::SRTT_ALPHA) * self.srtt + constants::SRTT_ALPHA * sample_ms;
        }

        // RTO = SRTT + max(G, K * RTTVAR)
        // where G is the clock granularity (we use 100ms minimum)
        let rto_ms =
            self.srtt + f64::max(constants::MIN_RTO_GRANULARITY_MS, constants::RTO_K * self.rttvar);

        // Clamp to [MIN_RTO, MAX_RTO]
        let rto_ms = rto_ms.clamp(
            constants::MIN_RTO.as_millis() as f64,
            constants::MAX_RTO.as_millis() as f64,
        );

        self.rto = Duration::from_millis(rto_ms as u64);
    }

    /// Get the current smoothed RTT.
    pub fn srtt(&self) -> Duration {
        Duration::from_secs_f64(self.srtt / 1000.0)
    }

    /// Get the current smoothed RTT in milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.srtt
    }

    /// Get the current RTT variance.
    pub fn rttvar(&self) -> Duration {
        Duration::from_secs_f64(self.rttvar / 1000.0)
    }

    /// Get the current retransmission timeout.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Check if the estimator has been initialized with at least one sample.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Apply exponential backoff to RTO (used after timeout).
    ///
    /// Returns the new RTO after doubling (capped at MAX_RTO).
    pub fn backoff(&mut self) -> Duration {
        let new_rto_ms = (self.rto.as_millis() as u64).saturating_mul(2);
        self.rto = Duration::from_millis(new_rto_ms).min(constants::MAX_RTO);
        self.rto
    }

    /// Reset RTO to initial value (e.g., after successful transmission).
    pub fn reset_backoff(&mut self) {
        if self.initialized {
            // Recalculate RTO from current SRTT/RTTVAR
            let rto_ms = self.srtt
                + f64::max(constants::MIN_RTO_GRANULARITY_MS, constants::RTO_K * self.rttvar);
            let rto_ms = rto_ms.clamp(
                constants::MIN_RTO.as_millis() as f64,
                constants::MAX_RTO.as_millis() as f64,
            );
            self.rto = Duration::from_millis(rto_ms as u64);
        } else {
            self.rto = constants::INITIAL_RTO;
        }
    }
}

/// Timestamp tracker for RTT measurement via timestamp echo.
///
/// Each frame carries a timestamp and echoes the peer's timestamp.
/// When we receive an echo of our timestamp, we can compute RTT.
#[derive(Debug, Clone)]
pub struct TimestampTracker {
    /// Session start time (all timestamps are relative to this).
    session_start: Instant,
    /// Most recent timestamp we received from peer (for echoing).
    last_peer_timestamp: u32,
    /// Our timestamp that we're waiting to be echoed.
    pending_timestamp: Option<u32>,
    /// When we sent the frame with pending_timestamp.
    pending_send_time: Option<Instant>,
}

impl TimestampTracker {
    /// Create a new timestamp tracker.
    pub fn new() -> Self {
        Self {
            session_start: Instant::now(),
            last_peer_timestamp: 0,
            pending_timestamp: None,
            pending_send_time: None,
        }
    }

    /// Create a timestamp tracker with a specific start time.
    pub fn with_start(start: Instant) -> Self {
        Self {
            session_start: start,
            last_peer_timestamp: 0,
            pending_timestamp: None,
            pending_send_time: None,
        }
    }

    /// Get the current timestamp (ms since session start).
    pub fn now(&self) -> u32 {
        self.session_start.elapsed().as_millis() as u32
    }

    /// Get the timestamp echo value (peer's last timestamp).
    pub fn timestamp_echo(&self) -> u32 {
        self.last_peer_timestamp
    }

    /// Record that we're sending a frame with the given timestamp.
    pub fn on_send(&mut self, timestamp: u32) {
        self.pending_timestamp = Some(timestamp);
        self.pending_send_time = Some(Instant::now());
    }

    /// Process a received frame's timestamps.
    ///
    /// Returns an RTT sample if the echo matches our pending timestamp.
    pub fn on_receive(&mut self, peer_timestamp: u32, echo: u32) -> Option<Duration> {
        // Update the timestamp we'll echo back
        self.last_peer_timestamp = peer_timestamp;

        // Check if this echoes our pending timestamp
        if let (Some(pending), Some(send_time)) = (self.pending_timestamp, self.pending_send_time)
            && echo == pending
        {
            let rtt = send_time.elapsed();
            self.pending_timestamp = None;
            self.pending_send_time = None;
            return Some(rtt);
        }

        None
    }

    /// Clear the pending timestamp (e.g., on retransmission).
    pub fn clear_pending(&mut self) {
        self.pending_timestamp = None;
        self.pending_send_time = None;
    }
}

impl Default for TimestampTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_estimator_initial() {
        let estimator = RttEstimator::new();
        assert!(!estimator.is_initialized());
        assert_eq!(estimator.rto(), constants::INITIAL_RTO);
    }

    #[test]
    fn test_rtt_estimator_first_sample() {
        let mut estimator = RttEstimator::new();
        estimator.update(Duration::from_millis(100));

        assert!(estimator.is_initialized());
        assert!((estimator.srtt_ms() - 100.0).abs() < 0.01);
        assert!((estimator.rttvar - 50.0).abs() < 0.01); // sample / 2
    }

    #[test]
    fn test_rtt_estimator_multiple_samples() {
        let mut estimator = RttEstimator::new();

        // First sample: 100ms
        estimator.update(Duration::from_millis(100));
        let srtt1 = estimator.srtt_ms();

        // Second sample: 120ms
        estimator.update(Duration::from_millis(120));
        let srtt2 = estimator.srtt_ms();

        // SRTT should move toward the new sample
        assert!(srtt2 > srtt1);
        assert!(srtt2 < 120.0);
    }

    #[test]
    fn test_rtt_estimator_backoff() {
        let mut estimator = RttEstimator::new();
        estimator.update(Duration::from_millis(100));

        let rto1 = estimator.rto();
        let rto2 = estimator.backoff();

        // RTO should double
        assert!(rto2 > rto1);
        assert!(rto2 <= constants::MAX_RTO);
    }

    #[test]
    fn test_rtt_estimator_max_rto() {
        let mut estimator = RttEstimator::new();
        estimator.update(Duration::from_millis(100));

        // Keep backing off until we hit max
        for _ in 0..20 {
            estimator.backoff();
        }

        assert_eq!(estimator.rto(), constants::MAX_RTO);
    }

    #[test]
    fn test_rtt_estimator_min_rto() {
        let mut estimator = RttEstimator::new();

        // Very small RTT sample
        estimator.update(Duration::from_micros(100));

        // RTO should still be at least MIN_RTO
        assert!(estimator.rto() >= constants::MIN_RTO);
    }

    #[test]
    fn test_timestamp_tracker_echo() {
        let start = Instant::now();
        let mut tracker = TimestampTracker::with_start(start);

        // Send a frame
        tracker.on_send(1000);

        // Receive a frame with echo of our timestamp
        std::thread::sleep(Duration::from_millis(10));
        let rtt = tracker.on_receive(2000, 1000);

        assert!(rtt.is_some());
        let rtt = rtt.unwrap();
        assert!(rtt >= Duration::from_millis(10));
    }

    #[test]
    fn test_timestamp_tracker_no_match() {
        let start = Instant::now();
        let mut tracker = TimestampTracker::with_start(start);

        // Send a frame
        tracker.on_send(1000);

        // Receive a frame with different echo (not our timestamp)
        let rtt = tracker.on_receive(2000, 999);

        assert!(rtt.is_none());
        // Pending timestamp should still be waiting
        assert!(tracker.pending_timestamp.is_some());
    }

    #[test]
    fn test_timestamp_tracker_peer_timestamp() {
        let mut tracker = TimestampTracker::new();

        // Initially no peer timestamp
        assert_eq!(tracker.timestamp_echo(), 0);

        // Receive frame from peer
        tracker.on_receive(5000, 0);

        // Now we have peer's timestamp to echo
        assert_eq!(tracker.timestamp_echo(), 5000);
    }
}
