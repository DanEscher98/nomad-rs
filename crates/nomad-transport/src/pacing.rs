//! Frame pacing and rate limiting.
//!
//! Implements the frame pacing algorithm from 2-TRANSPORT.md to prevent
//! buffer bloat and network congestion.

use std::time::{Duration, Instant};

/// Frame pacing constants from the protocol specification.
pub mod constants {
    use std::time::Duration;

    /// Minimum time between frames (lower bound).
    /// Actual minimum is max(SRTT/2, 20ms).
    pub const MIN_FRAME_INTERVAL_FLOOR: Duration = Duration::from_millis(20);

    /// Wait after state change before sending (batch rapid changes).
    pub const COLLECTION_INTERVAL: Duration = Duration::from_millis(8);

    /// Maximum time to delay an ack-only frame.
    pub const DELAYED_ACK_TIMEOUT: Duration = Duration::from_millis(100);

    /// Hard cap on frame rate (50 Hz = 20ms between frames).
    pub const MAX_FRAME_RATE_HZ: u32 = 50;

    /// Keepalive interval - send keepalive if no data sent.
    pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

    /// Dead interval - consider connection dead if no frames received.
    pub const DEAD_INTERVAL: Duration = Duration::from_secs(60);

    /// Maximum retransmits before giving up.
    pub const MAX_RETRANSMITS: u32 = 10;

    /// Retransmit backoff multiplier.
    pub const RETRANSMIT_BACKOFF: u32 = 2;
}

/// Reason why a frame should be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendReason {
    /// State has changed and needs to be synchronized.
    StateChange,
    /// Need to acknowledge received data.
    Ack,
    /// Keepalive to prevent timeout.
    Keepalive,
    /// Retransmitting unacknowledged data.
    Retransmit,
}

/// Action the pacer recommends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacerAction {
    /// Send a frame now.
    SendNow,
    /// Wait until the specified instant before sending.
    WaitUntil(Instant),
    /// No action needed (nothing to send).
    Idle,
}

/// Frame pacer that controls when frames can be sent.
///
/// The pacer ensures:
/// - Minimum interval between frames (SRTT/2 or 20ms, whichever is greater)
/// - Collection interval to batch rapid state changes (8ms)
/// - Delayed ACK to piggyback on data frames (100ms max)
/// - Frame rate cap at 50 Hz
#[derive(Debug, Clone)]
pub struct FramePacer {
    /// When we last sent a frame.
    last_frame_sent: Option<Instant>,
    /// When a state change occurred that needs to be sent.
    state_change_time: Option<Instant>,
    /// When an ACK became pending.
    ack_pending_since: Option<Instant>,
    /// Whether we have pending data to send (not just ACK).
    data_pending: bool,
    /// Current smoothed RTT in milliseconds (from RTT estimator).
    srtt_ms: f64,
}

impl Default for FramePacer {
    fn default() -> Self {
        Self::new()
    }
}

impl FramePacer {
    /// Create a new frame pacer.
    pub fn new() -> Self {
        Self {
            last_frame_sent: None,
            state_change_time: None,
            ack_pending_since: None,
            data_pending: false,
            srtt_ms: 0.0,
        }
    }

    /// Update the SRTT from the RTT estimator.
    pub fn set_srtt(&mut self, srtt: Duration) {
        self.srtt_ms = srtt.as_secs_f64() * 1000.0;
    }

    /// Notify the pacer that local state has changed.
    pub fn on_state_change(&mut self) {
        if self.state_change_time.is_none() {
            self.state_change_time = Some(Instant::now());
        }
        self.data_pending = true;
    }

    /// Notify the pacer that we received a frame and should send an ACK.
    pub fn on_ack_needed(&mut self) {
        if self.ack_pending_since.is_none() {
            self.ack_pending_since = Some(Instant::now());
        }
    }

    /// Notify the pacer that a frame was sent.
    pub fn on_frame_sent(&mut self) {
        self.last_frame_sent = Some(Instant::now());
        self.state_change_time = None;
        self.ack_pending_since = None;
        self.data_pending = false;
    }

    /// Clear pending state (e.g., after receiving ACK).
    pub fn clear_pending(&mut self) {
        self.data_pending = false;
        self.state_change_time = None;
    }

    /// Calculate the minimum frame interval based on SRTT.
    fn min_frame_interval(&self) -> Duration {
        let srtt_half_ms = self.srtt_ms / 2.0;
        let floor_ms = constants::MIN_FRAME_INTERVAL_FLOOR.as_millis() as f64;
        let interval_ms = f64::max(srtt_half_ms, floor_ms);

        // Also respect the hard frame rate cap
        let max_interval_ms = 1000.0 / constants::MAX_FRAME_RATE_HZ as f64;
        let interval_ms = f64::max(interval_ms, max_interval_ms);

        Duration::from_secs_f64(interval_ms / 1000.0)
    }

    /// Determine what action to take based on current state.
    pub fn poll(&self) -> PacerAction {
        let now = Instant::now();

        // Check if we need to send anything at all
        let needs_send = self.data_pending || self.ack_pending_since.is_some();
        if !needs_send {
            return PacerAction::Idle;
        }

        // Check minimum frame interval
        if let Some(last_sent) = self.last_frame_sent {
            let min_interval = self.min_frame_interval();
            let next_allowed = last_sent + min_interval;
            if now < next_allowed {
                return PacerAction::WaitUntil(next_allowed);
            }
        }

        // Check collection interval for state changes
        if let Some(state_time) = self.state_change_time {
            let collection_end = state_time + constants::COLLECTION_INTERVAL;
            if now < collection_end && self.ack_pending_since.is_none() {
                // Wait for collection interval, unless we have an ACK to send
                return PacerAction::WaitUntil(collection_end);
            }
        }

        // Check delayed ACK timeout
        if !self.data_pending
            && let Some(ack_time) = self.ack_pending_since
        {
            let ack_deadline = ack_time + constants::DELAYED_ACK_TIMEOUT;
            if now < ack_deadline {
                // Still within delayed ACK window, wait for data
                return PacerAction::WaitUntil(ack_deadline);
            }
        }

        // All checks passed, send now
        PacerAction::SendNow
    }

    /// Check if we should send a keepalive.
    pub fn needs_keepalive(&self, last_received: Instant) -> bool {
        if let Some(last_sent) = self.last_frame_sent {
            let now = Instant::now();
            let since_sent = now.duration_since(last_sent);
            let since_received = now.duration_since(last_received);

            // Send keepalive if we haven't sent anything recently
            // and the connection is still alive
            since_sent >= constants::KEEPALIVE_INTERVAL
                && since_received < constants::DEAD_INTERVAL
        } else {
            false
        }
    }

    /// Check if the connection should be considered dead.
    pub fn is_connection_dead(&self, last_received: Instant) -> bool {
        Instant::now().duration_since(last_received) >= constants::DEAD_INTERVAL
    }
}

/// Retransmission controller.
///
/// Tracks retransmission state and applies exponential backoff.
#[derive(Debug, Clone)]
pub struct RetransmitController {
    /// Number of retransmits for current data.
    retransmit_count: u32,
    /// Last retransmit time.
    last_retransmit: Option<Instant>,
    /// Current timeout (after backoff).
    current_timeout: Duration,
    /// Base RTO from RTT estimator.
    base_rto: Duration,
}

impl RetransmitController {
    /// Create a new retransmit controller.
    pub fn new(initial_rto: Duration) -> Self {
        Self {
            retransmit_count: 0,
            last_retransmit: None,
            current_timeout: initial_rto,
            base_rto: initial_rto,
        }
    }

    /// Update the base RTO from RTT estimator.
    pub fn set_rto(&mut self, rto: Duration) {
        self.base_rto = rto;
        // Only update current_timeout if we're not in backoff
        if self.retransmit_count == 0 {
            self.current_timeout = rto;
        }
    }

    /// Check if we should retransmit now.
    pub fn should_retransmit(&self, unacked_data: bool) -> bool {
        if !unacked_data {
            return false;
        }

        if self.retransmit_count >= constants::MAX_RETRANSMITS {
            return false; // Give up
        }

        match self.last_retransmit {
            Some(last) => Instant::now().duration_since(last) >= self.current_timeout,
            None => true, // First transmission
        }
    }

    /// Record that we're retransmitting.
    pub fn on_retransmit(&mut self) {
        self.retransmit_count += 1;
        self.last_retransmit = Some(Instant::now());

        // Exponential backoff
        let new_timeout = self.current_timeout * constants::RETRANSMIT_BACKOFF;
        self.current_timeout = new_timeout.min(crate::timing::constants::MAX_RTO);
    }

    /// Reset after successful acknowledgment.
    pub fn on_ack(&mut self) {
        self.retransmit_count = 0;
        self.last_retransmit = None;
        self.current_timeout = self.base_rto;
    }

    /// Get the current retransmit count.
    pub fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    /// Check if we've exceeded max retransmits.
    pub fn is_failed(&self) -> bool {
        self.retransmit_count >= constants::MAX_RETRANSMITS
    }

    /// Get time until next retransmit is allowed.
    pub fn time_until_retransmit(&self) -> Option<Duration> {
        self.last_retransmit.map(|last| {
            let elapsed = Instant::now().duration_since(last);
            self.current_timeout.saturating_sub(elapsed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pacer_initial_state() {
        let pacer = FramePacer::new();
        assert_eq!(pacer.poll(), PacerAction::Idle);
    }

    #[test]
    fn test_pacer_state_change() {
        let mut pacer = FramePacer::new();
        pacer.on_state_change();

        // Should wait for collection interval
        match pacer.poll() {
            PacerAction::WaitUntil(_) => {}
            other => panic!("Expected WaitUntil, got {:?}", other),
        }

        // After collection interval, should send
        std::thread::sleep(constants::COLLECTION_INTERVAL + Duration::from_millis(1));
        assert_eq!(pacer.poll(), PacerAction::SendNow);
    }

    #[test]
    fn test_pacer_ack_only() {
        let mut pacer = FramePacer::new();
        pacer.on_ack_needed();

        // ACK-only should wait for delayed ACK timeout
        match pacer.poll() {
            PacerAction::WaitUntil(_) => {}
            other => panic!("Expected WaitUntil, got {:?}", other),
        }
    }

    #[test]
    fn test_pacer_ack_with_data() {
        let mut pacer = FramePacer::new();
        pacer.on_ack_needed();
        pacer.on_state_change();

        // With data pending, should send after collection interval (not delayed ACK)
        std::thread::sleep(constants::COLLECTION_INTERVAL + Duration::from_millis(1));
        assert_eq!(pacer.poll(), PacerAction::SendNow);
    }

    #[test]
    fn test_pacer_min_interval() {
        let mut pacer = FramePacer::new();
        pacer.set_srtt(Duration::from_millis(100)); // 100ms SRTT

        // Min interval should be SRTT/2 = 50ms (greater than 20ms floor)
        let min_interval = pacer.min_frame_interval();
        assert!(min_interval >= Duration::from_millis(50));
    }

    #[test]
    fn test_pacer_frame_sent_clears_state() {
        let mut pacer = FramePacer::new();
        pacer.on_state_change();
        pacer.on_ack_needed();

        pacer.on_frame_sent();

        // After sending, should be idle
        assert_eq!(pacer.poll(), PacerAction::Idle);
    }

    #[test]
    fn test_retransmit_controller() {
        let mut controller = RetransmitController::new(Duration::from_millis(100));

        // Should retransmit immediately for unacked data
        assert!(controller.should_retransmit(true));
        assert!(!controller.should_retransmit(false));

        // After retransmit, should wait
        controller.on_retransmit();
        assert!(!controller.should_retransmit(true)); // Need to wait for timeout

        // After ACK, should reset
        controller.on_ack();
        assert_eq!(controller.retransmit_count(), 0);
    }

    #[test]
    fn test_retransmit_max_attempts() {
        let mut controller = RetransmitController::new(Duration::from_millis(1));

        for _ in 0..constants::MAX_RETRANSMITS {
            controller.on_retransmit();
        }

        assert!(controller.is_failed());
        assert!(!controller.should_retransmit(true));
    }

    #[test]
    fn test_keepalive_check() {
        let pacer = FramePacer::new();

        // No frames sent yet, no keepalive needed
        assert!(!pacer.needs_keepalive(Instant::now()));
    }

    #[test]
    fn test_connection_dead() {
        let pacer = FramePacer::new();

        // Recent activity, not dead
        assert!(!pacer.is_connection_dead(Instant::now()));

        // Very old activity would be dead
        // (Can't easily test without mocking time)
    }
}
