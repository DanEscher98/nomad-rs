//! Sender-side sync logic
//!
//! Manages outbound sync messages with pacing and batching.

use std::time::{Duration, Instant};

use super::message::SyncMessage;

/// Default collection interval for batching rapid state changes
pub const DEFAULT_COLLECTION_INTERVAL: Duration = Duration::from_millis(8);

/// Default delayed ack timeout
pub const DEFAULT_DELAYED_ACK_TIMEOUT: Duration = Duration::from_millis(100);

/// Sender state for managing outbound sync messages
#[derive(Debug)]
pub struct SyncSender {
    /// Minimum interval between sends (pacing)
    min_send_interval: Duration,

    /// Collection interval for batching rapid changes
    collection_interval: Duration,

    /// Delayed ack timeout
    delayed_ack_timeout: Duration,

    /// Last time we sent a message
    last_send_time: Option<Instant>,

    /// Time when pending state change was first detected
    pending_since: Option<Instant>,

    /// Time when ack became pending
    ack_pending_since: Option<Instant>,

    /// Pending message to send
    pending_message: Option<SyncMessage>,
}

impl SyncSender {
    /// Create a new sender with default settings
    pub fn new() -> Self {
        Self {
            min_send_interval: Duration::from_millis(20), // 50 Hz max
            collection_interval: DEFAULT_COLLECTION_INTERVAL,
            delayed_ack_timeout: DEFAULT_DELAYED_ACK_TIMEOUT,
            last_send_time: None,
            pending_since: None,
            ack_pending_since: None,
            pending_message: None,
        }
    }

    /// Create a sender with custom intervals
    pub fn with_intervals(
        min_send_interval: Duration,
        collection_interval: Duration,
        delayed_ack_timeout: Duration,
    ) -> Self {
        Self {
            min_send_interval,
            collection_interval,
            delayed_ack_timeout,
            last_send_time: None,
            pending_since: None,
            ack_pending_since: None,
            pending_message: None,
        }
    }

    /// Queue a message for sending
    ///
    /// The message will be held until the pacing interval allows sending.
    pub fn queue_message(&mut self, msg: SyncMessage) {
        let now = Instant::now();

        if msg.is_ack_only() {
            // Track ack pending time
            if self.ack_pending_since.is_none() {
                self.ack_pending_since = Some(now);
            }
        } else {
            // Track state change pending time
            if self.pending_since.is_none() {
                self.pending_since = Some(now);
            }
            // Clear ack pending since we're sending state
            self.ack_pending_since = None;
        }

        // Replace any pending message with newer one
        self.pending_message = Some(msg);
    }

    /// Check if we should send now
    pub fn should_send(&self) -> bool {
        self.should_send_at(Instant::now())
    }

    /// Check if we should send at a given time
    pub fn should_send_at(&self, now: Instant) -> bool {
        let Some(msg) = self.pending_message.as_ref() else {
            return false;
        };

        // Check pacing interval
        if self.last_send_time.is_some_and(|last| now.duration_since(last) < self.min_send_interval) {
            return false;
        }

        if msg.is_ack_only() {
            // Ack-only: wait for delayed ack timeout
            self.ack_pending_since
                .is_some_and(|since| now.duration_since(since) >= self.delayed_ack_timeout)
        } else {
            // State update: wait for collection interval
            self.pending_since
                .is_none_or(|since| now.duration_since(since) >= self.collection_interval)
        }
    }

    /// Take the pending message if we should send now
    pub fn take_if_ready(&mut self) -> Option<SyncMessage> {
        self.take_if_ready_at(Instant::now())
    }

    /// Take the pending message if ready at a given time
    pub fn take_if_ready_at(&mut self, now: Instant) -> Option<SyncMessage> {
        if self.should_send_at(now) {
            self.take_message_at(now)
        } else {
            None
        }
    }

    /// Force-take the pending message (bypass timing checks)
    pub fn take_message(&mut self) -> Option<SyncMessage> {
        self.take_message_at(Instant::now())
    }

    /// Force-take the pending message at a given time
    fn take_message_at(&mut self, now: Instant) -> Option<SyncMessage> {
        if let Some(msg) = self.pending_message.take() {
            self.last_send_time = Some(now);
            self.pending_since = None;
            self.ack_pending_since = None;
            Some(msg)
        } else {
            None
        }
    }

    /// Get time until next allowed send
    pub fn time_until_send(&self) -> Option<Duration> {
        self.time_until_send_at(Instant::now())
    }

    /// Get time until next allowed send at a given time
    pub fn time_until_send_at(&self, now: Instant) -> Option<Duration> {
        let msg = self.pending_message.as_ref()?;

        // Time until pacing allows
        let pacing_remaining = self.last_send_time.map_or(Duration::ZERO, |last| {
            let elapsed = now.duration_since(last);
            self.min_send_interval.saturating_sub(elapsed)
        });

        // Time until collection/ack timeout
        let batch_remaining = if msg.is_ack_only() {
            self.ack_pending_since.map_or(Duration::ZERO, |since| {
                let elapsed = now.duration_since(since);
                self.delayed_ack_timeout.saturating_sub(elapsed)
            })
        } else {
            self.pending_since.map_or(Duration::ZERO, |since| {
                let elapsed = now.duration_since(since);
                self.collection_interval.saturating_sub(elapsed)
            })
        };

        Some(pacing_remaining.max(batch_remaining))
    }

    /// Check if there's a pending message
    pub fn has_pending(&self) -> bool {
        self.pending_message.is_some()
    }

    /// Get reference to pending message
    pub fn pending_message(&self) -> Option<&SyncMessage> {
        self.pending_message.as_ref()
    }

    /// Cancel pending message
    pub fn cancel_pending(&mut self) {
        self.pending_message = None;
        self.pending_since = None;
        self.ack_pending_since = None;
    }

    /// Mark that an ack is needed (triggers delayed ack timer)
    pub fn mark_ack_needed(&mut self) {
        if self.ack_pending_since.is_none() && self.pending_message.is_none() {
            self.ack_pending_since = Some(Instant::now());
        }
    }

    /// Reset sender state
    pub fn reset(&mut self) {
        self.last_send_time = None;
        self.pending_since = None;
        self.ack_pending_since = None;
        self.pending_message = None;
    }
}

impl Default for SyncSender {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_state_msg(version: u64) -> SyncMessage {
        SyncMessage::new(version, 0, 0, vec![1, 2, 3])
    }

    fn create_ack_msg(version: u64) -> SyncMessage {
        SyncMessage::ack_only(version, version)
    }

    #[test]
    fn test_new_sender() {
        let sender = SyncSender::new();
        assert!(!sender.has_pending());
        assert!(!sender.should_send());
    }

    #[test]
    fn test_queue_state_message() {
        let mut sender = SyncSender::new();
        let msg = create_state_msg(1);

        sender.queue_message(msg.clone());

        assert!(sender.has_pending());
        assert_eq!(sender.pending_message().unwrap().sender_state_num, 1);
    }

    #[test]
    fn test_collection_interval() {
        let mut sender = SyncSender::with_intervals(
            Duration::from_millis(0), // No pacing
            Duration::from_millis(10), // 10ms collection
            Duration::from_millis(100),
        );

        let start = Instant::now();
        sender.queue_message(create_state_msg(1));

        // Shouldn't send immediately
        assert!(!sender.should_send_at(start));

        // Should send after collection interval
        let after_collection = start + Duration::from_millis(11);
        assert!(sender.should_send_at(after_collection));
    }

    #[test]
    fn test_delayed_ack() {
        let mut sender = SyncSender::with_intervals(
            Duration::from_millis(0),
            Duration::from_millis(10),
            Duration::from_millis(50), // 50ms delayed ack
        );

        let start = Instant::now();
        sender.queue_message(create_ack_msg(1));

        // Shouldn't send immediately
        assert!(!sender.should_send_at(start));

        // Should send after delayed ack timeout
        let after_timeout = start + Duration::from_millis(51);
        assert!(sender.should_send_at(after_timeout));
    }

    #[test]
    fn test_pacing() {
        let mut sender = SyncSender::with_intervals(
            Duration::from_millis(20), // 20ms pacing
            Duration::from_millis(0),
            Duration::from_millis(0),
        );

        let start = Instant::now();

        // First message should send immediately (no last_send_time)
        sender.queue_message(create_state_msg(1));
        assert!(sender.should_send_at(start));

        // Take it
        sender.take_message_at(start);

        // Queue another
        sender.queue_message(create_state_msg(2));

        // Shouldn't send yet (pacing)
        assert!(!sender.should_send_at(start + Duration::from_millis(10)));

        // Should send after pacing interval
        assert!(sender.should_send_at(start + Duration::from_millis(21)));
    }

    #[test]
    fn test_take_if_ready() {
        let mut sender = SyncSender::with_intervals(
            Duration::from_millis(0),
            Duration::from_millis(0),
            Duration::from_millis(0),
        );

        sender.queue_message(create_state_msg(1));

        let msg = sender.take_if_ready();
        assert!(msg.is_some());
        assert_eq!(msg.unwrap().sender_state_num, 1);
        assert!(!sender.has_pending());
    }

    #[test]
    fn test_time_until_send() {
        let mut sender = SyncSender::with_intervals(
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(100),
        );

        let start = Instant::now();
        sender.queue_message(create_state_msg(1));

        // Should wait for collection interval
        let wait = sender.time_until_send_at(start);
        assert!(wait.is_some());
        assert!(wait.unwrap() <= Duration::from_millis(10));
    }

    #[test]
    fn test_message_replacement() {
        let mut sender = SyncSender::new();

        sender.queue_message(create_state_msg(1));
        sender.queue_message(create_state_msg(2));

        // Should have replaced with newer message
        assert_eq!(sender.pending_message().unwrap().sender_state_num, 2);
    }

    #[test]
    fn test_cancel_pending() {
        let mut sender = SyncSender::new();

        sender.queue_message(create_state_msg(1));
        assert!(sender.has_pending());

        sender.cancel_pending();
        assert!(!sender.has_pending());
    }

    #[test]
    fn test_reset() {
        let mut sender = SyncSender::new();
        let start = Instant::now();

        sender.queue_message(create_state_msg(1));
        sender.take_message_at(start);

        sender.queue_message(create_state_msg(2));

        sender.reset();

        assert!(!sender.has_pending());
        assert!(sender.last_send_time.is_none());
    }
}
