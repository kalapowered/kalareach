//! Bounded PCM ring buffer for desktop audio playback.
//!
//! Section 15 paragraph 2 and the media survey define the jitter and receive pipeline:
//! remote audio packets decoded from Opus are placed into a bounded PCM buffer with a target
//! depth of 120 ms. Overrun drops the oldest audio rather than accumulating unbounded latency,
//! and underruns are counted and reported rather than hidden.

use std::collections::VecDeque;

/// Sampling rate in Hz for VoiceProcessingIO and Opus.
pub const SAMPLE_RATE: usize = 48_000;

/// Frame size in samples for a 20 ms audio frame.
pub const SAMPLES_PER_20MS: usize = 960;

/// Target buffer depth in samples (120 ms at 48 kHz mono = 5,760 samples).
pub const TARGET_DEPTH_SAMPLES: usize = (SAMPLE_RATE * 120) / 1000;

/// Maximum buffer capacity in samples (240 ms at 48 kHz mono = 11,520 samples).
pub const CAPACITY_SAMPLES: usize = (SAMPLE_RATE * 240) / 1000;

/// A bounded FIFO ring buffer for single-channel linear PCM samples.
#[derive(Debug)]
pub struct PcmRingBuffer {
    buffer: VecDeque<i16>,
    capacity: usize,
    target_depth: usize,
    underrun_count: u64,
    overrun_count: u64,
}

impl PcmRingBuffer {
    /// Creates a new buffer with standard 120 ms target depth and 240 ms capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_depth_and_capacity(TARGET_DEPTH_SAMPLES, CAPACITY_SAMPLES)
    }

    /// Creates a new buffer with custom depth and capacity.
    #[must_use]
    pub fn with_depth_and_capacity(target_depth: usize, capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            target_depth,
            underrun_count: 0,
            overrun_count: 0,
        }
    }

    /// Pushes new PCM samples into the buffer.
    ///
    /// If adding these samples would exceed capacity, the oldest samples are dropped to
    /// preserve bounded latency and prevent delay drift.
    pub fn push(&mut self, samples: &[i16]) {
        let needed = samples.len();
        if needed > self.capacity {
            // If the incoming chunk is larger than capacity, keep only the newest slice.
            let start = needed - self.capacity;
            self.buffer.clear();
            self.buffer.extend(&samples[start..]);
            self.overrun_count += 1;
            return;
        }

        let overflow = (self.buffer.len() + needed).saturating_sub(self.capacity);
        if overflow > 0 {
            self.buffer.drain(..overflow);
            self.overrun_count += 1;
        }
        self.buffer.extend(samples);
    }

    /// Drains samples from the buffer into the provided output slice.
    ///
    /// Returns the number of samples read. If fewer samples are available than requested,
    /// the remainder of `output` is zero-filled (silence) and an underrun is recorded.
    pub fn drain(&mut self, output: &mut [i16]) -> usize {
        let requested = output.len();
        let available = self.buffer.len();
        let to_copy = requested.min(available);

        for out in output.iter_mut().take(to_copy) {
            *out = self.buffer.pop_front().unwrap_or(0);
        }

        if to_copy < requested {
            output[to_copy..].fill(0);
            self.underrun_count += 1;
        }

        to_copy
    }

    /// Number of samples currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// True when the buffer holds no samples.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Target depth in samples.
    #[must_use]
    pub const fn target_depth(&self) -> usize {
        self.target_depth
    }

    /// Maximum capacity in samples.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of underrun events recorded.
    #[must_use]
    pub const fn underruns(&self) -> u64 {
        self.underrun_count
    }

    /// Number of overrun events recorded.
    #[must_use]
    pub const fn overruns(&self) -> u64 {
        self.overrun_count
    }

    /// Clears all buffered samples.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl Default for PcmRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_pushes_and_drains_correctly() {
        let mut buf = PcmRingBuffer::new();
        let samples = vec![100i16; 960];
        buf.push(&samples);
        assert_eq!(buf.len(), 960);

        let mut out = vec![0i16; 480];
        let read = buf.drain(&mut out);
        assert_eq!(read, 480);
        assert_eq!(buf.len(), 480);
        assert_eq!(out, vec![100i16; 480]);
        assert_eq!(buf.underruns(), 0);
    }

    #[test]
    fn buffer_records_underrun_and_silences_tail() {
        let mut buf = PcmRingBuffer::new();
        let samples = vec![200i16; 100];
        buf.push(&samples);

        let mut out = vec![5i16; 200];
        let read = buf.drain(&mut out);
        assert_eq!(read, 100);
        assert_eq!(buf.len(), 0);
        assert_eq!(&out[..100], &vec![200i16; 100][..]);
        assert_eq!(&out[100..], &vec![0i16; 100][..]);
        assert_eq!(buf.underruns(), 1);
    }

    #[test]
    fn buffer_drops_oldest_samples_on_overrun() {
        let mut buf = PcmRingBuffer::with_depth_and_capacity(100, 200);
        let first = (0..150).map(|i| i as i16).collect::<Vec<_>>();
        buf.push(&first);
        assert_eq!(buf.len(), 150);
        assert_eq!(buf.overruns(), 0);

        let second = (150..250).map(|i| i as i16).collect::<Vec<_>>();
        buf.push(&second);
        assert_eq!(buf.len(), 200);
        assert_eq!(buf.overruns(), 1);

        let mut out = vec![0i16; 200];
        buf.drain(&mut out);
        // The first 50 samples were dropped; buffer contains 50..250.
        assert_eq!(out[0], 50);
        assert_eq!(out[199], 249);
    }
}
