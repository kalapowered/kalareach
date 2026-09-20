//! Opus audio codec for 48 kHz mono voice communication.
//!
//! Encapsulates libopus encoding and decoding at 48,000 Hz, single channel (mono),
//! tuned for VoIP. Implements 20 ms frames (960 samples) and native packet-loss concealment (PLC).

use crate::error::{CommandError, Result};

/// Sample rate for Opus in Hz.
pub const SAMPLE_RATE: u32 = 48_000;

/// Number of channels (mono).
pub const CHANNELS: opus::Channels = opus::Channels::Mono;

/// Samples per 20 ms frame at 48 kHz.
pub const SAMPLES_PER_FRAME: usize = 960;

/// Maximum payload size in bytes for one encoded Opus frame.
pub const MAX_PACKET_BYTES: usize = 1275;

/// An Opus codec pair for bidirectional voice streaming.
pub struct OpusCodec {
    encoder: opus::Encoder,
    decoder: opus::Decoder,
    encode_buffer: Vec<u8>,
}

impl OpusCodec {
    /// Creates a new Opus encoder and decoder.
    ///
    /// # Errors
    ///
    /// Returns an error if libopus fails to initialise with the specified parameters.
    pub fn new() -> Result<Self> {
        let encoder = opus::Encoder::new(SAMPLE_RATE, CHANNELS, opus::Application::Voip)
            .map_err(|error| CommandError::local_failure(format!("opus encoder failed: {error}")))?;
        let decoder = opus::Decoder::new(SAMPLE_RATE, CHANNELS)
            .map_err(|error| CommandError::local_failure(format!("opus decoder failed: {error}")))?;

        Ok(Self {
            encoder,
            decoder,
            encode_buffer: vec![0u8; MAX_PACKET_BYTES],
        })
    }

    /// Encodes a 20 ms frame (960 samples) of 16-bit linear PCM into an Opus packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the PCM slice is not 960 samples or if encoding fails.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>> {
        if pcm.len() != SAMPLES_PER_FRAME {
            return Err(CommandError::invalid(format!(
                "opus frame must be {SAMPLES_PER_FRAME} samples, got {}",
                pcm.len()
            )));
        }
        let len = self
            .encoder
            .encode(pcm, &mut self.encode_buffer)
            .map_err(|error| CommandError::local_failure(format!("opus encode error: {error}")))?;
        Ok(self.encode_buffer[..len].to_vec())
    }

    /// Decodes an Opus packet into 16-bit linear PCM samples.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the destination buffer is too small.
    pub fn decode(&mut self, packet: &[u8], pcm_out: &mut [i16]) -> Result<usize> {
        let decoded = self
            .decoder
            .decode(packet, pcm_out, false)
            .map_err(|error| CommandError::local_failure(format!("opus decode error: {error}")))?;
        Ok(decoded)
    }

    /// Generates packet loss concealment (PLC) audio for a missing frame.
    ///
    /// Uses libopus's internal predictor to extrapolate missing voice without silence gaps.
    ///
    /// # Errors
    ///
    /// Returns an error if libopus PLC synthesis fails.
    pub fn decode_plc(&mut self, pcm_out: &mut [i16]) -> Result<usize> {
        let decoded = self
            .decoder
            .decode(&[], pcm_out, false)
            .map_err(|error| CommandError::local_failure(format!("opus plc error: {error}")))?;
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_codec_round_trip() {
        let mut codec = OpusCodec::new().expect("codec initializes");
        let pcm_in = vec![1000i16; SAMPLES_PER_FRAME];
        let encoded = codec.encode(&pcm_in).expect("encode succeeds");
        assert!(!encoded.is_empty());

        let mut pcm_out = vec![0i16; SAMPLES_PER_FRAME];
        let decoded_len = codec.decode(&encoded, &mut pcm_out).expect("decode succeeds");
        assert_eq!(decoded_len, SAMPLES_PER_FRAME);
    }

    #[test]
    fn opus_codec_plc_generates_samples() {
        let mut codec = OpusCodec::new().expect("codec initializes");
        // Decode a packet first to give decoder history.
        let pcm_in = vec![500i16; SAMPLES_PER_FRAME];
        let encoded = codec.encode(&pcm_in).expect("encode succeeds");
        let mut pcm_out = vec![0i16; SAMPLES_PER_FRAME];
        codec.decode(&encoded, &mut pcm_out).expect("decode succeeds");

        // Now run PLC for a lost packet.
        let mut plc_out = vec![0i16; SAMPLES_PER_FRAME];
        let plc_len = codec.decode_plc(&mut plc_out).expect("plc succeeds");
        assert_eq!(plc_len, SAMPLES_PER_FRAME);
    }

    #[test]
    fn invalid_pcm_frame_size_is_refused() {
        let mut codec = OpusCodec::new().expect("codec initializes");
        let pcm_short = vec![0i16; 100];
        assert!(codec.encode(&pcm_short).is_err());
    }
}
