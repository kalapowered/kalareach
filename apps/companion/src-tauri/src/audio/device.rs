//! Desktop platform audio device integration.
//!
//! On macOS, drives an `AudioUnit` of `IOType::VoiceProcessingIO` (Apple's Voice-Processing
//! I/O unit), providing OS-level acoustic echo cancellation (AEC), gain control (AGC),
//! and noise suppression. All callback registration and start/stop APIs are safe Rust.
//!
//! On Linux and Windows, returns `UNAVAILABLE` errors, matching the established pattern in `verify.rs`.

#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex};

use crate::error::{CommandError, Result};

#[cfg(target_os = "macos")]
use crate::audio::buffer::PcmRingBuffer;

/// Audio device controller for native capture and playback.
pub struct AudioDevice {
    #[cfg(target_os = "macos")]
    audio_unit: Option<coreaudio::audio_unit::AudioUnit>,
    #[cfg(target_os = "macos")]
    render_ring: Arc<Mutex<PcmRingBuffer>>,
    #[cfg(target_os = "macos")]
    is_running: bool,
}

impl AudioDevice {
    /// Creates a new audio device attached to the given playback buffer.
    #[must_use]
    #[cfg(target_os = "macos")]
    pub fn new(render_ring: Arc<Mutex<PcmRingBuffer>>) -> Self {
        Self {
            audio_unit: None,
            render_ring,
            is_running: false,
        }
    }

    /// Creates a new audio device on non-macOS platforms.
    #[must_use]
    #[cfg(not(target_os = "macos"))]
    pub fn new() -> Self {
        Self {}
    }

    /// Starts native capture and render.
    ///
    /// # Errors
    ///
    /// Returns `UNAVAILABLE` on non-macOS, or a local failure if CoreAudio fails to start.
    #[cfg(target_os = "macos")]
    pub fn start<F>(&mut self, mut on_captured_frame: F) -> Result<()>
    where
        F: FnMut(&[i16]) + Send + 'static,
    {
        use coreaudio::audio_unit::render_callback::data::Interleaved;
        use coreaudio::audio_unit::render_callback::Args;
        use coreaudio::audio_unit::types::IOType;
        use coreaudio::audio_unit::{AudioUnit, Element, Scope, StreamFormat};

        if self.is_running {
            return Ok(());
        }

        let mut unit = AudioUnit::new(IOType::VoiceProcessingIO).map_err(|error| {
            CommandError::local_failure(format!("failed to open VoiceProcessingIO unit: {error}"))
        })?;

        let format = StreamFormat {
            sample_rate: 48_000.0,
            sample_format: coreaudio::audio_unit::SampleFormat::I16,
            flags: coreaudio::audio_unit::audio_format::LinearPcmFlags::IS_SIGNED_INTEGER
                | coreaudio::audio_unit::audio_format::LinearPcmFlags::IS_PACKED,
            channels: 1,
        };

        // Element 1 is input (mic), element 0 is output (speaker).
        let _ = unit.set_stream_format(format, Scope::Output, Element::Input);
        let _ = unit.set_stream_format(format, Scope::Input, Element::Output);

        let ring_clone = Arc::clone(&self.render_ring);

        // Render callback: drains from ring buffer into speaker output.
        unit.set_render_callback(
            move |args: Args<Interleaved<i16>>| -> std::result::Result<(), ()> {
                let mut guard = ring_clone.lock().map_err(|_| ())?;
                let buf = args.data.buffer;
                guard.drain(buf);
                Ok(())
            },
        )
        .map_err(|error| {
            CommandError::local_failure(format!("failed to set render callback: {error}"))
        })?;

        // Input callback: forwards captured microphone PCM to callback.
        unit.set_input_callback(
            move |args: Args<Interleaved<i16>>| -> std::result::Result<(), ()> {
                let buf = args.data.buffer;
                on_captured_frame(buf);
                Ok(())
            },
        )
        .map_err(|error| {
            CommandError::local_failure(format!("failed to set input callback: {error}"))
        })?;

        unit.start().map_err(|error| {
            CommandError::local_failure(format!("failed to start VoiceProcessingIO unit: {error}"))
        })?;

        self.audio_unit = Some(unit);
        self.is_running = true;
        Ok(())
    }

    /// Starts audio device on non-macOS platforms.
    ///
    /// # Errors
    ///
    /// Always returns `UNAVAILABLE`.
    #[cfg(not(target_os = "macos"))]
    pub fn start<F>(&mut self, _on_captured_frame: F) -> Result<()>
    where
        F: FnMut(&[i16]) + Send + 'static,
    {
        Err(CommandError::unavailable(
            "this platform has no desktop audio backend yet; use an iOS or Android device",
        ))
    }

    /// Stops the audio device.
    pub fn stop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            if let Some(mut unit) = self.audio_unit.take() {
                let _ = unit.stop();
            }
            self.is_running = false;
        }
    }

    /// Whether the audio device is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.is_running
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
}

impl Drop for AudioDevice {
    fn drop(&mut self) {
        self.stop();
    }
}
