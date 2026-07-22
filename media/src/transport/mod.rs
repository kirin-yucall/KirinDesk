/// Encoded H.264 video frame with metadata.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub pts: u64,
    pub is_keyframe: bool,
    pub sequence: u64,
}

/// Streams encoded frames over a secure channel.
pub struct MediaStreamer {
    sequence: u64,
    max_packet_size: usize,
}

impl MediaStreamer {
    pub fn new(max_packet_size: usize) -> Self {
        Self { sequence: 0, max_packet_size }
    }

    /// Wrap encoded data as a frame with sequence metadata.
    pub fn fragment(&mut self, data: &[u8], is_keyframe: bool) -> Vec<EncodedFrame> {
        let seq = self.sequence;
        self.sequence += 1;
        vec![EncodedFrame {
            data: data.to_vec(),
            pts: seq * 33_333,
            is_keyframe,
            sequence: seq,
        }]
    }
}

/// Combined capture+encode pipeline.
pub struct MediaPipeline;

impl MediaPipeline {
    /// Capture one frame and encode it.
    pub async fn capture_and_encode(
        capture_cfg: &crate::capture::CaptureConfig,
        encoder: &mut crate::encode::FfmpegEncoder,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let frame = crate::capture::ScreenCapture::capture_frame(capture_cfg)?;
        let encoded = encoder.encode(&frame.data)?;
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streamer_sequence() {
        let mut s = MediaStreamer::new(65536);
        let f = s.fragment(b"data", true);
        assert_eq!(f[0].sequence, 0);
        assert!(f[0].is_keyframe);
        let f2 = s.fragment(b"more", false);
        assert_eq!(f2[0].sequence, 1);
    }
}
