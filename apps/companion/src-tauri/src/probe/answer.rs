//! The answer a provider would give to a call's offer, which a phone's checks and the harness's
//! voice service both build. It names nothing outside the standard library, so a test of another
//! crate includes this file by its path.

/// The answer a provider would give to `offer`, built from the offer's own sections.
///
/// Every section of the offer is answered in its place, with its own identifier: an audio section
/// with the one codec the offer and the provider share, and the data section the provider's events
/// channel is made in. The answer is an ICE-lite agent's, with a fingerprint and candidates that
/// lead nowhere, so a connection that applies it never connects. It is shaped as the recorded
/// answer of the provider's service is.
///
/// # Errors
///
/// Returns why the offer cannot be answered: it holds no audio section, no data section, or a kind
/// of section this answer does not know.
pub fn answer_for(offer: &str) -> Result<String, String> {
    let mut sections: Vec<(&str, String)> = Vec::new();
    let mut current: Option<(&str, String)> = None;
    for line in offer.lines().map(str::trim_end) {
        if let Some(media) = line.strip_prefix("m=") {
            if let Some(done) = current.take() {
                sections.push(done);
            }
            let kind = media.split_whitespace().next().unwrap_or_default();
            current = Some((
                match kind {
                    "audio" => "audio",
                    "application" => "application",
                    _ => {
                        return Err(format!(
                            "the offer holds a {kind} section, which is not answered"
                        ));
                    }
                },
                String::new(),
            ));
        } else if let Some((_, text)) = current.as_mut() {
            text.push_str(line);
            text.push('\n');
        }
    }
    sections.extend(current);
    let mut mids = Vec::new();
    for (_, text) in &sections {
        let mid = text
            .lines()
            .find_map(|line| line.strip_prefix("a=mid:"))
            .ok_or("a section of the offer has no identifier")?;
        mids.push(mid.to_owned());
    }
    if !sections.iter().any(|(kind, _)| *kind == "audio") {
        return Err("the offer holds no audio section".to_owned());
    }
    if !sections.iter().any(|(kind, _)| *kind == "application") {
        return Err("the offer holds no data section".to_owned());
    }
    let mut answer = String::new();
    answer.push_str("v=0\r\no=- 1155667488797280743 1789504978 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n");
    answer.push_str("a=msid-semantic:WMS *\r\n");
    answer.push_str(
        "a=fingerprint:sha-256 DD:0A:C5:DD:11:BB:23:F1:D5:85:19:90:CC:82:1E:E5:A3:04:88:D1:D3:53:83:5F:1A:D2:BA:2D:5A:42:40:25\r\n",
    );
    answer.push_str("a=ice-lite\r\na=extmap-allow-mixed\r\n");
    answer.push_str(&format!("a=group:BUNDLE {}\r\n", mids.join(" ")));
    for ((kind, _), mid) in sections.iter().zip(&mids) {
        match *kind {
            "audio" => {
                answer.push_str(
                    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=setup:active\r\n",
                );
                answer.push_str(&format!("a=mid:{mid}\r\n"));
                answer.push_str(
                    "a=ice-ufrag:FDTJv7/u0/3oMbfr\r\na=ice-pwd:GXuZvi9ZeCVsqv3XzFgEgVWxk25QYfLD\r\n\
                     a=rtcp-mux\r\na=rtcp-rsize\r\na=rtpmap:111 opus/48000/2\r\n\
                     a=fmtp:111 minptime=10;useinbandfec=1\r\n\
                     a=ssrc:3677868517 cname:realtimeapi\r\na=ssrc:3677868517 msid:realtimeapi audio\r\n\
                     a=ssrc:3677868517 mslabel:realtimeapi\r\na=ssrc:3677868517 label:audio\r\n\
                     a=msid:realtimeapi audio\r\na=sendrecv\r\n\
                     a=candidate:3826567912 1 udp 2130706431 127.0.0.1 3478 typ host ufrag FDTJv7/u0/3oMbfr\r\n",
                );
            }
            _ => {
                answer.push_str(
                    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=setup:active\r\n",
                );
                answer.push_str(&format!("a=mid:{mid}\r\n"));
                answer.push_str(
                    "a=sendrecv\r\na=sctp-port:5000\r\na=max-message-size:1073741823\r\n\
                     a=ice-ufrag:FDTJv7/u0/3oMbfr\r\na=ice-pwd:GXuZvi9ZeCVsqv3XzFgEgVWxk25QYfLD\r\n",
                );
            }
        }
    }
    Ok(answer)
}
