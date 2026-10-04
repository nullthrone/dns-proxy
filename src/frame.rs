//! Length-prefixed DNS message framing for TCP and TLS (RFC 1035 4.2.2).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Writes one length-prefixed DNS message (RFC 1035 4.2.2).
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "message too large"))?;
    let mut buf = Vec::with_capacity(2 + msg.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(msg);
    w.write_all(&buf).await?;
    w.flush().await
}

/// Reads one length-prefixed DNS message; `None` on clean EOF.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty message",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}
