use std::io::{
    self,
    Write,
};

use compio_buf::bytes::BytesMut;

pub struct BytesMutWriter<'a>(pub &'a mut BytesMut);

impl Write for BytesMutWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}
