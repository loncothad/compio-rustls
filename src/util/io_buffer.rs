//! Completion-I/O adapters for thread-local byte buffers.

use std::{
    mem::MaybeUninit,
    ptr::NonNull,
};

use bytes_rc::{
    Bytes,
    BytesMut,
    buf::BufMut as _,
};
use compio_buf::{
    BufResult,
    IntoInner,
    IoBuf,
    IoBufMut,
    ReserveError,
    ReserveExactError,
    SetLen,
};

pub(crate) struct IoBuffer<B>(pub(crate) B);

/// Appends a synchronous read to a completion-I/O buffer.
pub(crate) fn read_into_buf<B: IoBufMut>(reader: &mut impl std::io::Read, mut buf: B) -> BufResult<usize, B> {
    let initialized = buf.buf_len();
    if initialized == buf.buf_capacity() {
        return BufResult(Ok(0), buf);
    }

    // Read may inspect every byte of its destination. Initialize the spare
    // capacity before creating a byte slice, preserving the existing prefix.
    // ensure_init does not change the logical length on errors or short reads.
    let destination = &mut buf.ensure_init()[initialized ..];
    let available = destination.len();
    let result = reader.read(destination).and_then(|count| {
        if count > available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid plaintext read count",
            ));
        }
        // SAFETY: the count is bounded by the initialized destination above.
        unsafe { buf.advance_to(initialized + count) };
        Ok(count)
    });
    BufResult(result, buf)
}

impl<B> IntoInner for IoBuffer<B> {
    type Inner = B;

    fn into_inner(self) -> B {
        self.0
    }
}

impl IoBuf for IoBuffer<Bytes> {
    fn as_init(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn buf_len(&self) -> usize {
        self.0.len()
    }

    fn buf_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

impl IoBuf for IoBuffer<BytesMut> {
    fn as_init(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn buf_len(&self) -> usize {
        self.0.len()
    }
}

impl IoBuffer<BytesMut> {
    fn allocation_ptr(&mut self) -> *mut MaybeUninit<u8> {
        if self.0.capacity() == 0 {
            return NonNull::dangling().as_ptr();
        }

        let initialized = self.0.len();
        // SAFETY: shortening the initialized prefix preserves all stored bytes.
        unsafe { self.0.set_len(0) };
        // In the pinned bytes-rc release, a zero length and non-zero capacity
        // make chunk_mut expose the full
        // allocation without reserving or moving it. A pointer derived from
        // DerefMut would cover only the initialized prefix, not spare capacity.
        let ptr = self.0.chunk_mut().as_mut_ptr().cast();
        // SAFETY: chunk_mut did not modify the existing initialized prefix.
        unsafe { self.0.set_len(initialized) };
        ptr
    }
}

impl SetLen for IoBuffer<BytesMut> {
    unsafe fn set_len(&mut self, len: usize) {
        // SAFETY: the caller guarantees capacity bounds and initialization.
        unsafe { self.0.set_len(len) };
    }
}

impl IoBufMut for IoBuffer<BytesMut> {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let capacity = self.0.capacity();
        let ptr = self.allocation_ptr();
        // SAFETY: the pointer covers exactly this buffer's capacity. BytesMut
        // guarantees that mutable split regions do not overlap other handles.
        unsafe { std::slice::from_raw_parts_mut(ptr, capacity) }
    }

    fn buf_capacity(&mut self) -> usize {
        self.0.capacity()
    }

    fn buf_mut_ptr(&mut self) -> *mut MaybeUninit<u8> {
        self.allocation_ptr()
    }

    fn reserve(&mut self, additional: usize) -> Result<(), ReserveError> {
        self.0.reserve(additional);
        Ok(())
    }

    fn reserve_exact(&mut self, additional: usize) -> Result<(), ReserveExactError> {
        if self.0.capacity() - self.0.len() >= additional {
            return Ok(());
        }
        self.0.reserve(additional);
        let reserved = self.0.capacity() - self.0.len();
        if reserved != additional {
            return Err(ReserveExactError::ExactSizeMismatch {
                reserved,
                expected: additional,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid Read implementation may inspect the entire destination before
    // writing. Under Miri this detects uninitialized input, even on EOF/errors.
    struct InspectingReader(std::io::Result<usize>);

    impl std::io::Read for InspectingReader {
        fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
            assert!(destination.iter().all(|byte| *byte == 0));
            destination.fill(b'x');
            std::mem::replace(&mut self.0, Ok(0))
        }
    }

    fn check_plaintext_append<B: IoBufMut>(buffer: B) {
        let prefix = buffer.as_init().to_vec();
        let BufResult(result, buffer) = read_into_buf(&mut InspectingReader(Ok(2)), buffer);
        assert_eq!(result.unwrap(), 2);
        assert_eq!(&buffer.as_init()[.. prefix.len()], prefix);
        assert_eq!(&buffer.as_init()[prefix.len() ..], b"xx");
    }

    #[test]
    fn plaintext_read_initializes_spare_capacity() {
        check_plaintext_append(Vec::with_capacity(32));
        check_plaintext_append(IoBuffer(BytesMut::with_capacity(32)));
    }

    #[test]
    fn plaintext_read_preserves_initialized_prefix_and_slice_bounds() {
        let mut buffer = Vec::with_capacity(32);
        buffer.extend_from_slice(b"prefix");
        check_plaintext_append(buffer);
        let mut bytes = BytesMut::with_capacity(32);
        bytes.extend_from_slice(b"prefix");
        let frozen = bytes.split_to(3).freeze();
        check_plaintext_append(IoBuffer(bytes).slice(1 .. 8));
        assert_eq!(frozen.as_ref(), b"pre");
    }

    #[test]
    fn plaintext_read_does_not_advance_on_eof_or_error() {
        for outcome in [
            Ok(0),
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
        ] {
            let kind = outcome.as_ref().err().map(std::io::Error::kind);
            let mut buffer = Vec::with_capacity(32);
            buffer.extend_from_slice(b"prefix");
            let BufResult(result, buffer) = read_into_buf(&mut InspectingReader(outcome), buffer);
            assert_eq!(result.as_ref().err().map(std::io::Error::kind), kind);
            if kind.is_none() {
                assert_eq!(result.unwrap(), 0);
            }
            assert_eq!(buffer, b"prefix");
        }
    }

    #[test]
    fn plaintext_read_rejects_invalid_count_without_advancing() {
        let buffer = Vec::with_capacity(8);
        let BufResult(result, buffer) = read_into_buf(&mut InspectingReader(Ok(9)), buffer);
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert!(buffer.is_empty());
    }

    #[test]
    fn plaintext_read_skips_reader_when_destination_is_full() {
        struct MustNotRead;
        impl std::io::Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("a full destination must not consume plaintext");
            }
        }
        let BufResult(result, buffer) = read_into_buf(&mut MustNotRead, Vec::<u8>::new());
        assert_eq!(result.unwrap(), 0);
        assert!(buffer.is_empty());
        let BufResult(result, buffer) = read_into_buf(&mut MustNotRead, *b"full");
        assert_eq!(result.unwrap(), 0);
        assert_eq!(&buffer, b"full");
    }

    #[test]
    fn empty_capacity_does_not_allocate() {
        let mut buffer = IoBuffer(BytesMut::new());
        assert!(buffer.as_uninit().is_empty());
        assert_eq!(buffer.buf_capacity(), 0);
        assert_eq!(buffer.buf_len(), 0);
    }

    #[test]
    fn pointer_covers_spare_capacity_and_preserves_prefix() {
        let mut bytes = BytesMut::with_capacity(32);
        bytes.extend_from_slice(b"prefix");
        let mut buffer = IoBuffer(bytes);
        let ptr = buffer.buf_mut_ptr();
        let capacity = buffer.buf_capacity();
        let initialized = buffer.buf_len();
        assert_eq!(capacity, 32);
        assert_eq!(initialized, 6);
        // SAFETY: the pointer covers the full capacity; the four tail bytes
        // are initialized before advancing the length.
        unsafe {
            std::ptr::copy_nonoverlapping(b"tail".as_ptr(), ptr.add(initialized).cast(), 4);
            buffer.set_len(initialized + 4);
        }
        assert_eq!(buffer.as_init(), b"prefixtail");
    }

    #[test]
    fn completion_slice_appends_without_overwriting_initialized_bytes() {
        let mut bytes = BytesMut::with_capacity(32);
        bytes.extend_from_slice(b"prefix");
        let mut tail = IoBuffer(bytes).slice(6 ..);
        for (destination, byte) in tail.as_uninit().iter_mut().zip(b"tail") {
            destination.write(*byte);
        }
        // SAFETY: the first four bytes in the completion slice were written.
        unsafe { tail.set_len(4) };
        let bytes = tail.into_inner().into_inner();
        assert_eq!(bytes.as_ref(), b"prefixtail");
        assert_eq!(bytes.capacity(), 32);
    }

    #[test]
    fn immutable_slices_share_storage_and_restore_unique_capacity() {
        let mut bytes = BytesMut::with_capacity(64);
        bytes.extend_from_slice(b"abcdefgh");
        let bytes = bytes.freeze();
        let address = bytes.as_ptr();
        let slice = IoBuffer(Bytes::slice(&bytes, 2 .. 6));
        assert_eq!(slice.buf_ptr(), address.wrapping_add(2));
        assert_eq!(slice.as_init(), b"cdef");
        let bytes = bytes.try_into_mut().expect_err("the I/O slice keeps shared ownership");
        drop(slice);
        let bytes = bytes
            .try_into_mut()
            .expect("the returned I/O buffer is no longer shared");
        assert_eq!(bytes.as_ptr(), address);
        assert_eq!(bytes.capacity(), 64);
    }

    #[test]
    fn writable_split_capacity_is_disjoint_from_frozen_sibling() {
        let mut bytes = BytesMut::with_capacity(32);
        bytes.extend_from_slice(b"abcdefgh");
        let frozen = bytes.split_to(3).freeze();
        let mut buffer = IoBuffer(bytes);
        buffer.as_uninit()[5].write(b'!');
        // SAFETY: the initialized five-byte prefix and the new tail are valid.
        unsafe { buffer.set_len(6) };
        assert_eq!(buffer.as_init(), b"defgh!");
        assert_eq!(frozen.as_ref(), b"abc");
        IoBufMut::reserve(&mut buffer, 64).unwrap();
        assert_eq!(buffer.as_init(), b"defgh!");
        assert_eq!(frozen.as_ref(), b"abc");
    }
}
