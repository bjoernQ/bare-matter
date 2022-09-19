#[derive(Debug, Clone)]
pub struct Buffer<const C: usize> {
    data: [u8; C],
    len: usize,
    write_index: usize,
}

impl<const C: usize> Buffer<C> {
    pub fn new_from_slice(slice: &[u8]) -> Buffer<C> {
        let mut res = Buffer {
            data: [0u8; C],
            len: slice.len(),
            write_index: slice.len(),
        };

        res.data[..slice.len()].copy_from_slice(slice);
        res
    }

    pub fn slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn push(&mut self, bytes: &[u8]) -> usize {
        let fitting = usize::min(bytes.len(), C - self.write_index);
        self.data[self.write_index..][..fitting].copy_from_slice(&bytes[..fitting]);
        self.len += fitting;
        self.write_index += fitting;

        if fitting != bytes.len() {
            panic!("buffer overflow");
        }

        fitting
    }
}

impl<const C: usize> core::fmt::Write for Buffer<C> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        self.push(bytes);
        Ok(())
    }
}

impl<const C: usize> AsMut<[u8]> for Buffer<C> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.slice_mut()
    }
}

impl<const C: usize> AsRef<[u8]> for Buffer<C> {
    fn as_ref(&self) -> &[u8] {
        self.slice()
    }
}

impl<const C: usize> ccm::aead::Buffer for Buffer<C> {
    fn extend_from_slice(&mut self, other: &[u8]) -> ccm::aead::Result<()> {
        self.push(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
    }
}
