use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Condvar, Mutex};

/// Create something like a channel, where the sending side feeds chunks of `&[u8]` data
/// into the channel, and the receiving side collects it into a big `Vec<u8>` and can be
/// used as a `Read` and `Seek` object, synchonously blocking until the data is available.
///
/// We use this for streaming CAB extraction: The CAB API expects us to provide a `Read` object
/// that it can synchronously read from. But our data arrives in chunks from an `AsyncRead`
/// source. Se we make a blocking task for the CAB extraction, and feed the chunks into the
/// `RemotelyFedCursor` as they arrive. Then the blocking task can synchronously wait during
/// `Read::read` calls until the data is available.
pub fn create_cursor_channel() -> (RemotelyFedCursor, RemotelyFedCursorFeeder) {
    let shared = Arc::new((
        Mutex::new(RemotelyFedCursorMutexData::new()),
        Condvar::new(),
    ));
    let feeder = RemotelyFedCursorFeeder {
        shared: shared.clone(),
    };
    let cursor = RemotelyFedCursor {
        shared,
        current_pos: 0,
        current_known_length: 0,
        have_complete_length: false,
    };
    (cursor, feeder)
}

pub struct RemotelyFedCursor {
    shared: Arc<(Mutex<RemotelyFedCursorMutexData>, Condvar)>,
    current_pos: u64,
    current_known_length: u64,
    have_complete_length: bool,
}

pub struct RemotelyFedCursorFeeder {
    shared: Arc<(Mutex<RemotelyFedCursorMutexData>, Condvar)>,
}

struct RemotelyFedCursorMutexData {
    buffer: Vec<u8>,
    is_complete: bool,
}

impl RemotelyFedCursor {
    fn get_complete_len(&mut self) -> u64 {
        if self.have_complete_length {
            return self.current_known_length;
        }

        let (lock, cvar) = &*self.shared;
        let mut shared = lock.lock().unwrap();
        self.current_known_length = shared.buffer.len() as u64;
        self.have_complete_length = shared.is_complete;
        while !self.have_complete_length {
            shared = cvar.wait(shared).expect("condition variable wait failed");
            self.current_known_length = shared.buffer.len() as u64;
            self.have_complete_length = shared.is_complete;
        }

        self.current_known_length
    }

    fn wait_until_len_known_or_at_least(&mut self, min_len: u64) -> u64 {
        if self.have_complete_length || self.current_known_length >= min_len {
            return self.current_known_length;
        }

        let (lock, cvar) = &*self.shared;
        let mut shared = lock.lock().unwrap();
        self.current_known_length = shared.buffer.len() as u64;
        self.have_complete_length = shared.is_complete;

        while !self.have_complete_length && self.current_known_length < min_len {
            // eprintln!("Looking for length {min_len}, have {}", self.current_known_length);
            // Wait until the condition variable is signaled, indicating
            // that the length has updated.
            shared = cvar.wait(shared).expect("condition variable wait failed");
            self.current_known_length = shared.buffer.len() as u64;
            self.have_complete_length = shared.is_complete;
        }

        self.current_known_length
    }
}

impl RemotelyFedCursorFeeder {
    pub fn feed(&self, bytes: &[u8]) {
        let (lock, cvar) = &*self.shared;
        let mut shared = lock.lock().unwrap();
        shared.buffer.extend_from_slice(bytes);
        cvar.notify_one();
    }

    pub fn mark_complete(&self) {
        let (lock, cvar) = &*self.shared;
        let mut shared = lock.lock().unwrap();
        shared.is_complete = true;
        cvar.notify_one();
    }
}

impl RemotelyFedCursorMutexData {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            is_complete: false,
        }
    }
}

impl Seek for RemotelyFedCursor {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(new_pos) => new_pos,
            SeekFrom::End(offset) => {
                let new_pos = self.get_complete_len() as i64 + offset;
                if new_pos < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek to a negative position",
                    ));
                }
                new_pos as u64
            }
            SeekFrom::Current(offset) => {
                let new_pos = self.current_pos as i64 + offset;
                if new_pos < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid seek to a negative position",
                    ));
                }
                new_pos as u64
            }
        };
        self.current_pos = new_pos;
        Ok(new_pos)
    }
}

impl Read for RemotelyFedCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buf_end_pos = self.current_pos + buf.len() as u64;
        let available_end_pos = self.wait_until_len_known_or_at_least(buf_end_pos);
        if self.current_pos >= available_end_pos {
            return Ok(0);
        }
        let bytes_to_copy = std::cmp::min(buf.len() as u64, available_end_pos - self.current_pos);
        {
            let (lock, _cvar) = &*self.shared;
            let shared = lock.lock().unwrap();
            self.current_known_length = shared.buffer.len() as u64;
            self.have_complete_length = shared.is_complete;
            buf[..bytes_to_copy as usize].copy_from_slice(
                &shared.buffer[self.current_pos as usize..][..bytes_to_copy as usize],
            );
        }
        self.current_pos += bytes_to_copy as u64;
        Ok(bytes_to_copy as usize)
    }
}
