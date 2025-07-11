// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    catnap::transport::get_libc_err,
    collections::{async_queue::AsyncQueue, async_value::SharedAsyncValue},
    expect_ok,
    runtime::{fail::Fail, limits, memory::DemiBuffer, DemiRuntime},
};
use ::socket2::Socket;
use ::std::{cmp::min, mem::MaybeUninit, net::SocketAddr, slice, time::Duration};

//======================================================================================================================
// Structures
//======================================================================================================================

/// This structure represents outgoing packets.
struct Outgoing {
    addr: Option<SocketAddr>,
    buffer: DemiBuffer,
    result: SharedAsyncValue<Option<Result<(), Fail>>>,
}

/// This structure represents the metadata for an active established socket: the socket itself and the queue of
/// outgoing messages and incoming ones.
pub struct ActiveSocketData {
    socket: Socket,
    send_queue: AsyncQueue<Outgoing>,
    recv_queue: AsyncQueue<Result<(Option<SocketAddr>, DemiBuffer), Fail>>,
    closed: bool,
}

//======================================================================================================================
// Implementations
//======================================================================================================================

impl ActiveSocketData {
    pub fn new(socket: Socket) -> Self {
        Self {
            socket,
            send_queue: AsyncQueue::default(),
            recv_queue: AsyncQueue::default(),
            closed: false,
        }
    }

    /// Polls the send queue on an outgoing epoll event and send out data if there is any pending. We use an empty
    /// buffer for write to indicate that we want to know when the socket is ready for writing but do not have data to
    /// write (i.e., to detect when connect finishes).
    pub fn poll_send(&mut self) {
        if let Some(Outgoing {
            addr,
            mut buffer,
            mut result,
        }) = self.send_queue.try_pop()
        {
            // A dummy request to detect when the socket has connected.
            if buffer.is_empty() {
                result.set(Some(Ok(())));
                return;
            }
            // Try to send the buffer.
            let io_result = match addr {
                Some(addr) => self.socket.send_to(&buffer, &addr.into()),
                None => self.socket.send(&buffer),
            };
            match io_result {
                // Operation completed.
                Ok(nbytes) => {
                    trace!("data pushed ({:?}/{:?} bytes)", nbytes, buffer.len());
                    expect_ok!(
                        buffer.adjust(nbytes),
                        "OS should not have sent more bytes than in the buffer"
                    );
                    if buffer.is_empty() {
                        // Done sending this buffer
                        result.set(Some(Ok(())));
                    } else {
                        // Only sent part of the buffer so try again later.
                        self.send_queue.push_front(Outgoing { addr, buffer, result });
                    }
                },
                Err(e) => {
                    let errno = get_libc_err(e);
                    if DemiRuntime::should_retry(errno) {
                        // Put the buffer back and try again later.
                        self.send_queue.push_front(Outgoing { addr, buffer, result });
                    } else {
                        let cause = format!("failed to send on socket: {:?}", errno);
                        error!("poll_send(): {}", cause);
                        result.set(Some(Err(Fail::new(errno, &cause))));
                    }
                },
            }
        }
    }

    /// Polls the socket for incoming data on an incoming epoll event. Inserts any received data into the incoming
    /// queue.
    /// TODO: Incoming queue should possibly be byte oriented.
    pub fn poll_recv(&mut self) {
        let mut buffer = DemiBuffer::new(limits::POP_SIZE_MAX as u16);
        if self.closed {
            return;
        }
        match self
            .socket
            .recv_from(unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut MaybeUninit<u8>, buffer.len()) })
        {
            // Operation completed.
            Ok((num_bytes, socketaddr)) => {
                if let Err(e) = buffer.trim(buffer.len() - num_bytes) {
                    self.recv_queue.push(Err(e));
                } else {
                    trace!("data popped ({:?} bytes)", num_bytes);
                    if buffer.is_empty() {
                        self.closed = true;
                    }
                    self.recv_queue.push(Ok((socketaddr.as_socket(), buffer)));
                }
            },
            Err(e) => {
                let errno = get_libc_err(e);
                if !DemiRuntime::should_retry(errno) {
                    let cause = format!("failed to receive on socket: {:?}", errno);
                    error!("poll_recv(): {}", cause);
                    self.recv_queue.push(Err(Fail::new(errno, &cause)));
                }
            },
        }
    }

    /// Pushes data to the socket. Blocks until completion.
    pub async fn push(&mut self, addr: Option<SocketAddr>, buffer: DemiBuffer) -> Result<(), Fail> {
        let mut result = SharedAsyncValue::new(None);
        self.send_queue.push(Outgoing {
            addr,
            buffer,
            result: result.clone(),
        });
        loop {
            match result.get() {
                Some(result) => return result,
                None => {
                    result.wait_for_change(None).await?;
                    continue;
                },
            }
        }
    }

    /// Pops data from the socket. Blocks until some data is found but does not wait until the buf has reached [size].
    pub async fn pop(
        &mut self,
        size: usize,
        timeout: Option<Duration>,
    ) -> Result<(Option<SocketAddr>, DemiBuffer), Fail> {
        let (addr, mut buffer) = self.recv_queue.pop(timeout).await??;
        // Figure out how much data we got.
        let bytes_read = min(buffer.len(), size);
        // Trim the buffer and leave for next read if we got more than expected.
        if let Ok(remainder) = buffer.split_back(bytes_read) {
            if !remainder.is_empty() {
                self.push_front(remainder, addr.clone());
            }
        }
        Ok((addr, buffer))
    }

    /// Puts data back into the socket queue.
    pub fn push_front(&mut self, buf: DemiBuffer, addr: Option<SocketAddr>) {
        self.recv_queue.push_front(Ok((addr, buf)));
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }

    pub fn socket_mut(&mut self) -> &mut Socket {
        &mut self.socket
    }
}
