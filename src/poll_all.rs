use std::future::poll_fn;
use std::task::Poll;

use futures_util::FutureExt;

/// Provides a way to iterate over a collection of futures, but polling all
/// of them from the start. This can be used to start e.g. network requests
/// in parallel and to consume the results in the original order.
pub struct PollAllPreservingOrder<V, F: futures::Future<Output = V> + Unpin> {
    values: Vec<Option<V>>, // None if pending or already consumed, Some if ready
    pending_futures: Vec<(usize, F)>,
    current_index: usize,
}

impl<V, F: futures::Future<Output = V> + Unpin> PollAllPreservingOrder<V, F> {
    pub fn new(futures: Vec<F>) -> Self {
        Self {
            values: futures.iter().map(|_| None).collect(),
            pending_futures: futures.into_iter().enumerate().collect(),
            current_index: 0,
        }
    }

    pub async fn next(&mut self) -> Option<V> {
        poll_fn(move |cx| {
            if self.current_index == self.values.len() {
                return Poll::Ready(None);
            }

            // Poll all pending futures and remove the ones that are ready,
            // storing their values in the values array.
            self.pending_futures
                .retain_mut(|(i, f)| match f.poll_unpin(cx) {
                    Poll::Pending => true,
                    Poll::Ready(e) => {
                        self.values[*i] = Some(e);
                        false
                    }
                });
            if let Some(next_value) = self.values[self.current_index].take() {
                self.current_index += 1;
                Poll::Ready(Some(next_value))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::ready;

    #[tokio::test]
    async fn test_poll_all_ready() {
        let futures = vec![ready(1), ready(2), ready(3), ready(4), ready(5), ready(6)];
        let mut poll_all = PollAllPreservingOrder::new(futures);
        assert_eq!(poll_all.next().await, Some(1));
        assert_eq!(poll_all.next().await, Some(2));
        assert_eq!(poll_all.next().await, Some(3));
        assert_eq!(poll_all.next().await, Some(4));
        assert_eq!(poll_all.next().await, Some(5));
        assert_eq!(poll_all.next().await, Some(6));
        assert_eq!(poll_all.next().await, None);
    }

    #[tokio::test]
    async fn test_poll_some_pending() {
        // We create a tokio channel to send numbers. The channel broadcasts the messages
        // to all receivers. Then we create six receivers. Each receiver has an associated
        // threshold and a value. The receiver will read from the channel until it receives
        // a number which is at least as big as its threshold. Then it will return the value.
        async fn yield_until_threshold_exceeded(
            mut rx: tokio::sync::broadcast::Receiver<i32>,
            threshold: i32,
            value: i32,
        ) -> i32 {
            loop {
                let msg = rx.recv().await.unwrap();
                if msg >= threshold {
                    return value;
                }
                tokio::task::yield_now().await;
            }
        }
        let (tx, _) = tokio::sync::broadcast::channel(100);
        let receivers = vec![
            yield_until_threshold_exceeded(tx.subscribe(), 6, 1),
            yield_until_threshold_exceeded(tx.subscribe(), 3, 2),
            yield_until_threshold_exceeded(tx.subscribe(), 5, 3),
            yield_until_threshold_exceeded(tx.subscribe(), 1, 4),
            yield_until_threshold_exceeded(tx.subscribe(), 2, 5),
            yield_until_threshold_exceeded(tx.subscribe(), 4, 6),
        ];
        // Feed messages into the channel.
        for x in 0..10 {
            tx.send(x).unwrap();
        }
        // Create the poller and check that it returns the values in the correct order.
        let mut poll_all =
            PollAllPreservingOrder::new(receivers.into_iter().map(Box::pin).collect());
        assert_eq!(poll_all.next().await, Some(1));
        assert_eq!(poll_all.next().await, Some(2));
        assert_eq!(poll_all.next().await, Some(3));
        assert_eq!(poll_all.next().await, Some(4));
        assert_eq!(poll_all.next().await, Some(5));
        assert_eq!(poll_all.next().await, Some(6));
        assert_eq!(poll_all.next().await, None);
    }
}
