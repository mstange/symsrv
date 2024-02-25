use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Mutex;

use futures_util::{future, FutureExt};

/// Keeps track of inflight computations and reuses them if another computation with
/// the same arguments is requested while the first one is still running.
pub struct ComputationCoalescer<Args, Fut: Future> {
    weak_map: Mutex<WeakSharedFutureMap<Args, Fut>>,
}

impl<Args, Fut> ComputationCoalescer<Args, Fut>
where
    Args: Eq + PartialEq + Hash + Clone,
    Fut: Future,
    Fut::Output: Clone,
{
    pub fn new() -> Self {
        Self {
            weak_map: Mutex::new(WeakSharedFutureMap::new()),
        }
    }

    /// Start a new computation or wait for a currently-running computation with
    /// the same arguments to finish.
    ///
    /// If no computation with the same arguments is currently running,
    /// `compute_callback` is called to start a new computation.
    /// If a computation with the same arguments is currently running,
    /// `compute_callback` is *not* called and this function waits for the
    /// existing computation to finish and returns its result.
    ///
    /// `compute_callback` must not do any slow work synchronously; we call it while a
    /// mutex is locked. The actual work should be asynchronous, so that it
    /// starts only once this function awaits the returned future.
    pub fn subscribe_or_compute<'a>(
        &'a self,
        args: &'a Args,
        compute_callback: impl FnOnce() -> Fut,
    ) -> impl Future<Output = Fut::Output> + 'a {
        let future = {
            // Find an existing future or create a new one.
            let mut weak_map = self.weak_map.lock().unwrap();
            if let Some(shared_future) = weak_map.get(args) {
                shared_future
            } else {
                // No existing future, call the callback.
                let future = compute_callback();

                // Turn it into a shared future and store a weak reference to it.
                let shared_future = future.shared();
                weak_map.insert(args.clone(), &shared_future);
                shared_future
            }
        };
        let remover = scopeguard::guard((), |_| {
            // Make sure that our map doesn't accumulate too many old entries
            // for futures which have already completed or which have been canceled.
            // With a scopeguard we can handle both completion and cancellation.
            let mut weak_map = self.weak_map.lock().unwrap();
            weak_map.remove_if_done(args);
        });

        async move {
            // Make sure the `remover` scopeguard is moved into this future.
            let _remover = remover;

            future.await
        }
    }
}

struct WeakSharedFutureMap<Args, Fut: Future> {
    map: HashMap<Args, future::WeakShared<Fut>>,
}

impl<Args: Eq + PartialEq + Hash, Fut: Future> WeakSharedFutureMap<Args, Fut> {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn insert(&mut self, args: Args, future: &future::Shared<Fut>) {
        if let Some(weak) = future.downgrade() {
            self.map.insert(args, weak);
        }
    }

    fn get(&mut self, args: &Args) -> Option<future::Shared<Fut>> {
        let strong = self.map.get(args)?.upgrade();
        if strong.is_none() {
            self.map.remove(args);
        }
        strong
    }

    fn remove_if_done(&mut self, args: &Args) {
        self.get(args);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::ready;

    #[tokio::test]
    async fn test_coalescer() {
        let coalescer = ComputationCoalescer::new();
        let future1 = coalescer.subscribe_or_compute(&"key", || ready(1));
        let future2 = coalescer.subscribe_or_compute(&"key", || ready(2));
        let result1 = future1.await;
        let result2 = future2.await;
        assert_eq!(result1, 1);
        assert_eq!(result2, 1);
    }
}
