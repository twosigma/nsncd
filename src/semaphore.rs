/*
 * Copyright 2021 Two Sigma Open Source, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// clippy does a false alarm if you're trying to use a Condvar.
//
// https://rust-lang.github.io/rust-clippy/master/index.html#mutex_atomic
// https://github.com/rust-lang/rust-clippy/issues/1516
#![allow(clippy::mutex_atomic)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A counting semaphore.
///
/// Acquiring a permit returns a scoped RAII Permits that is released when
/// dropped. Permits are Send so they can be passed between threads.
///
/// Semaphores make no guarantee about fairness, and do not issue permits as
/// a first-come-first-serve.
pub(crate) struct Semaphore {
    permits: usize,
    data: Arc<SemData>,
}

struct SemData {
    acquired: Mutex<usize>,
    cond: Condvar,
}

/// An RAII implementation of a Sempahore permit. The Permit is released when
/// this struct goes out of scope.
pub(crate) struct Permit {
    data: Arc<SemData>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut count = self.data.acquired.lock().unwrap();
        *count = count.saturating_sub(1);

        self.data.cond.notify_one();
    }
}

impl Semaphore {
    /// Create a new semaphore with a fixed number of permits.
    ///
    /// Semaphores must have at least one permit. Panics if permits is zero.
    pub fn new(permits: usize) -> Self {
        assert!(permits > 0, "semaphore: can't have 0 permits");
        let data = SemData {
            acquired: Mutex::new(0),
            cond: Condvar::new(),
        };
        Semaphore {
            permits,
            data: Arc::new(data),
        }
    }

    /// Acquire a permit. Returns an error if this call timed out waiting for
    /// a permit to become available.
    pub fn acquire(&self, timeout: Duration) -> Result<Permit, ()> {
        let mut count = self.data.acquired.lock().unwrap();
        if *count >= self.permits {
            let (guard, wait) = self
                .data
                .cond
                .wait_timeout_while(count, timeout, |&mut count| count >= self.permits)
                .unwrap();
            count = guard;

            if wait.timed_out() {
                return Err(());
            }
        }

        *count = count.saturating_add(1);
        Ok(Permit {
            data: self.data.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic(expected = "semaphore: can't have 0 permits")]
    fn panic_on_zero_permits() {
        Semaphore::new(0);
    }

    #[test]
    fn acquire_does_not_block() {
        let sem = Semaphore::new(10);
        let permit = sem.acquire(Duration::from_nanos(1));
        assert!(permit.is_ok());
    }

    #[test]
    fn aquire_blocks() {
        let sem = Semaphore::new(2);
        let p1 = sem.acquire(Duration::from_nanos(1));
        assert!(p1.is_ok());
        let p2 = sem.acquire(Duration::from_nanos(1));
        assert!(p2.is_ok());
        let p3 = sem.acquire(Duration::from_nanos(1));
        assert!(p3.is_err());
    }
}
