/*
 * Copyright 2021-2023 Two Sigma Open Source, LLC
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

use std::any::Any;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

pub struct WorkGroup {
    fs: Vec<Box<dyn FnOnce(Context) + Send + 'static>>,
    data: Arc<(Mutex<Option<usize>>, Condvar)>,
}

pub struct Context {
    thread: usize,
    data: Arc<(Mutex<Option<usize>>, Condvar)>,
}

impl Context {
    pub fn is_shutdown(&self) -> bool {
        let (m, _) = &*self.data;
        m.lock().unwrap().is_some()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let (mtx, cond) = &*self.data;
        mtx.lock().unwrap().get_or_insert(self.thread);

        cond.notify_all();
    }
}

impl WorkGroup {
    pub fn new() -> WorkGroup {
        let fs = vec![];
        let data = Arc::new((Mutex::new(None), Condvar::new()));

        WorkGroup { fs, data }
    }

    pub fn add<F>(&mut self, f: F)
    where
        F: FnOnce(Context),
        F: Send + 'static,
    {
        self.fs.push(Box::new(f));
    }

    // Box<dyn Any + Send + 'static> is how the stdlib defines JoinHandle panic
    // data, so that's what we're doing too.
    #[allow(clippy::type_complexity)]
    pub fn run(
        self,
    ) -> (
        Result<(), Box<dyn Any + Send + 'static>>,
        Vec<JoinHandle<()>>,
    ) {
        let mut handles = vec![];

        for f in self.fs {
            let data = self.data.clone();
            let thread = handles.len();
            handles.push(thread::spawn(move || {
                let context = Context { thread, data };
                f(context);
            }));
        }

        // wait for the first thread to exit.
        let (mtx, cond) = &*self.data;
        let mut data = mtx.lock().unwrap();
        while !data.is_some() {
            data = cond.wait(data).unwrap();
        }

        // pull the result out of the JoinHandle of the thread that exited first
        // and then join on the rest so that we wait on them to exit.
        let result = handles.remove(data.unwrap()).join();
        (result, handles)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_run_one() {
        let state = Arc::new(AtomicUsize::new(123));

        let mut wg = WorkGroup::new();

        let state_ref = state.clone();
        wg.add(move |_| {
            state_ref.store(456, Ordering::SeqCst);
        });

        let (result, handles) = wg.run();
        assert!(result.is_ok());
        assert!(handles.is_empty());
        assert_eq!(state.load(Ordering::SeqCst), 456);
    }

    #[test]
    fn test_run_multiple() {
        let state = Arc::new(AtomicUsize::new(0));

        let mut wg = WorkGroup::new();

        for _ in 0..10 {
            let state_ref = state.clone();
            wg.add(move |_| {
                state_ref.fetch_add(1, Ordering::SeqCst);
            });
        }

        let (result, handles) = wg.run();
        assert!(result.is_ok());
        assert!(!handles.is_empty());
        for handle in handles {
            let _ = handle.join();
        }
        assert_eq!(state.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn test_run_panic() {
        let mut wg = WorkGroup::new();

        for _ in 0..10 {
            wg.add(move |_| {
                thread::sleep(Duration::from_secs(300));
            });
        }
        wg.add(move |_| {
            panic!("hello");
        });

        let (result, _) = wg.run();
        assert!(result.is_err());
        assert_eq!(
            result
                .err()
                .and_then(|data| data.downcast_ref::<&'static str>().map(|s| *s == "hello")),
            Some(true)
        );
    }
}
