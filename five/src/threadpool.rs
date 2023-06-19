use std::thread::{self, JoinHandle};

pub struct Threadpool {
    workers: Vec<Worker>,
}

impl Threadpool {
    pub fn new(num_threads: usize) -> Self {
        let workers = (0..num_threads).map(|_| Worker::new()).collect();
        Threadpool { workers }
    }

    pub fn submit<F, A, B>(&self, f: F)
    where
        F: FnOnce(A) -> B + Send + 'static,
    {
    }
}

struct Worker {
    thread: JoinHandle<()>,
}

impl Worker {
    fn new() -> Self {
        let thread = thread::spawn(|| {});
        Worker { thread }
    }
}
