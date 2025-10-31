use worker::Env;

#[derive(Clone)]
pub struct WorkerEnv(Env);

impl WorkerEnv {
    pub fn new(env: Env) -> Self {
        WorkerEnv(env)
    }

    pub fn inner(&self) -> &Env {
        &self.0
    }
}

// Implement Send and Sync for WorkerEnv
unsafe impl Send for WorkerEnv {}
unsafe impl Sync for WorkerEnv {}
