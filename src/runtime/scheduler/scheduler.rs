// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of our efficient, single-threaded task scheduler.
//!
//! Our scheduler uses a pinned memory slab to store tasks ([SchedulerFuture]s).
//! As background tasks are polled, they notify task in our scheduler via the
//! [crate::page::WakerPage]s.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::runtime::{
    scheduler::{group::TaskGroup, Task},
    SharedObject,
};
use ::slab::Slab;
use ::std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

//======================================================================================================================
// Structures
//======================================================================================================================

#[derive(Default)]
pub struct Scheduler {
    // A list of groups. We just use direct mapping for identifying these because they are never externalized.
    groups: Slab<TaskGroup>,
}

/// Internal ids used by the scheduler. These should NEVER be exposed to the application without first going through
/// the runtime.
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct SchedulerId(pub usize);

#[derive(Clone, Default)]
pub struct SharedScheduler(SharedObject<Scheduler>);

/// Possible outcomes for scheduling a task.
#[derive(Debug)]
pub enum ScheduleResult {
    Scheduled(SchedulerId),
    Completed(Box<dyn Task>),
}

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl Scheduler {
    pub fn create_group(&mut self) -> SchedulerId {
        self.groups.insert(TaskGroup::default()).into()
    }

    fn get_group_mut(&mut self, id: SchedulerId) -> Option<&mut TaskGroup> {
        self.groups.get_mut(id.into())
    }

    pub fn schedule<T: Task>(&mut self, group_id: SchedulerId, task: T) -> Option<ScheduleResult> {
        self.get_group_mut(group_id)?.schedule(Box::new(task))
    }

    pub fn get_task_mut(&mut self, group_id: SchedulerId, task_id: SchedulerId) -> Option<Pin<&mut Box<dyn Task>>> {
        self.get_group_mut(group_id)?.get_task_mut(task_id.into())
    }

    /// Do not use this function on coroutines that use poll_yield, unless limit is set.
    pub fn run(&mut self, id: SchedulerId, limit: Option<usize>) -> Vec<Box<dyn Task>> {
        let group = self.get_group_mut(id).expect("group missing");
        group.run(limit, true)
    }

    pub fn run_once(&mut self, id: SchedulerId, limit: Option<usize>) -> Vec<Box<dyn Task>> {
        let group = self.get_group_mut(id).expect("group missing");
        group.run(limit, false)
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Deref for SharedScheduler {
    type Target = Scheduler;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SharedScheduler {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl From<usize> for SchedulerId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl From<SchedulerId> for usize {
    fn from(value: SchedulerId) -> Self {
        value.0
    }
}

impl From<u64> for SchedulerId {
    fn from(value: u64) -> Self {
        Self(value as usize)
    }
}

impl From<SchedulerId> for u64 {
    fn from(value: SchedulerId) -> Self {
        value.0 as u64
    }
}

//======================================================================================================================
// Unit Tests
//======================================================================================================================

#[cfg(test)]
mod tests {
    use crate::runtime::scheduler::{
        scheduler::{ScheduleResult, Scheduler, SchedulerId},
        task::TaskWithResult,
    };
    use ::anyhow::Result;
    use ::futures::FutureExt;
    use ::std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };
    use ::test::{black_box, Bencher};

    #[derive(Default)]
    struct DummyCoroutine {
        pub val: usize,
    }

    impl DummyCoroutine {
        pub fn new(val: usize) -> Self {
            Self { val }
        }
    }
    impl Future for DummyCoroutine {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
            match self.as_ref().val {
                0 => Poll::Ready(()),
                _ => {
                    self.get_mut().val -= 1;
                    let waker = context.waker();
                    waker.wake_by_ref();
                    Poll::Pending
                },
            }
        }
    }

    type DummyTask = TaskWithResult<()>;

    #[test]
    fn run_group_with_one_small_task_completes_it() -> Result<()> {
        let mut scheduler = Scheduler::default();
        let group_id = scheduler.create_group();

        // Schedule a single future in the scheduler. This future shall complete with a single poll operation.
        let task = DummyTask::new("testing", Box::pin(DummyCoroutine::new(1).fuse()));
        let Some(ScheduleResult::Scheduled(_)) = scheduler.schedule(group_id, task) else {
            anyhow::bail!("schedule() failed")
        };

        // All futures are scheduled in the scheduler with notification flag set.
        // By polling once, our future should complete.
        if scheduler.run_once(group_id, None).pop().is_none() {
            anyhow::bail!("task should have completed")
        }

        Ok(())
    }

    #[test]
    fn run_group_twice_with_one_long_task_completes_it() -> Result<()> {
        let mut scheduler = Scheduler::default();
        let group_id = scheduler.create_group();

        // Schedule a single future in the scheduler. This future shall complete
        // with two poll operations.
        let task = DummyTask::new("testing", Box::pin(DummyCoroutine::new(2).fuse()));
        let Some(ScheduleResult::Scheduled(_)) = scheduler.schedule(group_id, task) else {
            anyhow::bail!("schedule() failed")
        };

        // All futures are scheduled in the scheduler with notification flag set.
        // By polling once, this future should make a transition.
        let result = scheduler.run_once(group_id, None).pop();
        crate::ensure_eq!(result.is_some(), false);

        // This shall make the future ready.
        if scheduler.run_once(group_id, None).pop().is_none() {
            anyhow::bail!("task should have completed");
        }

        Ok(())
    }

    #[test]
    fn run_until_unrunnable_with_one_long_task_completes_it() -> Result<()> {
        let mut scheduler = Scheduler::default();
        let group_id = scheduler.create_group();

        // Schedule a single future in the scheduler. This future shall complete with a single poll operation.
        let task = DummyTask::new("testing", Box::pin(DummyCoroutine::new(1).fuse()));
        let Some(ScheduleResult::Scheduled(_)) = scheduler.schedule(group_id, task) else {
            anyhow::bail!("schedule() failed")
        };

        // All futures are scheduled in the scheduler with notification flag set.
        // By polling until the task completes, our future should complete.
        if scheduler.run(group_id, None).pop().is_none() {
            anyhow::bail!("task should have completed")
        }

        Ok(())
    }

    #[bench]
    fn schedule_bench(b: &mut Bencher) {
        let mut scheduler = Scheduler::default();
        let group_id = scheduler.create_group();

        b.iter(|| {
            let task = DummyTask::new("testing", Box::pin(black_box(DummyCoroutine::new(1).fuse())));
            let Some(ScheduleResult::Scheduled(task_id)) = scheduler.schedule(group_id, task) else {
                panic!("couldn't schedule future in scheduler");
            };
            black_box(task_id);
        });
    }

    #[bench]
    fn benchmark_run_one_task_at_a_time(b: &mut Bencher) {
        let mut scheduler = Scheduler::default();
        let group_id = scheduler.create_group();

        const NUM_TASKS: usize = 1024;
        let mut task_ids = Vec::<SchedulerId>::with_capacity(NUM_TASKS);

        for val in 1..NUM_TASKS {
            let task = DummyTask::new("testing", Box::pin(DummyCoroutine::new(val).fuse()));
            match scheduler.schedule(group_id, task) {
                Some(ScheduleResult::Completed(_)) => panic!("task should not have completed"),
                Some(ScheduleResult::Scheduled(task_id)) => task_ids.push(task_id),
                None => panic!("schedule() failed"),
            };
        }

        b.iter(|| {
            black_box(scheduler.run_once(group_id, None));
        });
    }

    #[bench]
    fn run_many_tasks_until_done_bench(b: &mut Bencher) {
        let mut scheduler = Scheduler::default();
        let group_id = scheduler.create_group();

        const NUM_TASKS: usize = 8;
        let mut task_ids = Vec::<SchedulerId>::with_capacity(NUM_TASKS);

        for val in 1..NUM_TASKS {
            let task = DummyTask::new("testing", Box::pin(DummyCoroutine::new(val).fuse()));
            match scheduler.schedule(group_id, task) {
                Some(ScheduleResult::Completed(_)) => panic!("task should not have completed"),
                Some(ScheduleResult::Scheduled(task_id)) => task_ids.push(task_id),
                None => panic!("schedule() failed"),
            };
        }

        b.iter(|| {
            black_box(scheduler.run(group_id, None));
        });
    }
}
