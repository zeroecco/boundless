// Taken from https://github.com/risc0/scratch/tree/main/dev/tcarstens/proof-plan/src/planner from tcarstens (thanks!)
pub mod task;

use crate::planner::task::{Command, Task};
use std::{cmp::Ordering, collections::{HashMap, VecDeque}};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlannerErr {
    #[error("Planning not yet started")]
    PlanNotStartedString,
    #[error("Cannot add segment to finished plan")]
    PlanFinalized,
}

/// Balance strategy determines how tasks will be organized when joining
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum BalanceStrategy {
    /// Traditional approach - join equal height trees first
    Traditional,

    /// Breadth-first approach - join tasks as early as possible to reduce height
    #[default]
    BreadthFirst,

    /// Mixed approach - switch strategies based on segment count
    Adaptive,
}
/// Performance factors for task time estimation
#[derive(Clone, Debug)]
pub struct PerformanceFactors {
    /// Base time for segment operations
    pub segment_time: f64,
    /// Base time for keccak operations
    pub keccak_time: f64,
    /// Base time for join operations
    pub join_base_time: f64,
    /// Height factor for join time calculation
    pub join_height_factor: f64,
    /// Base time for union operations
    pub union_base_time: f64,
    /// Height factor for union time calculation
    pub union_height_factor: f64,
    /// Base time for finalize operations
    pub finalize_base_time: f64,
    /// Height factor for finalize time calculation
    pub finalize_height_factor: f64,
    /// Parallelism factor - higher values model more parallel execution
    pub parallelism_factor: f64,
}

impl Default for PerformanceFactors {
    fn default() -> Self {
        Self {
            segment_time: 3.0,
            keccak_time: 2.0,
            join_base_time: 1.0,
            join_height_factor: 1.0,
            union_base_time: 1.0,
            union_height_factor: 1.0,
            finalize_base_time: 1.0,
            finalize_height_factor: 1.0,
            parallelism_factor: 1.0,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Planner {
    /// All of the tasks in this plan
    tasks: Vec<Task>,

    /// List of current "peaks." Sorted in order of decreasing height.
    ///
    /// A task is a "peak" if (1) it is either a Segment or Join command AND (2) no other join tasks depend on it.
    peaks: Vec<usize>,

    /// List of current `keccak_peaks`. Sorted in order of decreasing height.
    ///
    /// A task is a `keccak_peak` if (1) it is either a Keccak Segment or Union command AND (2) no other union tasks depend on it.
    keccak_peaks: VecDeque<usize>,

    /// Iterator position. Used by `self.next_task()`.
    consumer_position: usize,

    /// Last task in the plan. Set by `self.finish()`.
    last_task: Option<usize>,

    /// Whether to use union
    use_union: bool,

    /// Strategy for balancing the tree
    balance_strategy: BalanceStrategy,

    /// Estimated completion times for tasks (in arbitrary units)
    completion_times: HashMap<usize, f64>,

    /// Performance factors to adjust time estimations based on hardware profiles
    performance_factors: PerformanceFactors,

    /// Total number of segments added
    segment_count: usize,
}

impl Planner {
    /// Enable union operations for better task execution
    pub fn use_union(&mut self) {
        self.use_union = true;
    }

    /// Set the strategy for balancing joins
    pub fn set_balance_strategy(&mut self, strategy: BalanceStrategy) {
        self.balance_strategy = strategy;
    }

    /// Set custom performance factors for more accurate time modeling
    pub fn set_performance_factors(&mut self, factors: PerformanceFactors) {
        self.performance_factors = factors;
        // Recalculate all existing completion times with new factors
        self.recalculate_completion_times();
    }

    /// Recalculate all existing task completion times using current performance factors
    fn recalculate_completion_times(&mut self) {
        // Store tasks that need recalculation
        let task_ids: Vec<usize> = (0..self.tasks.len()).collect();

        // Clear existing completion times
        self.completion_times.clear();

        // Recalculate in task number order (ensures dependencies are calculated first)
        for task_id in task_ids {
            let task = &self.tasks[task_id];
            match task.command {
                Command::Segment => {
                    self.completion_times.insert(task_id, self.performance_factors.segment_time);
                },
                Command::Keccak => {
                    self.completion_times.insert(task_id, self.performance_factors.keccak_time);
                },
                Command::Join => {
                    let left = task.depends_on[0];
                    let right = task.depends_on[1];
                    let left_time = self.completion_times.get(&left).copied().unwrap_or(0.0);
                    let right_time = self.completion_times.get(&right).copied().unwrap_or(0.0);

                    // Apply parallelism factor to model concurrent execution
                    let max_dependency_time = if self.performance_factors.parallelism_factor > 1.0 {
                        let parallel_time = (left_time + right_time) / self.performance_factors.parallelism_factor;
                        f64::max(f64::max(left_time, right_time), parallel_time)
                    } else {
                        f64::max(left_time, right_time)
                    };

                    let join_op_time = self.performance_factors.join_base_time +
                        (task.task_height as f64 * self.performance_factors.join_height_factor);

                    self.completion_times.insert(task_id, join_op_time + max_dependency_time);
                },
                Command::Union => {
                    if let Some(left) = task.keccak_depends_on.front().copied() {
                        if let Some(right) = task.keccak_depends_on.get(1).copied() {
                            let left_time = self.completion_times.get(&left).copied().unwrap_or(0.0);
                            let right_time = self.completion_times.get(&right).copied().unwrap_or(0.0);

                            // Apply parallelism factor to model concurrent execution
                            let max_dependency_time = if self.performance_factors.parallelism_factor > 1.0 {
                                let parallel_time = (left_time + right_time) / self.performance_factors.parallelism_factor;
                                f64::max(f64::max(left_time, right_time), parallel_time)
                            } else {
                                f64::max(left_time, right_time)
                            };

                            let union_op_time = self.performance_factors.union_base_time +
                                (task.task_height as f64 * self.performance_factors.union_height_factor);

                            self.completion_times.insert(task_id, union_op_time + max_dependency_time);
                        }
                    }
                },
                Command::Finalize => {
                    let depends_on = task.depends_on[0];
                    let depends_on_time = self.completion_times.get(&depends_on).copied().unwrap_or(0.0);

                    let mut keccak_time = 0.0;
                    for &peak in &task.keccak_depends_on {
                        if let Some(&time) = self.completion_times.get(&peak) {
                            keccak_time = f64::max(keccak_time, time);
                        }
                    }

                    let finalize_op_time = self.performance_factors.finalize_base_time +
                        (task.task_height as f64 * self.performance_factors.finalize_height_factor);

                    // Apply parallelism factor for finalize operation
                    let max_dependency_time = if self.performance_factors.parallelism_factor > 1.0 && keccak_time > 0.0 {
                        let parallel_time = (depends_on_time + keccak_time) / self.performance_factors.parallelism_factor;
                        f64::max(f64::max(depends_on_time, keccak_time), parallel_time)
                    } else {
                        f64::max(depends_on_time, keccak_time)
                    };

                    self.completion_times.insert(task_id, finalize_op_time + max_dependency_time);
                }
            }
        }
    }

    /// Get estimated critical path completion time
    pub fn estimated_completion_time(&self) -> f64 {
        if let Some(last_task) = self.last_task {
            self.completion_times.get(&last_task).copied().unwrap_or(0.0)
        } else if let Some(peak) = self.peaks.first() {
            self.completion_times.get(peak).copied().unwrap_or(0.0)
        } else {
            0.0
        }
    }

    pub fn enqueue_segment(&mut self) -> Result<usize, PlannerErr> {
        if self.last_task.is_some() {
            return Err(PlannerErr::PlanFinalized);
        }

        let task_number = self.next_task_number();
        self.tasks.push(Task::new_segment(task_number));
        self.completion_times.insert(task_number, self.performance_factors.segment_time);
        self.segment_count += 1;

        // Determine if we should switch strategies based on segment count
        if self.balance_strategy == BalanceStrategy::Adaptive {
            // Switch to breadth-first for large segment counts (>40)
            let effective_strategy = if self.segment_count > 40 {
                BalanceStrategy::BreadthFirst
            } else {
                BalanceStrategy::Traditional
            };
            self.join_segment_with_strategy(task_number, effective_strategy)
        } else {
            // Use the configured strategy
            self.join_segment_with_strategy(task_number, self.balance_strategy)
        }
    }

    fn join_segment_with_strategy(&mut self, task_number: usize, strategy: BalanceStrategy) -> Result<usize, PlannerErr> {
        let mut new_peak = task_number;

        match strategy {
            BalanceStrategy::Traditional => {
                // Traditional approach - build balanced binary tree
                while let Some(smallest_peak) = self.peaks.last().copied() {
                    let new_height = self.get_task(new_peak).task_height;
                    let smallest_peak_height = self.get_task(smallest_peak).task_height;
                    match new_height.cmp(&smallest_peak_height) {
                        Ordering::Less => break,
                        Ordering::Equal => {
                            self.peaks.pop();
                            new_peak = self.enqueue_join(smallest_peak, new_peak);
                        }
                        Ordering::Greater => unreachable!(),
                    }
                }
            },
            BalanceStrategy::BreadthFirst | BalanceStrategy::Adaptive => {
                // Breadth-first approach - try to join with lowest available peak first
                // This creates wider, less tall trees which can improve parallelism
                if !self.peaks.is_empty() {
                    // Find peak with lowest completion time (roughly corresponds to task complexity)
                    let mut best_peak_idx = self.peaks.len() - 1;
                    let mut best_time = f64::MAX;

                    for (i, &peak) in self.peaks.iter().enumerate() {
                        if let Some(&completion_time) = self.completion_times.get(&peak) {
                            if completion_time < best_time {
                                best_time = completion_time;
                                best_peak_idx = i;
                            }
                        }
                    }

                    // Join with the best peak
                    let join_with = self.peaks.remove(best_peak_idx);
                    new_peak = self.enqueue_join(join_with, new_peak);
                }
            }
        }

        self.peaks.push(new_peak);
        Ok(task_number)
    }

    pub fn enqueue_keccak(&mut self) -> Result<usize, PlannerErr> {
        if self.last_task.is_some() {
            return Err(PlannerErr::PlanFinalized);
        }

        let task_number = self.next_task_number();
        self.tasks.push(Task::new_keccak(task_number));
        self.completion_times.insert(task_number, self.performance_factors.keccak_time);

        let mut new_peak = task_number;
        if self.use_union {
            // Improved union strategy for keccak operations
            // We'll use a similar breadth-first approach to join keccak tasks when possible
            if self.balance_strategy == BalanceStrategy::BreadthFirst ||
               (self.balance_strategy == BalanceStrategy::Adaptive && self.segment_count > 40) {
                // Try to find the keccak task with minimum completion time
                if !self.keccak_peaks.is_empty() {
                    let mut min_time = f64::MAX;
                    let mut min_idx = 0;

                    for (i, &peak) in self.keccak_peaks.iter().enumerate() {
                        if let Some(&time) = self.completion_times.get(&peak) {
                            if time < min_time {
                                min_time = time;
                                min_idx = i;
                            }
                        }
                    }

                    let other_peak = self.keccak_peaks.remove(min_idx).unwrap();
                    new_peak = self.enqueue_union(other_peak, new_peak);
                }

                self.keccak_peaks.push_back(new_peak);
            } else {
                // Traditional approach - balance based on height
                while let Some(smallest_peak) = self.keccak_peaks.back().copied() {
                    let new_height = self.get_task(new_peak).task_height;
                    let smallest_peak_height = self.get_task(smallest_peak).task_height;
                    match new_height.cmp(&smallest_peak_height) {
                        Ordering::Less => break,
                        Ordering::Equal => {
                            self.keccak_peaks.pop_back();
                            new_peak = self.enqueue_union(smallest_peak, new_peak);
                        }
                        Ordering::Greater => unreachable!(),
                    }
                }
                self.keccak_peaks.push_back(new_peak);
            }
        } else {
            self.keccak_peaks.push_front(task_number);
        }

        Ok(task_number)
    }

    fn finish_unions(&mut self) -> Option<VecDeque<usize>> {
        // This assumes there's always a minimum of 1 segment
        if self.keccak_peaks.is_empty() {
            return None;
        }

        // Join remaining peaks if using union
        // Use a breadth-first approach for unioning remaining peaks
        // to minimize the overall tree height
        if 2 <= self.keccak_peaks.len() && self.use_union {
            let mut peaks: Vec<_> = self.keccak_peaks.drain(..).collect();

            // Sort peaks by estimated completion time to join faster tasks first
            peaks.sort_by(|&a, &b| {
                let time_a = self.completion_times.get(&a).copied().unwrap_or(0.0);
                let time_b = self.completion_times.get(&b).copied().unwrap_or(0.0);
                time_a.partial_cmp(&time_b).unwrap()
            });

            // Join peaks in a balanced way
            while peaks.len() >= 2 {
                let mut new_peaks = Vec::new();

                // Process pairs of peaks
                for chunk in peaks.chunks(2) {
                    if chunk.len() == 2 {
                        let left = chunk[0];
                        let right = chunk[1];
                        let union_peak = self.enqueue_union(left, right);
                        new_peaks.push(union_peak);
                    } else {
                        // Add remaining odd peak
                        new_peaks.push(chunk[0]);
                    }
                }

                peaks = new_peaks;
            }

            // Add the final peak back to keccak_peaks
            self.keccak_peaks.extend(peaks);
        }

        // Return only highest peak
        Some(VecDeque::from([self.keccak_peaks[0]]))
    }

    pub fn finish(&mut self) -> Result<usize, PlannerErr> {
        // Finish unions first
        let keccak_depends_on = if self.use_union {
            self.finish_unions()
        } else {
            Some(self.keccak_peaks.clone())
        };

        // Return error if plan has not yet started
        if self.peaks.is_empty() {
            return Err(PlannerErr::PlanNotStartedString);
        }

        // Finish the plan (if it's not yet finished)
        if self.last_task.is_none() {
            // Use a better strategy for joining remaining peaks
            // to create a more balanced join tree
            if self.peaks.len() >= 2 {
                let mut peaks: Vec<_> = self.peaks.drain(..).collect();

                // Sort peaks by estimated completion time
                peaks.sort_by(|&a, &b| {
                    let time_a = self.completion_times.get(&a).copied().unwrap_or(0.0);
                    let time_b = self.completion_times.get(&b).copied().unwrap_or(0.0);
                    time_a.partial_cmp(&time_b).unwrap()
                });

                // Join peaks in pairs to create a balanced tree
                while peaks.len() >= 2 {
                    let mut new_peaks = Vec::new();

                    // Process pairs of peaks
                    for chunk in peaks.chunks(2) {
                        if chunk.len() == 2 {
                            let left = chunk[0];
                            let right = chunk[1];
                            let join_peak = self.enqueue_join(left, right);
                            new_peaks.push(join_peak);
                        } else {
                            // Add remaining odd peak
                            new_peaks.push(chunk[0]);
                        }
                    }

                    peaks = new_peaks;
                }

                // Add the final peak back to self.peaks
                self.peaks.extend(peaks);
            }

            // Add the Finalize task
            self.last_task = Some(self.enqueue_finalize(self.peaks[0], keccak_depends_on));
        }

        Ok(self.last_task.unwrap())
    }

    #[must_use]
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    #[must_use]
    pub fn get_task(&self, task_number: usize) -> &Task {
        if task_number < self.tasks.len() {
            &self.tasks[task_number]
        } else {
            panic!("Invalid task number {task_number}");
        }
    }

    pub fn next_task(&mut self) -> Option<&Task> {
        if self.consumer_position < self.task_count() {
            let out = &self.tasks[self.consumer_position];
            self.consumer_position += 1;
            Some(out)
        } else {
            None
        }
    }

    fn enqueue_join(&mut self, left: usize, right: usize) -> usize {
        let task_number = self.next_task_number();

        // Calculate the task height based on input task heights
        let task_height = 1 + u32::max(
            self.get_task(left).task_height,
            self.get_task(right).task_height,
        );

        self.tasks.push(Task::new_join(task_number, task_height, left, right));

        // Calculate estimated completion time based on dependency completion times
        let left_time = self.completion_times.get(&left).copied().unwrap_or(0.0);
        let right_time = self.completion_times.get(&right).copied().unwrap_or(0.0);

        // Join time is max of input times plus join operation time
        // We use a sliding scale based on height to model real-world performance
        let join_op_time = self.performance_factors.join_base_time +
            (task_height as f64 * self.performance_factors.join_height_factor);

        // Apply parallelism factor to model concurrent execution when possible
        let max_dependency_time = if self.performance_factors.parallelism_factor > 1.0 {
            let parallel_time = (left_time + right_time) / self.performance_factors.parallelism_factor;
            f64::max(f64::max(left_time, right_time), parallel_time)
        } else {
            f64::max(left_time, right_time)
        };

        let completion_time = join_op_time + max_dependency_time;

        self.completion_times.insert(task_number, completion_time);
        task_number
    }

    fn enqueue_union(&mut self, left: usize, right: usize) -> usize {
        let task_number = self.next_task_number();
        let task_height = 1 + u32::max(
            self.get_task(left).task_height,
            self.get_task(right).task_height,
        );

        self.tasks.push(Task::new_union(task_number, task_height, left, right));

        // Calculate estimated completion time for union
        let left_time = self.completion_times.get(&left).copied().unwrap_or(0.0);
        let right_time = self.completion_times.get(&right).copied().unwrap_or(0.0);

        // Union operations are typically more expensive than joins
        let union_op_time = self.performance_factors.union_base_time +
            (task_height as f64 * self.performance_factors.union_height_factor);

        // Apply parallelism factor to model concurrent execution
        let max_dependency_time = if self.performance_factors.parallelism_factor > 1.0 {
            let parallel_time = (left_time + right_time) / self.performance_factors.parallelism_factor;
            f64::max(f64::max(left_time, right_time), parallel_time)
        } else {
            f64::max(left_time, right_time)
        };

        let completion_time = union_op_time + max_dependency_time;

        self.completion_times.insert(task_number, completion_time);
        task_number
    }

    fn enqueue_finalize(
        &mut self,
        depends_on: usize,
        keccak_depends_on: Option<VecDeque<usize>>,
    ) -> usize {
        let task_number = self.next_task_number();
        let mut task_height = 1 + self.get_task(depends_on).task_height;

        // Track keccak dependencies for finalize operation
        let mut keccak_time = 0.0;

        if let Some(val) = &keccak_depends_on {
            // Update task height based on keccak dependencies
            if let Some(highest_peak) = val.iter().max().copied() {
                task_height = task_height.max(1 + self.get_task(highest_peak).task_height);

                // Find max completion time among keccak dependencies
                for &peak in val.iter() {
                    if let Some(&time) = self.completion_times.get(&peak) {
                        keccak_time = f64::max(keccak_time, time);
                    }
                }
            }
        }

        self.tasks.push(Task::new_finalize(
            task_number,
            task_height,
            depends_on,
            keccak_depends_on,
        ));

        // Calculate finalize completion time
        let depends_on_time = self.completion_times.get(&depends_on).copied().unwrap_or(0.0);
        let finalize_op_time = self.performance_factors.finalize_base_time +
            (task_height as f64 * self.performance_factors.finalize_height_factor);

        // Apply parallelism factor for finalize operation
        let max_dependency_time = if self.performance_factors.parallelism_factor > 1.0 && keccak_time > 0.0 {
            let parallel_time = (depends_on_time + keccak_time) / self.performance_factors.parallelism_factor;
            f64::max(f64::max(depends_on_time, keccak_time), parallel_time)
        } else {
            f64::max(depends_on_time, keccak_time)
        };

        // Finalize time is max of dependencies plus finalize operation time
        let completion_time = finalize_op_time + max_dependency_time;

        self.completion_times.insert(task_number, completion_time);
        task_number
    }

    fn next_task_number(&self) -> usize {
        self.task_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_plan() {
        let mut planner = Planner::default();
        // Use traditional balance strategy for consistent test behavior
        planner.set_balance_strategy(BalanceStrategy::Traditional);

        let numb = planner.enqueue_segment().unwrap();
        assert_eq!(numb, 0);
        let task = planner.next_task().unwrap();
        assert_eq!(task.keccak_depends_on.len(), 0);
        assert_eq!(task.depends_on.len(), 0);
        assert_eq!(task.command, Command::Segment);
        assert_eq!(task.task_number, 0);
        assert!(planner.next_task().is_none());

        let numb = planner.enqueue_keccak().unwrap();
        let task = planner.next_task().unwrap();
        assert_eq!(numb, 1);
        assert_eq!(task.keccak_depends_on.len(), 0);
        assert_eq!(task.depends_on.len(), 0);
        assert_eq!(task.command, Command::Keccak);
        assert_eq!(task.task_number, 1);
        assert!(planner.next_task().is_none());

        planner.finish().unwrap();
        let task = planner.next_task().unwrap();
        assert_eq!(task.command, Command::Finalize);
        assert_eq!(task.keccak_depends_on.len(), 1);
        assert_eq!(task.task_number, 2);
        assert_eq!(task.depends_on.len(), 1);
        assert_eq!(task.task_height, 1);

        assert_eq!(planner.task_count(), 3);
        assert_eq!(planner.get_task(0).task_number, 0);

        // Check that completion times are properly calculated
        assert!(planner.estimated_completion_time() > 0.0);
    }

    #[test]
    fn test_balanced() {
        let mut planner = Planner::default();
        planner.use_union();
        planner.set_balance_strategy(BalanceStrategy::Traditional);

        planner.enqueue_segment().unwrap();
        {
            let task = planner.next_task().unwrap();
            assert_eq!(task.command, Command::Segment);
            assert_eq!(task.task_number, 0);
            assert_eq!(task.task_height, 0);
            assert!(planner.next_task().is_none());
        }

        planner.enqueue_keccak().unwrap();
        {
            let task = planner.next_task().unwrap();
            assert_eq!(task.command, Command::Keccak);
            assert_eq!(task.task_number, 1);
            assert_eq!(task.task_height, 0);
        }

        planner.enqueue_segment().unwrap();
        {
            let task = planner.next_task().unwrap();
            assert_eq!(task.command, Command::Segment);
            assert_eq!(task.task_number, 2);
            assert_eq!(task.task_height, 0);
            assert_eq!(task.depends_on.len(), 0);
        }
        {
            let join = planner.next_task().unwrap();
            assert_eq!(join.command, Command::Join);
            assert_eq!(join.task_number, 3);
            assert_eq!(join.task_height, 1);
            assert_eq!(join.depends_on.len(), 2);
        }

        planner.enqueue_keccak().unwrap();
        {
            let task = planner.next_task().unwrap();
            assert_eq!(task.command, Command::Keccak);
            assert_eq!(task.task_number, 4);
            assert_eq!(task.task_height, 0);
        }
        {
            let union = planner.next_task().unwrap();
            assert_eq!(union.command, Command::Union);
            assert_eq!(union.task_number, 5);
            assert_eq!(union.task_height, 1);
            assert_eq!(union.keccak_depends_on.len(), 2);
        }

        planner.finish().unwrap();
        let keccak_last_task = planner.next_task().unwrap();
        assert_eq!(keccak_last_task.command, Command::Finalize);
        assert_eq!(keccak_last_task.task_number, 6);
        assert_eq!(keccak_last_task.task_height, 2);
        assert_eq!(keccak_last_task.depends_on.len(), 1);
        assert_eq!(keccak_last_task.keccak_depends_on.len(), 1);
    }

    #[test]
    fn test_unbalanced_keccak() {
        let mut planner = Planner::default();
        planner.use_union();
        planner.set_balance_strategy(BalanceStrategy::Traditional);

        planner.enqueue_keccak().unwrap();
        planner.enqueue_keccak().unwrap();
        planner.enqueue_keccak().unwrap();
        planner.enqueue_segment().unwrap();
        planner.finish().unwrap();

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 0);
        assert_eq!(task.command, Command::Keccak);
        assert_eq!(task.task_height, 0);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 1);
        assert_eq!(task.command, Command::Keccak);
        assert_eq!(task.task_height, 0);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 2);
        assert_eq!(task.command, Command::Union);
        assert_eq!(task.task_height, 1);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 3);
        assert_eq!(task.command, Command::Keccak);
        assert_eq!(task.task_height, 0);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 4);
        assert_eq!(task.command, Command::Segment);
        assert_eq!(task.task_height, 0);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 5);
        assert_eq!(task.command, Command::Union);
        assert_eq!(task.task_height, 2);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 6);
        assert_eq!(task.command, Command::Finalize);
        assert_eq!(task.task_height, 3);

        // Check that completion time estimate is available
        assert!(planner.estimated_completion_time() > 0.0);
    }

    #[test]
    fn test_unbalanced() {
        let mut planner = Planner::default();
        planner.set_balance_strategy(BalanceStrategy::Traditional);

        planner.enqueue_segment().unwrap();
        planner.enqueue_segment().unwrap();
        planner.enqueue_segment().unwrap();

        planner.finish().unwrap();

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 0);
        assert_eq!(task.command, Command::Segment);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 1);
        assert_eq!(task.command, Command::Segment);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 2);
        assert_eq!(task.command, Command::Join);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 3);
        assert_eq!(task.command, Command::Segment);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 4);
        assert_eq!(task.command, Command::Join);

        let task = planner.next_task().unwrap();
        assert_eq!(task.task_number, 5);
        assert_eq!(task.command, Command::Finalize);
        assert_eq!(task.task_height, 3);
    }

    #[test]
    fn test_breadth_first_strategy() {
        let mut planner = Planner::default();
        planner.set_balance_strategy(BalanceStrategy::BreadthFirst);

        // Add several segments to test breadth-first joining
        for _ in 0..8 {
            planner.enqueue_segment().unwrap();
        }

        planner.finish().unwrap();

        // Reset consumer position to read all tasks
        planner.consumer_position = 0;

        // First gather all tasks
        let mut tasks = Vec::new();
        while let Some(task) = planner.next_task() {
            tasks.push(task.clone());
        }

        // Find the finalize task
        let finalize_task = tasks.iter().find(|t| matches!(t.command, Command::Finalize)).unwrap();

        // In breadth-first, total tree height should be lower
        assert!(finalize_task.task_height <= 4,
                "Breadth-first strategy should have lower tree height, got {}",
                finalize_task.task_height);
    }

    #[test]
    fn test_adaptive_strategy() {
        let mut planner = Planner::default();
        planner.set_balance_strategy(BalanceStrategy::Adaptive);

        // Add segments to test adaptive joining
        for _ in 0..60 {
            planner.enqueue_segment().unwrap();
        }

        planner.finish().unwrap();

        // Verify that completion time is reasonable
        let completion_time = planner.estimated_completion_time();
        assert!(completion_time > 0.0, "Completion time should be positive");

        // Get the finalize task
        let finalize_task = planner.get_task(planner.last_task.unwrap());

        // In adaptive strategy with many segments, the tree should be relatively balanced
        println!("Adaptive strategy with 60 segments produced task height: {}",
                 finalize_task.task_height);
    }

    #[test]
    #[should_panic(expected = "PlanNotStartedString")]
    fn err_not_started() {
        let mut planner = Planner::default();
        planner.finish().unwrap();
    }

    #[test]
    #[should_panic(expected = "PlanFinalized")]
    fn err_finalized() {
        let mut planner = Planner::default();
        planner.enqueue_segment().unwrap();
        planner.finish().unwrap();
        planner.enqueue_segment().unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid task number 100")]
    fn err_bad_task_numb() {
        let planner = Planner::default();
        let _ = planner.get_task(100);
    }
}
