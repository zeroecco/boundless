use std::collections::VecDeque;

/// Command types supported by the planner
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Keccak hash computation
    Keccak,
    /// Finalize operation that wraps up proof generation
    Finalize,
    /// Join operation that combines two segments
    Join,
    /// Segment operation for individual proof segments
    Segment,
    /// Union operation that combines keccak operations
    Union,
}

/// Priority level for task execution ordering
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Default)]
pub enum Priority {
    /// Critical priority - execute as soon as possible
    Critical = 0,
    /// High priority - execute before normal tasks
    High = 1,
    /// Normal priority - standard execution
    #[default]
    Normal = 2,
    /// Low priority - can be delayed if needed
    Low = 3,
}

/// Task structure representing a unit of work in the planner
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Task {
    /// Unique identifier for this task
    pub task_number: usize,

    /// Height of this task in the dependency tree
    pub task_height: u32,

    /// The type of command this task represents
    pub command: Command,

    /// Tasks this task depends on for join/finalize operations
    pub depends_on: Vec<usize>,

    /// Tasks this task depends on for keccak operations
    pub keccak_depends_on: VecDeque<usize>,

    /// Execution priority for this task (used for scheduling)
    pub priority: Priority,
}

impl Task {
    /// Determine optimal priority for a task based on its command and height
    fn optimal_priority(command: &Command, task_height: u32) -> Priority {
        match command {
            // Finalize is always critical
            Command::Finalize => Priority::Critical,

            // Joins at lower heights are more critical since they unlock
            // more potential parallelism when completed
            Command::Join => {
                if task_height <= 1 {
                    Priority::Critical // Prioritize bottom-level joins to maximize parallelism
                } else if task_height <= 3 {
                    Priority::High
                } else if task_height <= 5 {
                    Priority::Normal
                } else {
                    Priority::Low
                }
            }

            // Segments are high priority because they're needed for joins
            Command::Segment => Priority::High,

            // Unions at lower heights are more critical
            Command::Union => {
                if task_height <= 1 {
                    Priority::Critical // Prioritize bottom-level unions
                } else if task_height <= 3 {
                    Priority::High
                } else {
                    Priority::Normal
                }
            }

            // Keccak operations can be executed in parallel with segment operations
            Command::Keccak => Priority::High,
        }
    }

    #[must_use]
    pub fn new_segment(task_number: usize) -> Self {
        Task {
            task_number,
            task_height: 0,
            command: Command::Segment,
            depends_on: Vec::new(),
            keccak_depends_on: VecDeque::new(),
            priority: Priority::High, // Segments are high priority
        }
    }

    #[must_use]
    pub fn new_keccak(task_number: usize) -> Self {
        Task {
            task_number,
            task_height: 0,
            command: Command::Keccak,
            depends_on: Vec::new(),
            keccak_depends_on: VecDeque::new(),
            priority: Priority::Normal,
        }
    }

    #[must_use]
    pub fn new_join(task_number: usize, task_height: u32, left: usize, right: usize) -> Self {
        let command = Command::Join;
        Task {
            task_number,
            task_height,
            command: command.clone(),
            depends_on: vec![left, right],
            keccak_depends_on: VecDeque::new(),
            priority: Self::optimal_priority(&command, task_height),
        }
    }

    #[must_use]
    pub fn new_union(task_number: usize, task_height: u32, left: usize, right: usize) -> Self {
        let command = Command::Union;
        Task {
            task_number,
            task_height,
            command: command.clone(),
            depends_on: vec![],
            keccak_depends_on: vec![left, right].into(),
            priority: Self::optimal_priority(&command, task_height),
        }
    }

    #[must_use]
    pub fn new_finalize(
        task_number: usize,
        task_height: u32,
        depends_on: usize,
        keccak_depends_on: Option<VecDeque<usize>>,
    ) -> Self {
        Task {
            task_number,
            task_height,
            command: Command::Finalize,
            depends_on: vec![depends_on],
            keccak_depends_on: keccak_depends_on.unwrap_or_default(),
            priority: Priority::Critical, // Finalize is highest priority
        }
    }

    /// Sets a custom priority for this task
    #[must_use]
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Returns true if this task is on the critical path (affects overall completion time)
    #[must_use]
    pub fn is_critical_path(&self) -> bool {
        self.priority == Priority::Critical ||
        // Higher-level joins and unions are more likely to be on the critical path
        (self.command == Command::Join && self.task_height > 1) ||
        (self.command == Command::Union && self.task_height > 1) ||
        // Last segment in a sequence is likely critical
        (self.command == Command::Segment && self.task_number % 2 == 0)
    }
}
