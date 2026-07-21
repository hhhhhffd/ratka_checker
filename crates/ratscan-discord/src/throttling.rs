use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

/// Bounded in-memory limiter with separately configurable user, guild, and queue limits.
#[derive(Debug)]
pub struct RateLimiter {
    per_user: usize,
    per_guild: usize,
    window: Duration,
    max_queued: usize,
    queued: usize,
    users: HashMap<u64, VecDeque<Instant>>,
    guilds: HashMap<u64, VecDeque<Instant>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitError {
    User,
    Guild,
    Queue,
}

impl RateLimiter {
    pub fn new(per_user: usize, per_guild: usize, max_queued: usize, window: Duration) -> Self {
        Self {
            per_user,
            per_guild,
            window,
            max_queued,
            queued: 0,
            users: HashMap::new(),
            guilds: HashMap::new(),
        }
    }

    pub fn accept_batch(
        &mut self,
        user_id: u64,
        guild_id: u64,
        jobs: usize,
        now: Instant,
    ) -> Result<(), RateLimitError> {
        if jobs == 0 || jobs > self.max_queued.saturating_sub(self.queued) {
            return Err(RateLimitError::Queue);
        }
        let window = self.window;
        let user = self.users.entry(user_id).or_default();
        prune(user, now, window);
        if user.len().saturating_add(jobs) > self.per_user {
            return Err(RateLimitError::User);
        }
        let guild = self.guilds.entry(guild_id).or_default();
        prune(guild, now, window);
        if guild.len().saturating_add(jobs) > self.per_guild {
            return Err(RateLimitError::Guild);
        }
        user.extend(std::iter::repeat_n(now, jobs));
        guild.extend(std::iter::repeat_n(now, jobs));
        self.queued += jobs;
        Ok(())
    }

    pub fn complete_batch(&mut self, jobs: usize) {
        self.queued = self.queued.saturating_sub(jobs);
    }
}

fn prune(values: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while values
        .front()
        .is_some_and(|value| now.duration_since(*value) >= window)
    {
        values.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_user_guild_and_queue_limits() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(1, 2, 2, Duration::from_secs(60));
        assert_eq!(limiter.accept_batch(1, 10, 1, start), Ok(()));
        assert_eq!(
            limiter.accept_batch(1, 10, 1, start),
            Err(RateLimitError::User)
        );
        assert_eq!(limiter.accept_batch(2, 10, 1, start), Ok(()));
        assert_eq!(
            limiter.accept_batch(3, 11, 1, start),
            Err(RateLimitError::Queue)
        );
        limiter.complete_batch(1);
        assert_eq!(
            limiter.accept_batch(3, 10, 1, start),
            Err(RateLimitError::Guild)
        );
    }

    #[test]
    fn counts_every_attachment_before_accepting_message() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(2, 3, 3, Duration::from_secs(60));
        assert_eq!(limiter.accept_batch(1, 10, 2, start), Ok(()));
        assert_eq!(
            limiter.accept_batch(2, 10, 2, start),
            Err(RateLimitError::Queue)
        );
        assert_eq!(
            limiter.accept_batch(1, 10, 1, start),
            Err(RateLimitError::User)
        );
    }
}
