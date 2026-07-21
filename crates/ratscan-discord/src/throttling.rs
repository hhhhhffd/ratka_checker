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

    pub fn accept(
        &mut self,
        user_id: u64,
        guild_id: u64,
        now: Instant,
    ) -> Result<(), RateLimitError> {
        if self.queued >= self.max_queued {
            return Err(RateLimitError::Queue);
        }
        let window = self.window;
        let user = self.users.entry(user_id).or_default();
        prune(user, now, window);
        if user.len() >= self.per_user {
            return Err(RateLimitError::User);
        }
        let guild = self.guilds.entry(guild_id).or_default();
        prune(guild, now, window);
        if guild.len() >= self.per_guild {
            return Err(RateLimitError::Guild);
        }
        user.push_back(now);
        guild.push_back(now);
        self.queued += 1;
        Ok(())
    }

    pub fn complete(&mut self) {
        self.queued = self.queued.saturating_sub(1);
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
        assert_eq!(limiter.accept(1, 10, start), Ok(()));
        assert_eq!(limiter.accept(1, 10, start), Err(RateLimitError::User));
        assert_eq!(limiter.accept(2, 10, start), Ok(()));
        assert_eq!(limiter.accept(3, 11, start), Err(RateLimitError::Queue));
        limiter.complete();
        assert_eq!(limiter.accept(3, 10, start), Err(RateLimitError::Guild));
    }
}
