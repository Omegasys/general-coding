use std::time::{Duration, Instant};
use std::thread::sleep;

struct CpuThrottle {
    max_active_time: Duration,
    window: Duration,
    last_check: Instant,
    active_time: Duration,
}

impl CpuThrottle {
    fn new(max_cpu_percent: u64) -> Self {
        let window = Duration::from_millis(100);

        Self {
            max_active_time: window * max_cpu_percent as u32 / 100,
            window,
            last_check: Instant::now(),
            active_time: Duration::ZERO,
        }
    }

    fn start_work(&mut self) -> Instant {
        Instant::now()
    }

    fn end_work(&mut self, start: Instant) {
        self.active_time += start.elapsed();

        if self.last_check.elapsed() >= self.window {
            if self.active_time > self.max_active_time {
                let sleep_time = self.active_time - self.max_active_time;
                sleep(sleep_time);
            }

            self.active_time = Duration::ZERO;
            self.last_check = Instant::now();
        }
    }
}