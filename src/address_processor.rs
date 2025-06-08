use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rayon::prelude::*;
use crate::utils::{generate_addresses, generate_secure_mnemonic, SecureSeed};
use crate::progress::{ProgressTracker, StatsSummary};
use crate::matcher::PatternMatcher;
use crate::crypto;

// Result type: (mnemonic, address, matched pattern, address position, seed word count)
pub type MatchResult = (String, String, String, u32, usize);

// Secure version of the result type that zeroes memory when dropped
type SecureMatchResult = (SecureSeed, String, String, u32, usize);

/// Address processor for finding vanity addresses
pub struct AddressProcessor {
    progress: ProgressTracker,
    max_batch_size: usize,
    min_batch_size: usize,
    batch_adjust_interval: usize,
    batch_size: Arc<AtomicUsize>,
    batch_counter: Arc<AtomicUsize>,
    performance_metrics: Arc<Mutex<HashMap<usize, Duration>>>,
    should_cancel: Arc<AtomicBool>,
    // Optional callback for real‐time result reporting
    result_callback: Arc<Mutex<Option<Box<dyn Fn(&str, &str, &str, u32, usize) + Send + Sync>>>>,
    // Crypto acceleration context
    accel_ctx: &'static crypto::AccelContext,
}

impl AddressProcessor {
    pub fn new() -> Self {
        // Determine thread count
        let cpu_count = num_cpus::get();
        let thread_count = cpu_count.max(1);
        
        // Get hardware acceleration context
        let accel_ctx = crypto::get_context();
        
        // Configure the Rayon global thread pool once
        static THREAD_POOL_INITIALIZED: AtomicBool = AtomicBool::new(false);
        if !THREAD_POOL_INITIALIZED.load(Ordering::SeqCst) {
            if let Err(e) = rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build_global() 
            {
                eprintln!("Warning: Failed to configure Rayon thread pool: {}", e);
            } else {
                THREAD_POOL_INITIALIZED.store(true, Ordering::SeqCst);
            }
        }

        // Use optimized batch sizes based on hardware capabilities
        let initial_batch_size = accel_ctx.get_optimal_batch_count();
        let min_batch_size = accel_ctx.get_optimal_batch_size() * 10;
        let max_batch_size = initial_batch_size * 3;
        let batch_adjust_interval = 10;

        Self {
            progress: ProgressTracker::new(thread_count, true),
            max_batch_size,
            min_batch_size,
            batch_adjust_interval,
            batch_size: Arc::new(AtomicUsize::new(initial_batch_size)),
            batch_counter: Arc::new(AtomicUsize::new(0)),
            performance_metrics: Arc::new(Mutex::new(HashMap::new())),
            should_cancel: Arc::new(AtomicBool::new(false)),
            result_callback: Arc::new(Mutex::new(None)),
            accel_ctx,
        }
    }

    /// Set a callback for throttled progress updates
    pub fn set_progress_callback<F>(&self, callback: F)
    where
        F: Fn(usize, usize, f64, f64) + Send + Sync + 'static,
    {
        let throttled_callback = move |seeds, addresses, seed_rate, addr_rate| {
            // Only call back every 250ms to avoid spamming
            static LAST_UPDATE: AtomicUsize = AtomicUsize::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as usize;
            
            if now.saturating_sub(LAST_UPDATE.load(Ordering::Relaxed)) > 250 {
                LAST_UPDATE.store(now, Ordering::Relaxed);
                callback(seeds, addresses, seed_rate, addr_rate);
            }
        };
        
        self.progress.set_callback(throttled_callback);
    }

    /// Optional callback to handle *each* matching result in real time
    pub fn set_result_callback<F>(&self, callback: F)
    where
        F: Fn(&str, &str, &str, u32, usize) + Send + Sync + 'static,
    {
        *self.result_callback.lock().unwrap() = Some(Box::new(callback));
    }

    /// Public entry point to find addresses matching patterns
    pub fn find_matches(
        &self,
        matcher: PatternMatcher,
        word_count: usize,
        num_results: usize,
        balanced: bool,
        addresses_per_seed: u32,
    ) -> Vec<MatchResult> {
        // Adjust the initial batch size if needed based on word count
        let optimal_batch_size = self.accel_ctx.get_optimal_batch_count();
        let initial_batch_size = if word_count == 0 {
            optimal_batch_size // Mixed word count, use default
        } else if word_count == 12 {
            (optimal_batch_size * 12) / 10 // 20% higher for 12-word
        } else if word_count == 15 {
            optimal_batch_size
        } else {
            (optimal_batch_size * 8) / 10 // 20% smaller for 24-word
        };
        self.batch_size.store(initial_batch_size, Ordering::Relaxed);

        // Start progress monitor in background
        let progress_thread = self.progress.start_monitoring_thread();

        // Either balanced or any
        let matches = if balanced {
            self.find_balanced_matches(&matcher, word_count, num_results, addresses_per_seed)
        } else {
            self.find_any_matches(&matcher, word_count, num_results, addresses_per_seed)
        };

        // Stop progress, wait for thread
        self.progress.stop();
        let _ = progress_thread.join();

        matches
    }

    /// Get final performance statistics
    pub fn get_stats(&self) -> StatsSummary {
        self.progress.get_stats()
    }

    /// Request cancellation
    pub fn cancel(&self) {
        self.should_cancel.store(true, Ordering::SeqCst);
        self.progress.stop();
        *self.result_callback.lock().unwrap() = None;
        println!("Cancellation requested — stopping search.");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    
    /// Reset the processor for a fresh search
    pub fn reset(&self) {
        self.should_cancel.store(true, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.should_cancel.store(false, Ordering::SeqCst);
        self.batch_counter.store(0, Ordering::Relaxed);
        self.performance_metrics.lock().unwrap().clear();
        self.progress.reset();
        *self.result_callback.lock().unwrap() = None;
    }
    
    /// Internal check for cancellation
    fn is_cancelled(&self) -> bool {
        self.should_cancel.load(Ordering::SeqCst)
    }

    /// Internal conversion from secure results to exposed results
    fn convert_secure_to_exposed(&self, secure_results: Vec<SecureMatchResult>) -> Vec<MatchResult> {
        secure_results
            .into_iter()
            .map(|(secure_seed, address, pattern, position, word_count)| {
                (secure_seed.expose(), address, pattern, position, word_count)
            })
            .collect()
    }

    /// Adapt the batch size based on performance measurements
    fn adjust_batch_size(&self, thread_idx: usize) {
        let metrics = self.performance_metrics.lock().unwrap();
        if let Some(last_duration) = metrics.get(&thread_idx) {
            let duration_ms = last_duration.as_millis() as f64;
            let current_batch_size = self.batch_size.load(Ordering::Relaxed);
            
            // Target 80-120ms per batch for optimal throughput
            const TARGET_MS_MIN: f64 = 80.0;
            const TARGET_MS_MAX: f64 = 120.0;
            
            let new_batch_size = if duration_ms < TARGET_MS_MIN {
                // Too fast, increase batch size by 10-25% to reduce overhead
                let increase_factor = 1.0 + (0.25 * (TARGET_MS_MIN - duration_ms) / TARGET_MS_MIN);
                let bigger_batch = (current_batch_size as f64 * increase_factor) as usize;
                bigger_batch.min(self.max_batch_size) // Cap at maximum
            } else if duration_ms > TARGET_MS_MAX {
                // Too slow, decrease batch size by 10-25%
                let decrease_factor = 1.0 - (0.25 * (duration_ms - TARGET_MS_MAX) / TARGET_MS_MAX);
                let smaller_batch = (current_batch_size as f64 * decrease_factor) as usize;
                smaller_batch.max(self.min_batch_size) // Floor at minimum
            } else {
                // In the sweet spot
                current_batch_size
            };
            
            // Ensure batch size is a multiple of the SIMD width for optimal performance
            let simd_width = self.accel_ctx.get_optimal_batch_size().max(1);
            let aligned_size = ((new_batch_size + simd_width - 1) / simd_width) * simd_width;
            
            // Only update if significantly different (>5%)
            if (aligned_size as f64 / current_batch_size as f64).abs() > 1.05 || 
               (aligned_size as f64 / current_batch_size as f64).abs() < 0.95 {
                self.batch_size.store(aligned_size, Ordering::Relaxed);
            }
        }
    }

    // -------------------------------------------
    // CHUNK-BASED APPROACH FOR "BALANCED" MATCHES
    // -------------------------------------------
    fn find_balanced_matches(
        &self,
        matcher: &PatternMatcher,
        word_count: usize,
        num_results: usize,
        addresses_per_seed: u32,
    ) -> Vec<MatchResult> {
        let pattern_matches = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let found_count = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(Mutex::new(Vec::<SecureMatchResult>::new()));

        // Keep generating in parallel "batches" until we have enough or are cancelled
        while found_count.load(Ordering::SeqCst) < num_results && !self.is_cancelled() {
            if self.is_cancelled() {
                break;
            }
            let batch_num = self.batch_counter.fetch_add(1, Ordering::Relaxed);
            let current_batch_size = self.batch_size.load(Ordering::Relaxed);

            // Adjust batch size periodically
            if batch_num % self.batch_adjust_interval == 0 {
                self.adjust_batch_size(0);
            }

            let start_time = Instant::now();

            // Generate seeds in parallel
            let chunk: Vec<Vec<SecureMatchResult>> = 
                (0..current_batch_size)
                    .into_par_iter()
                    .map(|_| {
                        if self.is_cancelled()
                            || found_count.load(Ordering::SeqCst) >= num_results
                        {
                            return Vec::new();
                        }
                        
                        // Generate one seed, produce addresses
                        let (secure_seed, actual_wc) = generate_secure_mnemonic(word_count);
                        let addrs = generate_addresses(secure_seed.as_str(), addresses_per_seed);

                        let mut local_results = Vec::new();
                        for addr_info in addrs {
                            if let Some(pattern) = matcher.is_match(&addr_info.address) {
                                local_results.push((
                                    secure_seed.clone(),  // Use the secure seed
                                    addr_info.address,
                                    pattern.clone(),
                                    addr_info.position,
                                    actual_wc,
                                ));
                            }
                        }
                        local_results
                    })
                    .collect();

            // Record timing for this batch
            let elapsed = start_time.elapsed();
            {
                let mut pm = self.performance_metrics.lock().unwrap();
                pm.insert(0, elapsed);
            }

            // Update progress counters
            self.progress.record_processed(
                current_batch_size,
                current_batch_size * addresses_per_seed as usize,
            );

            // Flatten results from all threads
            let chunk = chunk.into_iter().flatten().collect::<Vec<_>>();

            // Move them into our global results, checking if we reached num_results
            for (secure_seed, address, pattern, position, wc) in chunk {
                if self.is_cancelled() {
                    break;
                }
                {
                    let mut pmatches = pattern_matches.lock().unwrap();
                    *pmatches.entry(pattern.clone()).or_insert(0) += 1;
                }
                
                let total_found = found_count.fetch_add(1, Ordering::Relaxed) + 1;
                
                // Store the result
                {
                    let mut r = results.lock().unwrap();
                    r.push((secure_seed.clone(), address.clone(), pattern.clone(), position, wc));
                }
                
                // If there's a user callback, invoke it
                if let Some(callback) = self.result_callback.lock().unwrap().as_ref() {
                    callback(secure_seed.as_str(), &address, &pattern, position, wc);
                }
                
                // Log match to console
                if total_found <= 10 || total_found % 10 == 0 {
                    println!("MATCH #{} found pattern: {}", total_found, pattern);
                    println!("Address: {}", address);
                    println!("Position: {}", position);
                    println!("Seed phrase ({}-word): {}", wc, secure_seed.as_str());
                    println!("---------------------------");
                }

                // If balanced matching, check if we have enough of this specific pattern
                if let Some(max_per_pattern) = if matcher.has_multiple_patterns() {
                    Some(1 + (num_results / pattern_matches.lock().unwrap().len()))
                } else {
                    None
                } {
                    if let Some(count) = pattern_matches.lock().unwrap().get(&pattern) {
                        if *count >= max_per_pattern && total_found >= pattern_matches.lock().unwrap().len() {
                            break;
                        }
                    }
                }

                // Stop if we have enough total matches
                if total_found >= num_results {
                    break;
                }
            }
        }

        // Fix for the borrow issue - clone the vector before the lock is dropped
        let secure_results = {
            let locked_results = results.lock().unwrap();
            locked_results.clone()
        };

        // Convert secure results to exposed results at the end
        self.convert_secure_to_exposed(secure_results)
    }

    // -------------------------------------------
    // DIRECT APPROACH FOR "ANY" MATCHES
    // -------------------------------------------
    fn find_any_matches(
        &self,
        matcher: &PatternMatcher,
        word_count: usize,
        num_results: usize,
        addresses_per_seed: u32,
    ) -> Vec<MatchResult> {
        let found_count = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(Mutex::new(Vec::<SecureMatchResult>::new()));

        // Generate seed batches in parallel until we have enough matches
        while found_count.load(Ordering::SeqCst) < num_results && !self.is_cancelled() {
            if self.is_cancelled() {
                break;
            }
            let batch_num = self.batch_counter.fetch_add(1, Ordering::Relaxed);
            let current_batch_size = self.batch_size.load(Ordering::Relaxed);

            // Periodically adjust batch size
            if batch_num % self.batch_adjust_interval == 0 {
                self.adjust_batch_size(0);
            }

            let start_time = Instant::now();
            
            // Generate seeds in parallel and find addresses that match
            let chunk: Vec<SecureMatchResult> = (0..current_batch_size)
                .into_par_iter()
                .filter_map(|_| {
                    if self.is_cancelled() || found_count.load(Ordering::SeqCst) >= num_results {
                        return None;
                    }
                    
                    // Generate one seed and check all derived addresses
                    let (secure_seed, actual_wc) = generate_secure_mnemonic(word_count);
                    let addrs = generate_addresses(secure_seed.as_str(), addresses_per_seed);
                    
                    // Return the first matching address for this seed (if any)
                    for addr_info in addrs {
                        if let Some(pattern) = matcher.is_match(&addr_info.address) {
                            return Some((
                                secure_seed,
                                addr_info.address,
                                pattern,
                                addr_info.position,
                                actual_wc
                            ));
                        }
                    }
                    
                    None
                })
                .collect();
                
            // Record timing
            let elapsed = start_time.elapsed();
            {
                let mut pm = self.performance_metrics.lock().unwrap();
                pm.insert(0, elapsed);
            }
            
            // Record metrics
            self.progress.record_processed(
                current_batch_size,
                current_batch_size * addresses_per_seed as usize,
            );
            
            // Process only as many results as needed to reach num_results
            let needed = num_results.saturating_sub(found_count.load(Ordering::SeqCst));
            let to_take = needed.min(chunk.len());
            
            for (secure_seed, address, pattern, position, wc) in chunk.into_iter().take(to_take) {
                if self.is_cancelled() {
                    break;
                }
                
                let total_found = found_count.fetch_add(1, Ordering::Relaxed) + 1;
                
                // Store the result
                {
                    let mut r = results.lock().unwrap();
                    r.push((secure_seed.clone(), address.clone(), pattern.clone(), position, wc));
                }
                
                // If there's a user callback, invoke it
                if let Some(callback) = self.result_callback.lock().unwrap().as_ref() {
                    callback(secure_seed.as_str(), &address, &pattern, position, wc);
                }
                
                // Log match to console
                if total_found <= 10 || total_found % 10 == 0 {
                    println!("MATCH #{} found pattern: {}", total_found, pattern);
                    println!("Address: {}", address);
                    println!("Position: {}", position);
                    println!("Seed phrase ({}-word): {}", wc, secure_seed.as_str());
                    println!("---------------------------");
                }
                
                if total_found >= num_results {
                    break;
                }
            }
        }
        
        // Fix for the borrow issue - clone the vector before the lock is dropped
        let secure_results = {
            let locked_results = results.lock().unwrap();
            locked_results.clone()
        };
        
        // Convert secure results to exposed results at the end
        self.convert_secure_to_exposed(secure_results)
    }
}
