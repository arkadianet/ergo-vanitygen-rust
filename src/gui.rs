use egui::{Color32, RichText, ScrollArea, TextEdit, Ui};
use eframe::{App, Frame, NativeOptions};
use poll_promise::Promise;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use chrono::Local;
use std::sync::atomic::{AtomicUsize, Ordering};
use rfd::FileDialog;

use crate::address_processor::{AddressProcessor, MatchResult};
use crate::matcher::PatternMatcher;
use crate::paper_wallet::PaperWalletInfo;
use crate::estimator;

const MAX_LOG_ENTRIES: usize = 100;

/// Tabs for the GUI.
#[derive(PartialEq, Copy, Clone)]
enum Tab {
    Status,
    Results,
    Log,
}

/// Main application structure.
pub struct VanityGenApp {
    // --- GUI State ---
    input_patterns: String,
    start_match: bool,
    end_match: bool,
    case_sensitive: bool,
    twelve_words: bool,
    fifteen_words: bool,
    twenty_four_words: bool,
    all_word_lengths: bool,
    addresses_per_seed: u32,
    num_results: usize,
    balanced: bool,
    current_tab: Tab,

    // Add security options
    mask_seed_phrases: bool,
    show_security_warning: bool,

    // Seed phrase unmasking
    show_unmasked_seed: bool,
    current_unmasked_seed: String,

    // --- Results and Statistics ---
    results: Arc<Mutex<Vec<MatchResult>>>,
    logs: VecDeque<String>,
    stats: Arc<Mutex<Option<(usize, usize, f64, f64, usize)>>>,

    // --- Processing State ---
    running: Arc<Mutex<bool>>,
    promise: Option<Promise<()>>,
    start_time: Option<Instant>,
    processor: Option<Arc<AddressProcessor>>,
}

impl Default for VanityGenApp {
    fn default() -> Self {
        Self {
            input_patterns: String::new(),
            start_match: false,
            end_match: false,
            case_sensitive: false,
            twelve_words: false,
            fifteen_words: false,
            twenty_four_words: true,
            all_word_lengths: false,
            addresses_per_seed: 1,
            num_results: 1,
            balanced: false,
            current_tab: Tab::Status,

            // Initialize security options
            mask_seed_phrases: true,
            show_security_warning: true,

            // Seed phrase unmasking
            show_unmasked_seed: false,
            current_unmasked_seed: String::new(),

            results: Arc::new(Mutex::new(Vec::new())),
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            stats: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(false)),
            promise: None,
            start_time: None,
            processor: None,
        }
    }
}

impl App for VanityGenApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Handle window close request
        if ctx.input(|i| i.viewport().close_requested()) {
            self.handle_window_close();
        }
        // Request frequent updates for smooth animations
        ctx.request_repaint_after(Duration::from_millis(10));
        if *self.running.lock().unwrap() {
            ctx.request_repaint();
        }

        // Auto-switch to Results tab when new matches are found
        static LAST_LOGGED_COUNT: AtomicUsize = AtomicUsize::new(0);
        let last_logged = LAST_LOGGED_COUNT.load(Ordering::Relaxed);
        let result_count = self.results.lock().unwrap().len();
        if result_count > last_logged {
            ctx.request_repaint();
            self.current_tab = Tab::Results;
        }
        if result_count > 0 {
            LAST_LOGGED_COUNT.store(result_count, Ordering::Relaxed);
        }

        // Show unmasked seed phrase modal when requested
        if self.show_unmasked_seed {
            egui::Window::new("⚠️ Unmasked Seed Phrase")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(RichText::new("⚠️ SENSITIVE DATA - Keep Safe").strong().size(16.0).color(Color32::RED));
                    ui.separator();

                    let text_style = egui::TextStyle::Monospace;
                    let row_height = ui.text_style_height(&text_style) * 1.5;
                    let seed_words: Vec<&str> = self.current_unmasked_seed.split_whitespace().collect();

                    egui::Grid::new("seed_phrase_grid")
                        .num_columns(2)
                        .spacing([10.0, 8.0])
                        .striped(true)
                        .min_row_height(row_height)
                        .show(ui, |ui| {
                            for (i, word) in seed_words.iter().enumerate() {
                                ui.label(RichText::new(format!("{:2}.", i+1)).strong().color(Color32::LIGHT_YELLOW));
                                ui.label(RichText::new(*word).monospace());

                                if i % 2 == 1 {
                                    ui.end_row();
                                }
                            }

                            // Handle odd number of words
                            if seed_words.len() % 2 == 1 {
                                ui.end_row();
                            }
                        });

                    ui.add_space(15.0);
                    ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                        if ui.button("Close").clicked() {
                            self.show_unmasked_seed = false;
                            self.current_unmasked_seed.clear();
                        }

                        ui.add_space(5.0);
                        ui.label("Close this window when done viewing");
                    });
                });
        }

        // Left sidebar for settings and configuration
        egui::SidePanel::left("sidebar")
            .frame(egui::Frame::dark_canvas(&ctx.style()).inner_margin(10.0))
            .resizable(false)
            .show(ctx, |ui| {
                self.render_app_header(ui);
                ui.add_space(10.0);
                ui.heading("Settings");
                ui.separator();
                ui.add_space(10.0);

                ui.label("Pattern(s) to find:");

                let invalid_chars = self.validate_patterns();
                let has_invalid = invalid_chars.is_some();

                let text_edit = TextEdit::multiline(&mut self.input_patterns)
                    .hint_text("e.g. ABC, 123");

                let text_response = if has_invalid {
                    let frame = egui::Frame::none()
                        .stroke(egui::Stroke::new(2.0, Color32::from_rgb(220, 38, 38)))
                        .inner_margin(egui::vec2(4.0, 4.0));
                    frame.show(ui, |ui| {
                        ui.add(text_edit)
                    }).inner
                } else {
                    ui.add(text_edit)
                };

                if has_invalid {
                    if let Some(invalid) = invalid_chars {
                        text_response.on_hover_ui(|ui| {
                            ui.colored_label(Color32::from_rgb(220, 38, 38), "❌ Invalid characters detected");

                            // Show each invalid character with clear description
                            for &c in &invalid {
                                let description = match c {
                                    '0' => "0 (zero)",
                                    'O' => "O (uppercase O)",
                                    'I' => "I (uppercase i)",
                                    'l' => "l (lowercase L)",
                                    _ => "invalid character",
                                };
                                ui.label(format!("• {} - {}", c, description));
                            }

                            ui.separator();
                            ui.label("Valid characters:");
                            ui.label("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
                            ui.label("Excluded to avoid confusion between similar-looking characters");
                        });
                    }
                }
                ui.label("Comma-separated for multiple patterns");

                // Add Base58 info with subtle coloring
                ui.label(
                    RichText::new("Note: Only Base58 characters are valid (no 0, O, I, l)")
                        .color(Color32::from_rgb(200, 200, 200))
                        .size(12.0)
                ).on_hover_ui(|ui| {
                    ui.label("Valid characters: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
                    ui.label("Excluded characters: 0, O, I, l");
                    ui.label("These restrictions exist in the Ergo address format to prevent confusion between similar-looking characters.");
                });

                ui.add_space(5.0);

                ui.label("Match type:");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.start_match, true, "Start")
                        .on_hover_text("Match at the beginning (after the first 9 characters)");
                    if self.start_match {
                        self.end_match = false;
                    }
                    ui.radio_value(&mut self.end_match, true, "End")
                        .on_hover_text("Match at the end of the address");
                    if self.end_match {
                        self.start_match = false;
                    }
                    // Matching anywhere option:
                    let anywhere = !self.start_match && !self.end_match;
                    if ui
                        .radio_value(&mut self.start_match, false, "Anywhere")
                        .on_hover_text("Match anywhere in the address")
                        .clicked()
                        && !anywhere
                    {
                        self.start_match = false;
                        self.end_match = false;
                    }
                });
                ui.add_space(5.0);
                ui.checkbox(&mut self.case_sensitive, "Case sensitive")
                    .on_hover_text("Exact match required");

                ui.add_space(10.0);
                ui.label("Seed phrase type:");
                if ui.radio_value(&mut self.twelve_words, true, "12-word seed")
                    .on_hover_text("Faster generation with 12 words")
                    .clicked()
                {
                    self.fifteen_words = false;
                    self.twenty_four_words = false;
                    self.all_word_lengths = false;
                }
                if ui.radio_value(&mut self.fifteen_words, true, "15-word seed")
                    .on_hover_text("Balanced speed and security")
                    .clicked()
                {
                    self.twelve_words = false;
                    self.twenty_four_words = false;
                    self.all_word_lengths = false;
                }
                if ui.radio_value(&mut self.twenty_four_words, true, "24-word seed")
                    .on_hover_text("Most secure")
                    .clicked()
                {
                    self.twelve_words = false;
                    self.fifteen_words = false;
                    self.all_word_lengths = false;
                }
                if ui.radio_value(&mut self.all_word_lengths, true, "All lengths")
                    .on_hover_text("Randomly choose 12, 15, or 24 words")
                    .clicked()
                {
                    self.twelve_words = false;
                    self.fifteen_words = false;
                    self.twenty_four_words = false;
                }
                if !self.twelve_words && !self.fifteen_words && !self.twenty_four_words && !self.all_word_lengths {
                    self.twenty_four_words = true;
                }

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Addresses per seed:");
                    ui.add(
                        egui::DragValue::new(&mut self.addresses_per_seed)
                            .clamp_range(1..=100)
                            .speed(0.1),
                    )
                    .on_hover_text("How many addresses are checked per seed phrase");
                });
                ui.horizontal(|ui| {
                    ui.label("Results to find:");
                    ui.add(
                        egui::DragValue::new(&mut self.num_results)
                            .clamp_range(1..=100)
                            .speed(0.1),
                    )
                    .on_hover_text("Number of matching addresses to find");
                });
                ui.checkbox(&mut self.balanced, "Balanced matches")
                    .on_hover_text("Distribute matches evenly across patterns");

                ui.add_space(15.0);
                let patterns: Vec<String> = self.input_patterns
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if ui.add_enabled(!patterns.is_empty(), egui::Button::new("Estimate Time"))
                    .on_hover_text("Estimate time needed for search")
                    .clicked()
                {
                    for pattern in &patterns {
                        let estimate = estimator::estimate_pattern(pattern, self.start_match);

                        if estimate.has_invalid_chars {
                            self.add_log(&format!(
                                "Pattern: \"{}\" contains invalid Base58 characters: {}",
                                pattern,
                                estimate.invalid_chars.iter().collect::<String>()
                            ));
                            self.add_log("  This pattern is IMPOSSIBLE to find in a valid Ergo address");
                            self.add_log("  Valid characters: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
                            self.current_tab = Tab::Log; // Switch to log tab to make error visible
                        } else {
                            self.add_log(&format!(
                                "Pattern: \"{}\", Est. attempts: {:.0}, Time: {} to {}",
                                pattern,
                                estimate.attempts_needed,
                                estimator::format_time(estimate.time_at_min),
                                estimator::format_time(estimate.time_at_max)
                            ));
                        }
                    }
                }
                ui.add_space(10.0);
                let is_running = *self.running.lock().unwrap();
                let has_invalid = self.validate_patterns().is_some();
                let can_start = !is_running && !patterns.is_empty() && !has_invalid;

                if ui.add_enabled(can_start, egui::Button::new("Start Search").fill(Color32::from_rgb(0, 120, 0)))
                    .clicked()
                {
                    self.start_search();
                }
                if ui.add_enabled(is_running, egui::Button::new("Stop Search").fill(Color32::from_rgb(180, 0, 0)))
                    .clicked()
                {
                    self.stop_search();
                }

                // Add spacer to push the donation button to the bottom
                ui.add_space(ui.available_height() - 50.0);

                // Donation button at bottom of sidebar
                ui.separator();
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.add_space(10.0);
                    let donate_button = ui.add(
                        egui::Button::new(
                            RichText::new("❤ Donate")
                                .color(Color32::from_rgb(240, 180, 180))
                                .size(14.0)
                        )
                        .fill(Color32::from_rgb(80, 40, 40))
                        .rounding(8.0)
                    );

                    if donate_button.clicked() {
                        const DONATION_ADDRESS: &str = "9fMUoW2fVXzG8yBaGzaRNtWS8wcpNLJc6HCPrK6YFs6SkNDYryK";
                        ui.output_mut(|o| o.copied_text = DONATION_ADDRESS.to_string());
                        self.add_log("Donation address copied to clipboard");
                    }

                    if donate_button.hovered() {
                        egui::show_tooltip(ui.ctx(), egui::Id::new("donation_tooltip"), |ui| {
                            ui.label("Click to copy donation address");
                            ui.label("9ergoFunMJ5MffMM31siayxK4juNGJ1qBQXukFJRy4jXVF4S66K");
                        });
                    }
                });
            });

        // Central panel with tabbed content
        egui::CentralPanel::default().show(ctx, |ui| {
            // Custom tab bar at the top
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let tab_button = |ui: &mut Ui, text: &str, active: bool| {
                    let (bg, fg) = if active {
                        (Color32::from_rgb(0, 120, 215), Color32::WHITE)
                    } else {
                        (Color32::from_rgb(50, 50, 50), Color32::LIGHT_GRAY)
                    };
                    let frame = egui::Frame::none()
                        .fill(bg)
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::vec2(10.0, 4.0));
                    frame.show(ui, |ui| {
                        ui.label(RichText::new(text).color(fg).size(16.0));
                    }).response.interact(egui::Sense::click())
                };

                if tab_button(ui, "Status", self.current_tab == Tab::Status).clicked() {
                    self.current_tab = Tab::Status;
                }
                let results_count = self.results.lock().unwrap().len();
                let results_label = if results_count > 0 {
                    format!("Results ({})", results_count)
                } else {
                    "Results".to_string()
                };
                if tab_button(ui, &results_label, self.current_tab == Tab::Results).clicked() {
                    self.current_tab = Tab::Results;
                }
                if tab_button(ui, "Log", self.current_tab == Tab::Log).clicked() {
                    self.current_tab = Tab::Log;
                }
            });
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            // Render the content of the selected tab
            match self.current_tab {
                Tab::Status => self.show_status(ui),
                Tab::Results => self.show_results(ui),
                Tab::Log => self.show_log(ui),
            }
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.handle_window_close();
    }
}

impl VanityGenApp {
    /// Starts the background search process.
    fn start_search(&mut self) {
        let patterns: Vec<String> = self.input_patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if patterns.is_empty() {
            self.add_log("No patterns specified");
            return;
        }

        // Validate patterns first
        if let Some(invalid_chars) = self.validate_patterns() {
            let invalid_str: String = invalid_chars.iter().collect();
            self.add_log(&format!("Error: Invalid characters in pattern: {}", invalid_str));
            self.add_log("Valid characters: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
            self.add_log("Excluded characters: 0, O, I, l (to avoid confusion)");
            self.current_tab = Tab::Log;
            return;
        }

        let matcher = PatternMatcher::new(patterns.clone(), self.case_sensitive, self.start_match, self.end_match);

        // Validate matcher
        if let Err(err) = matcher.validate() {
            self.add_log(&format!("Error: {}", err));
            self.current_tab = Tab::Log;

            // Add specific messages based on error type
            if self.start_match && patterns.iter().any(|p| {
                let first_char = p.chars().next().unwrap_or('_');
                !['e', 'f', 'g', 'h', 'i'].contains(&first_char)
            }) {
                self.add_log("Invalid start pattern: Ergo addresses can only start with e, f, g, h, or i");
                self.add_log("Try 'Anywhere' or 'End' matching instead for this pattern");
            }
            return;
        }

        let word_count = if self.all_word_lengths {
            0 // Use random seed length (12/15/24)
        } else if self.twelve_words {
            12
        } else if self.fifteen_words {
            15
        } else {
            24
        };
        let start_match = self.start_match;
        let end_match = self.end_match;
        let case_sensitive = self.case_sensitive;
        let patterns_clone = patterns.clone();
        let addresses_per_seed = self.addresses_per_seed;
        let num_results = self.num_results;
        let balanced = self.balanced;

        self.start_time = Some(Instant::now());
        *self.running.lock().unwrap() = true;
        let running = self.running.clone();
        let results = self.results.clone();
        let stats = self.stats.clone();

        // Create or reset the processor
        let processor = if let Some(proc) = &self.processor {
            // Reset the existing processor to reuse it
            proc.reset();
            proc.clone()
        } else {
            // Create a new processor
            Arc::new(AddressProcessor::new())
        };
        self.processor = Some(processor.clone());

        // Set up the callback for new matches.
        let results_for_callback = results.clone();
        let logs_arc = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)));
        let logs_for_callback = logs_arc.clone();
        processor.set_result_callback(move |mnemonic, address, pattern, position, word_count| {
            results_for_callback.lock().unwrap().push((
                mnemonic.to_string(), address.to_string(), pattern.to_string(), position, word_count
            ));
            let mut logs = logs_for_callback.lock().unwrap();
            logs.push_back(format!("Match for pattern '{}'!", pattern));
            logs.push_back(format!("Address: {}", address));
            logs.push_back(format!("Position: {}", position));
            logs.push_back(format!("Seed ({}-word): {}", word_count, mnemonic));
            logs.push_back("---------------------------".to_string());
            while logs.len() > MAX_LOG_ENTRIES {
                logs.pop_front();
            }
        });

        let location = if start_match { "starting with" } else if end_match { "ending with" } else { "containing" };
        // Make sure both branches return a String.
        let seed_type = if word_count == 0 { "random (12/15/24)".to_string() } else { word_count.to_string() };
        let seed_suffix = if word_count != 0 { "-word seed phrases" } else { "" };
        self.add_log(&format!(
            "Starting search for {} addresses {} {} patterns {}",
            num_results,
            if balanced { "balanced across" } else { "matching" },
            patterns_clone.len(),
            location
        ));
        self.add_log(&format!(
            "Using {}{}, checking {} addresses per seed",
            seed_type, seed_suffix, addresses_per_seed
        ));

        self.results.lock().unwrap().clear();
        static LAST_LOGGED_COUNT: AtomicUsize = AtomicUsize::new(0);
        LAST_LOGGED_COUNT.store(0, Ordering::Relaxed);

        self.promise = Some(Promise::spawn_thread("address_search", move || {
            let matcher = PatternMatcher::new(patterns_clone.clone(), case_sensitive, start_match, end_match);
            let thread_count = processor.get_stats().4;
            let stats_clone = stats.clone();
            let results_for_logging = results.clone();
            let previously_found = Arc::new(AtomicUsize::new(0));

            processor.set_progress_callback(move |seeds, addresses, seed_rate, addr_rate| {
                static LAST_UPDATE: AtomicUsize = AtomicUsize::new(0);
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as usize;
                let last_update = LAST_UPDATE.load(Ordering::Relaxed);
                if now - last_update > 100 {
                    *stats_clone.lock().unwrap() = Some((seeds, addresses, seed_rate, addr_rate, thread_count));
                    LAST_UPDATE.store(now, Ordering::Relaxed);
                    let current_count = results_for_logging.lock().unwrap().len();
                    let prev_count = previously_found.load(Ordering::Relaxed);
                    if current_count > prev_count {
                        previously_found.store(current_count, Ordering::Relaxed);
                    }
                }
            });

            let _matches = processor.find_matches(matcher, word_count, num_results, balanced, addresses_per_seed);
            let final_stats = processor.get_stats();
            *stats.lock().unwrap() = Some(final_stats);
            *running.lock().unwrap() = false;
        }));

        // Switch tab to Results if matches are found.
        for entry in self.logs.iter() {
            if entry.contains("Match") {
                self.current_tab = Tab::Results;
                break;
            }
        }
    }

    /// Stops the search.
    fn stop_search(&mut self) {
        *self.running.lock().unwrap() = false;

        let processor_clone = self.processor.clone();

        if let Some(processor) = processor_clone {
            processor.cancel();
            std::thread::sleep(std::time::Duration::from_millis(50));
            processor.reset();
            self.add_log("Search cancelled");
        } else {
            self.add_log("No active search to cancel");
        }

        self.promise = None;
    }

    /// Adds a log entry with a timestamp.
    fn add_log(&mut self, message: &str) {
        let time = Local::now().format("%H:%M:%S").to_string();
        let log_entry = format!("[{}] {}", time, message);
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(log_entry);
    }

    /// Displays the statistics in the Status tab.
    fn show_stats(&self, ui: &mut Ui, stats: (usize, usize, f64, f64, usize)) {
        let (total_seeds, total_addresses, seed_rate, address_rate, threads) = stats;
        let frame = egui::Frame::dark_canvas(&ui.ctx().style())
            .rounding(egui::Rounding::same(6.0))
            .inner_margin(12.0);
        frame.show(ui, |ui| {
            ui.heading("Statistics");
            ui.add_space(8.0);
            egui::Grid::new("stats_grid")
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Threads:");
                    ui.label(format!("{}", threads));
                    ui.end_row();

                    ui.label("Seeds checked:");
                    ui.label(format!("{}", total_seeds));
                    ui.end_row();

                    ui.label("Addresses checked:");
                    ui.label(format!("{}", total_addresses));
                    ui.end_row();

                    ui.label("Seed rate:");
                    ui.label(RichText::new(format!("{:.0} seeds/second", seed_rate))
                        .color(if seed_rate > 0.0 { Color32::from_rgb(152, 195, 121) } else { Color32::LIGHT_GRAY }));
                    ui.end_row();

                    ui.label("Address rate:");
                    ui.label(RichText::new(format!("{:.0} addresses/second", address_rate))
                        .color(if address_rate > 0.0 { Color32::from_rgb(152, 195, 121) } else { Color32::LIGHT_GRAY }));
                    ui.end_row();
                });
        });
    }

    /// Renders the header with the logo and application title.
    fn render_app_header(&self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(8.0);
            // Draw the Ergo logo (Sigma in an octagon)
            let logo_size = 60.0;
            let (logo_rect, logo_response) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
            if ui.is_rect_visible(logo_rect) {
                self.draw_ergo_logo(ui.painter(), logo_rect);
            }
            if logo_response.hovered() {
                egui::show_tooltip(ui.ctx(), egui::Id::new("ergo_logo_tooltip"), |ui| {
                    ui.label("Ergo Platform");
                });
            }
            ui.add_space(5.0);
            let app_title = RichText::new("Vanity Address Generator")
                .color(Color32::from_rgb(221, 67, 56))
                .strong()
                .italics()
                .size(24.0);
            ui.label(app_title);
            ui.add_space(8.0);
        });
        ui.separator();
    }

    /// Draws the Ergo logo – a white sigma (Σ) inside an octagon.
    fn draw_ergo_logo(&self, painter: &egui::Painter, rect: egui::Rect) {
        let center = rect.center();
        let size = rect.width().min(rect.height());
        let stroke_color = Color32::WHITE;
        let sigma_color = Color32::WHITE;

        let octagon_radius = size * 0.45;
        let mut octagon_points = Vec::with_capacity(8);
        for i in 0..8 {
            let angle = std::f32::consts::PI / 2.0 + i as f32 * (std::f32::consts::PI / 4.0);
            let x = center.x + octagon_radius * angle.cos();
            let y = center.y + octagon_radius * angle.sin();
            octagon_points.push(egui::Pos2::new(x, y));
        }
        painter.add(egui::Shape::closed_line(
            octagon_points,
            egui::Stroke::new(2.0, stroke_color),
        ));

        let sigma_text = "Σ";
        let font_id = egui::FontId::proportional(size * 0.5);
        let sigma_galley = painter.ctx().fonts(|f| {
            f.layout_no_wrap(sigma_text.to_string(), font_id.clone(), sigma_color)
        });
        let text_rect = sigma_galley.rect;
        let text_pos = center - 0.5 * text_rect.size();
        painter.galley(text_pos, sigma_galley, sigma_color);
    }

    /// Displays the Status tab with running status, stats, and configuration.
    fn show_status(&mut self, ui: &mut Ui) {
        ui.vertical(|ui| {
            let frame = egui::Frame::dark_canvas(&ui.ctx().style())
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(12.0);
            frame.show(ui, |ui| {
                let is_running = *self.running.lock().unwrap();
                ui.horizontal(|ui| {
                    ui.heading("Status:");
                    ui.add_space(8.0);
                    if is_running {
                        let elapsed = self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
                        ui.heading(RichText::new(format!("Running ({:02}:{:02})", elapsed / 60, elapsed % 60))
                            .color(Color32::from_rgb(152, 195, 121)));
                        let time = ui.input(|i| i.time);
                        let size = 18.0;
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
                        let painter = ui.painter();
                        let center = rect.center();
                        let radius = size / 2.0 * 0.8;
                        let angle = time % 1.0 * std::f64::consts::TAU;
                        painter.circle_stroke(center, radius, egui::Stroke::new(2.0, Color32::from_rgb(152, 195, 121)));
                        let points = 8;
                        for i in 0..points {
                            let t = (i as f64 / points as f64 + angle) % 1.0;
                            let angle = t * std::f64::consts::TAU;
                            let dist = radius * 0.8;
                            let pos = center + egui::vec2((angle.cos() * dist as f64) as f32, (angle.sin() * dist as f64) as f32);
                            let alpha = (t * 255.0) as u8;
                            painter.circle_filled(pos, 2.0, Color32::from_rgba_unmultiplied(152, 195, 121, alpha));
                        }
                    } else if self.start_time.is_some() {
                        ui.heading(RichText::new("Stopped").color(Color32::from_rgb(229, 192, 123)));
                    } else {
                        ui.heading(RichText::new("Ready").color(Color32::LIGHT_GRAY));
                    }
                });
            });
            ui.add_space(12.0);
            if let Some(stats) = *self.stats.lock().unwrap() {
                self.show_stats(ui, stats);
            } else {
                let frame = egui::Frame::dark_canvas(&ui.ctx().style())
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(12.0);
                frame.show(ui, |ui| {
                    ui.heading("Statistics");
                    ui.add_space(4.0);
                    ui.label(RichText::new("Start a search to see performance statistics")
                        .color(Color32::LIGHT_GRAY).italics());
                });
            }
            ui.add_space(12.0);

            frame.show(ui, |ui| {
                ui.heading("Current Configuration");
                ui.add_space(8.0);
                egui::Grid::new("config_grid")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Patterns:");
                        let patterns: Vec<String> = self.input_patterns
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        ui.label(if patterns.is_empty() { "None".to_string() } else { patterns.join(", ") });
                        ui.end_row();
                        ui.label("Match type:");
                        let match_type = if self.start_match { "Start" } else if self.end_match { "End" } else { "Anywhere" };
                        ui.label(match_type);
                        ui.end_row();
                        ui.label("Case sensitive:");
                        ui.label(if self.case_sensitive { "Yes" } else { "No" });
                        ui.end_row();
                        ui.label("Seed length:");
                        let seed_type = if self.all_word_lengths { "Random (12/15/24)".to_string() }
                            else if self.twelve_words { "12-word".to_string() }
                            else if self.fifteen_words { "15-word".to_string() }
                            else { "24-word".to_string() };
                        ui.label(seed_type);
                        ui.end_row();
                        ui.label("Addresses per seed:");
                        ui.label(self.addresses_per_seed.to_string());
                        ui.end_row();
                        ui.label("Results to find:");
                        ui.label(self.num_results.to_string());
                        ui.end_row();
                        ui.label("Balanced matching:");
                        ui.label(if self.balanced { "Yes" } else { "No" });
                        ui.end_row();
                    });
            });
        });
    }

    /// Displays the Results tab.
    fn show_results(&mut self, ui: &mut Ui) {
        ui.heading(RichText::new("Found Matches").size(24.0).color(Color32::WHITE));
        ui.add_space(8.0);

        // Add security options
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.mask_seed_phrases, "Mask seed phrases")
                .on_hover_text("Hide seed phrases for security");

            if ui.button("Security Tips").clicked() {
                self.show_security_warning = true;
            }
        });

        // Security warning popup
        if self.show_security_warning {
            egui::Window::new("⚠️ Security Warning")
                .collapsible(false)
                .resizable(false)
                .min_width(400.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .frame(egui::Frame::window(&ui.ctx().style()).fill(Color32::from_rgb(240, 240, 240)))
                .show(ui.ctx(), |ui| {
                    ui.label(RichText::new("Security Best Practices").strong().size(16.0));
                    ui.separator();
                    ui.label("• Use at your own risk; The author assumes no responsibility for loss of funds.");
                    ui.label("• Verify seed phrase restores the correct wallet");
                    ui.label("• Keep seed phrases private - never share them");
                    ui.label("• Use paper wallets in a secure, offline environment");
                    ui.label("• Clear clipboard after copying sensitive data");
                    ui.label("• Consider BIP39 passphrase for additional security");
                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        self.show_security_warning = false;
                    }
                });
        }

        let results = self.results.lock().unwrap().clone();
        ui.label(RichText::new(format!("Total matches found: {}", results.len())).strong());
        ui.add_space(4.0);
        if results.is_empty() {
            let available_size = ui.available_size();
            let text_size = ui.text_style_height(&egui::TextStyle::Body);
            ui.allocate_space(egui::vec2(0.0, (available_size.y - text_size) / 3.0));
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No matches found yet...")
                    .color(Color32::LIGHT_GRAY).size(18.0));
                ui.add_space(10.0);
                if *self.running.lock().unwrap() {
                    ui.label(RichText::new("Search is running. Matches will appear here automatically.")
                        .color(Color32::LIGHT_GRAY).italics());
                } else {
                    ui.label(RichText::new("Start a search to find matches.")
                        .color(Color32::LIGHT_GRAY).italics());
                }
            });
        } else {
            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                for (i, result) in results.iter().enumerate() {
                    let (mnemonic, address, pattern, position, word_count) = result;
                    let frame = egui::Frame::dark_canvas(&ui.ctx().style())
                        .stroke(egui::Stroke::new(1.0, Color32::from_gray(100)))
                        .inner_margin(10.0)
                        .outer_margin(5.0)
                        .rounding(8.0);
                    frame.show(ui, |ui| {
                        ui.colored_label(Color32::from_rgb(220, 220, 255), format!("Match #{}: Pattern \"{}\"", i + 1, pattern));
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.strong("Address: ");
                            ui.label(RichText::new(address).color(Color32::LIGHT_GREEN));
                            if ui.small_button("📋 Copy").clicked() {
                                ui.output_mut(|o| o.copied_text = address.clone());
                                self.add_log("Address copied to clipboard");
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.strong("Position: ");
                            ui.label(position.to_string());
                        });
                        ui.horizontal(|ui| {
                            ui.strong(format!("Seed phrase ({}-word):", word_count));
                        });

                        // Show masked or unmasked seed phrase based on user preference
                        if self.mask_seed_phrases {
                            ui.horizontal(|ui| {
                                let masked_seed = self.mask_sensitive_data(mnemonic);
                                ui.label(RichText::new(masked_seed).monospace().color(Color32::LIGHT_YELLOW));

                                if ui.small_button("👁 Show").clicked() {
                                    // Set the current seed to be shown in a modal
                                    self.show_unmasked_seed = true;
                                    self.current_unmasked_seed = mnemonic.clone();
                                }
                            });
                        } else {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(mnemonic).monospace().color(Color32::LIGHT_YELLOW));
                            });
                        }

                        ui.horizontal(|ui| {
                            if ui.small_button("📋 Copy seed").clicked() {
                                ui.output_mut(|o| o.copied_text = mnemonic.clone());
                                self.add_log("Seed phrase copied to clipboard - clear clipboard when done!");

                                // Prompt user to clear clipboard after 60 seconds
                                let ctx = ui.ctx().clone();
                                std::thread::spawn(move || {
                                    std::thread::sleep(std::time::Duration::from_secs(60));
                                    ctx.request_repaint(); // Request repaint to show the notification
                                });
                            }

                            // Add paper wallet generation button
                            if ui.small_button("📄 Generate Paper Wallet").clicked() {
                                let paper_wallet_info = PaperWalletInfo {
                                    address: address.clone(),
                                    mnemonic: mnemonic.clone(),
                                    word_count: *word_count,
                                    position: *position,
                                };

                                self.generate_paper_wallet(paper_wallet_info);
                            }
                        });
                    });
                    ui.add_space(5.0);
                }
            });
        }
    }

    /// Generate a paper wallet HTML and prompt user to save it
    fn generate_paper_wallet(&mut self, info: PaperWalletInfo) {
        // Open a save file dialog
        match FileDialog::new()
            .set_title("Save Paper Wallet")
            .set_directory(".")
            .set_file_name(format!("ergo-paper-wallet-{}.html", &info.address[..10]))
            .add_filter("HTML Files", &["html"])
            .save_file() {
                Some(path) => {
                    // Generate the paper wallet HTML
                    match crate::paper_wallet::generate_paper_wallet(&info, &path, None) {
                        Ok(_) => {
                            self.add_log(&format!("Paper wallet saved to {}", path.display()));

                            // Try to open the HTML file in the default browser
                            #[cfg(target_os = "windows")]
                            {
                                let _ = std::process::Command::new("cmd")
                                    .args(&["/C", "start", "", path.to_str().unwrap_or("")])
                                    .spawn();
                            }

                            #[cfg(target_os = "linux")]
                            {
                                let _ = std::process::Command::new("xdg-open")
                                    .arg(&path)
                                    .spawn();

                                self.add_log("Opening paper wallet in your browser...");
                            }

                            #[cfg(target_os = "macos")]
                            {
                                let _ = std::process::Command::new("open")
                                    .arg(&path)
                                    .spawn();
                            }
                        },
                        Err(e) => {
                            self.add_log(&format!("Error generating paper wallet: {}", e));
                        }
                    }
                },
                None => {
                    // User cancelled the dialog
                    self.add_log("Paper wallet generation cancelled");
                }
            }
    }

    /// Displays the Log tab.
    fn show_log(&mut self, ui: &mut Ui) {
        ui.heading("Log");
        ui.add_space(4.0);
        let frame = egui::Frame::dark_canvas(&ui.ctx().style())
            .rounding(egui::Rounding::same(6.0))
            .inner_margin(8.0);
        frame.show(ui, |ui| {
            if ui.button("Clear Log").clicked() && !self.logs.is_empty() {
                self.logs.clear();
                self.add_log("Log cleared");
            }
            ui.add_space(4.0);
            ScrollArea::vertical()
                .stick_to_bottom(true)
                .max_height(ui.available_height() - 40.0)
                .show(ui, |ui| {
                    if self.logs.is_empty() {
                        ui.weak("No log entries yet.");
                    } else {
                        for log in &self.logs {
                            let log_entry = if log.contains("Error:") || log.contains("error") {
                                RichText::new(log).color(Color32::from_rgb(224, 108, 117))
                            } else if log.contains("Match found") {
                                RichText::new(log).color(Color32::from_rgb(152, 195, 121))
                            } else if log.contains("Starting search") {
                                RichText::new(log).color(Color32::from_rgb(97, 175, 239))
                            } else if log.contains("copied") {
                                RichText::new(log).color(Color32::from_rgb(198, 160, 246))
                            } else if log.contains("stopped") {
                                RichText::new(log).color(Color32::from_rgb(229, 192, 123))
                            } else {
                                RichText::new(log).color(Color32::LIGHT_GRAY)
                            };
                            ui.label(log_entry);
                        }
                    }
                });
        });
    }

    /// Add a new helper function to mask sensitive data
    fn mask_sensitive_data(&self, data: &str) -> String {
        let words: Vec<&str> = data.split_whitespace().collect();
        let mut masked = String::new();

        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                masked.push(' ');
            }

            if word.len() <= 2 {
                masked.push_str(word);
            } else {
                // Show first character and last character, mask the rest
                let first = word.chars().next().unwrap();
                let last = word.chars().last().unwrap();
                let mask_len = word.len() - 2;
                masked.push(first);
                masked.push_str(&"•".repeat(mask_len));
                masked.push(last);
            }
        }

        masked
    }

    /// Handle window close event
    fn handle_window_close(&mut self) {
        if *self.running.lock().unwrap() {
            self.add_log("Window closing - stopping search...");
            self.stop_search();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if let Some(processor) = &self.processor {
            processor.cancel();
        }
        self.promise = None;
    }

    /// Validates input patterns and returns invalid characters if any
    fn validate_patterns(&self) -> Option<Vec<char>> {
        let patterns: Vec<String> = self.input_patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut invalid_chars = Vec::new();

        for pattern in patterns {
            for c in pattern.chars() {
                if !self.is_base58_char(c) && !invalid_chars.contains(&c) {
                    invalid_chars.push(c);
                }
            }
        }

        if invalid_chars.is_empty() {
            None
        } else {
            Some(invalid_chars)
        }
    }

    /// Check if character is valid Base58
    fn is_base58_char(&self, c: char) -> bool {
        match c {
            '0' | 'O' | 'I' | 'l' => false,
            '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z' => true,
            _ => false,
        }
    }
}

/// Runs the GUI application.
pub fn run_gui() -> Result<(), eframe::Error> {
    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 768.0])
            .with_min_inner_size([1024.0, 600.0]),
        vsync: true,
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,
        follow_system_theme: false,
        default_theme: eframe::Theme::Dark,
        ..Default::default()
    };

    eframe::run_native("Ergo Vanitygen", options, Box::new(|_cc| Box::new(VanityGenApp::default())))
}
