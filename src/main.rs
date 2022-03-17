#![windows_subsystem = "windows"]
mod ui;
use ui::start;

const WINDOW_TITLE: druid::LocalizedString<ui::State> =
    druid::LocalizedString::new("Kian's ToolFetch");
    
fn main() {
    #[cfg(target_os = "windows")]
    std::thread::spawn(move || {
        ui::dialog("Info", "the application is starting, this may take some time.");
    });
    start(WINDOW_TITLE);
}
