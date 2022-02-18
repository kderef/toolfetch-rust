#![windows_subsystem = "windows"]
mod ui;
use ui::{start, dialog};

const WINDOW_TITLE: druid::LocalizedString<ui::State> =
    druid::LocalizedString::new("Kian's ToolFetch");

fn main() {
    std::thread::spawn(move || {
        dialog("Info", "the application is starting,\nthis may take some time.");
    });
    start(WINDOW_TITLE);
}
