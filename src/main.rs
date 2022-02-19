#![windows_subsystem = "windows"]
mod ui;
use ui::start;

const WINDOW_TITLE: druid::LocalizedString<ui::State> =
    druid::LocalizedString::new("Kian's ToolFetch");

fn main() {
    start(WINDOW_TITLE);
}
