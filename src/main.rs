#![windows_subsystem = "windows"]
mod ui;

const WINDOW_TITLE: druid::LocalizedString<ui::State> =
    druid::LocalizedString::new("Kian's ToolFetch");


fn main() {
    ui::start(WINDOW_TITLE);
}
