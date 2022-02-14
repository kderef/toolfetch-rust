#![windows_subsystem = "windows"]
mod ui;

const WINDOW_SIZE: druid::Size = druid::Size {
    width: 450.0,
    height: 0.0,
};
const WINDOW_TITLE: druid::LocalizedString<ui::State> =
    druid::LocalizedString::new("Kian's ToolFetch");

fn main() {
    ui::start(WINDOW_SIZE, WINDOW_TITLE);
}