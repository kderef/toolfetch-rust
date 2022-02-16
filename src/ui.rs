#![allow(dead_code)]
#![allow(unused_assignments)]

use druid::{
    widget::{Align, Button, CrossAxisAlignment, Flex, FlexParams, Label, MainAxisAlignment},
    AppLauncher, Data, Env, Lens, LocalizedString, Widget, WindowDesc,
};
use math::round;
use std::env;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

#[cfg(target_os = "windows")]
use std::ptr::null_mut as NULL;
#[cfg(target_os = "windows")]
use winapi::um::winuser;

pub struct Hardware;
pub struct OS;
pub struct Network;

pub struct Disk {
    pub capacity: f64,
    pub free: f64,
    pub used: f64,
}

#[derive(Clone, Data, Lens)]
struct _State {
    name: String,
}

#[derive(Clone, Data, Lens)]
pub struct State {
    cpu: String,
    ram: i32,
    ip4: (String, String),
    ip6: (String, String),
    subnet: String,
    hostname: String,
    username: String,
    host_os: String,
}
#[cfg(target_os = "windows")]
fn dialog(title: &str, text: &str) {
    let mut message_n = text.to_string();
    let mut title_n = title.to_string();
    message_n.push('\0');
    title_n.push('\0');

    let l_msg: Vec<u16> = message_n.as_str().encode_utf16().collect::<Vec<u16>>();
    let l_title: Vec<u16> = title_n.as_str().encode_utf16().collect::<Vec<u16>>();
    unsafe {
        winuser::MessageBoxW(
            NULL(),
            l_msg.as_ptr(),
            l_title.as_ptr(),
            winuser::MB_OK | winuser::MB_ICONINFORMATION,
        );
    }
}
pub fn start(window_size: druid::Size, window_title: LocalizedString<State>) {
    // describe the main window
    let main_window = WindowDesc::new(build_root_widget)
        .title(window_title)
        .window_size(window_size);

    // create the initial app state
    let ip4_static = Network::private_ip4();
    let cpu = Hardware::cpu();
    let initial_state = State {
        cpu: format!("{} with {} cores", cpu.0, cpu.1),
        ram: Hardware::ram(),
        ip4: (Network::private_ip4(), Network::public_ip4()),
        ip6: (Network::private_ip6(), Network::public_ip6()),
        subnet: subnet(&ip4_static.to_string()).to_string(),
        host_os: OS::windows_version(),
        username: OS::username(),
        hostname: OS::hostname(),
    };

    // start the application
    AppLauncher::with_window(main_window)
        .launch(initial_state)
        .expect("Failed to launch application");
}
fn build_root_widget() -> impl Widget<State> {
    let lbl_username =
        Label::new(|data: &State, _env: &Env| format!("username: {}", data.username));
    let lbl_hostname =
        Label::new(|data: &State, _env: &Env| format!("hostname: {}", data.hostname));

    let lbl_cpu = Label::new(|data: &State, _env: &Env| format!("cpu: {}", data.cpu));
    let lbl_ram = Label::new(|data: &State, _env: &Env| format!("ram: {}GB", data.ram));
    let lbl_ip4_i = Label::new(|data: &State, _env: &Env| {
        format!("[internal] ip4: {}/{}", data.ip4.0, data.subnet)
    });
    let lbl_ip6_i =
        Label::new(|data: &State, _env: &Env| format!("[internal] ip6: {}", data.ip6.0));
    let lbl_ip4_e =
        Label::new(|data: &State, _env: &Env| format!("[external] ip4: {}", data.ip4.1));
    let lbl_ip6_e =
        Label::new(|data: &State, _env: &Env| format!("[external] ip6: {}", data.ip6.1));

    let btn_programs =
        Button::new("install/remove programs").on_click(|_ctx, _data: &mut State, _env: &Env| {
            let _ = std::process::Command::new("control.exe")
                .arg("appwiz.cpl")
                .spawn()
                .expect("failed to run control.exe");
        });
    let btn_network =
        Button::new("network connections").on_click(|_ctx, _data: &mut State, _env: &Env| {
            let _ = std::process::Command::new("control.exe")
                .arg("ncpa.cpl")
                .spawn()
                .expect("failed to run control.exe");
        });
    let btn_admin = Button::new("admin tools").on_click(|_ctx, _data: &mut State, _env: &Env| {
        let _ = std::process::Command::new("control.exe")
            .args(["/name", "Microsoft.AdministrativeTools"])
            .spawn()
            .expect("failed to run control.exe");
    });
    let btn_features =
        Button::new("windows features").on_click(|_ctx, _data: &mut State, _env: &Env| {
            let _ = std::process::Command::new("rundll32.exe")
                .arg("shell32.dll,Control_RunDLL")
                .arg("appwiz.cpl,,2")
                .spawn()
                .expect("failed to run control.exe");
        });

    // arrange the widgets vertically, with some padding
    let mut layout = Flex::column()
        .cross_axis_alignment(CrossAxisAlignment::Start)
        .with_child(lbl_username)
        .with_child(lbl_hostname)
        .with_flex_spacer(0.3)
        .with_child(lbl_cpu)
        .with_child(lbl_ram)
        .with_child(lbl_ip4_i)
        .with_child(lbl_ip6_i)
        .with_child(lbl_ip4_e)
        .with_child(lbl_ip6_e)
        .with_flex_spacer(0.3)
        .with_flex_child(
            btn_programs,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        )
        .with_flex_child(
            btn_network,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        )
        .with_flex_child(btn_admin, FlexParams::new(1.0, CrossAxisAlignment::Center))
        .with_flex_child(
            btn_features,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        );

    layout.set_main_axis_alignment(MainAxisAlignment::Start);
    Align::centered(layout)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

fn subnet(ip4: &String) -> &'static str {
    let octet = ip4.split(".").collect::<Vec<&str>>()[0]
        .parse::<i32>()
        .unwrap_or(0);
    if octet <= 223 && octet >= 192 {
        return "255.255.255.0";
    }
    if octet <= 191 && octet >= 128 {
        return "255.255.0.0";
    }
    if octet <= 127 {
        return "255.0.0.0";
    } else {
        return "0.0.0.0";
    }
}

fn getenv(key: &str, default: &str) -> String {
    let return_val: String;
    match env::var(key) {
        Ok(val) => return_val = val,
        Err(_e) => return_val = default.to_string(),
    }
    return return_val;
}
#[cfg(target_os = "windows")]
fn output_from(args: Vec<&str>) -> String {
    let mut run = Command::new("powershell.exe");
    run.arg("-command");
    run.creation_flags(0x08000000); // do not spawn window

    if args.is_empty() {
        return String::from("None");
    }

    if args.len() == 1 {
        run.arg(args[0]);
    } else {
        for arg in args {
            run.arg(arg);
        }
    }

    let output = run
        // record output
        .stdout(Stdio::piped())
        // execute the command, wait for it to complete, then capture the output
        .output()
        // Blow up if the OS was unable to start the program
        .unwrap();

    // extract the raw bytes that we captured and interpret them as a string
    let stdout = String::from_utf8(output.stdout).unwrap();

    return stdout;
}
#[cfg(not(target_os = "windows"))]
fn output_from(args: Vec<&str>) -> String {
    let mut run = Command::new("bash");
    run.arg("-c");

    match args.len() {
        0 => return String::from("None"),
        1 => run.arg(args[0]),
        _ => {
            for arg in args {
                run.arg(arg);
            }
        }
    }

    let output = run
        // record output
        .stdout(Stdio::piped())
        // execute the command, wait for it to complete, then capture the output
        .output()
        // Blow up if the OS was unable to start the program
        .unwrap();

    // extract the raw bytes that we captured and interpret them as a string
    let stdout = String::from_utf8(output.stdout).unwrap();

    return stdout;
}
impl OS {
    pub fn username() -> String {
        #[cfg(target_os = "windows")]
        return getenv("USERNAME", "undefined");
        #[cfg(not(target_os = "windows"))]
        return getenv("USER", "undefined");
    }
    pub fn hostname() -> String {
        if env::consts::OS == "windows" {
            return getenv("COMPUTERNAME", "undefined");
        } else {
            return getenv("hostname", "undefined");
        }
    }
    pub fn windows_version() -> String {
        if env::consts::OS != "windows" {
            panic!(
                "ERROR: this function is windows only, you are running {}",
                env::consts::OS
            );
        }
        let raw = output_from(vec!["(Get-WmiObject -class Win32_OperatingSystem).Caption"]);
        return raw.trim().to_string();
    }
}
#[cfg(target_os = "windows")]
impl Hardware {
    pub fn cpu() -> (String, i16) {
        let cores = getenv("NUMBER_OF_PROCESSORS", "0").parse::<i16>().unwrap() / 2;
        let cpu_raw = output_from(vec!["WMIC CPU GET NAME"]);
        let cpu_def: Vec<&str> = cpu_raw.trim().split("\n").collect();
        return (cpu_def[1].to_string(), cores);
    }
    pub fn ram() -> i32 {
        let args = vec![
            "[Math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1GB)",
        ];
        let total_ram = output_from(args);
        return total_ram.trim().parse().unwrap();
    }
}
#[cfg(target_os = "macos")]
impl Hardware {
    pub fn cpu() -> (String, i32) {
        // cores //
        let cores = num_cpus::get_physical() as i32;
        // cpu //
        let mut cpu_r = std::process::Command::new("sysctl");
        cpu_r.args(["-n", "machdep.cpu.brand_string"]);
        let output = cpu_r.stdout(Stdio::piped()).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        return (
            stdout.split("\n").collect::<Vec<&str>>()[0].to_string(),
            cores,
        );
    }
    pub fn ram() -> i32 {
        let args = vec!["system_profiler SPHardwareDataType"];
        let total_ram = output_from(args);
        let mut found = false;
        for i in total_ram.split("\n") {
            if i.trim().starts_with("Memory:") {
                found = true;
                return i.trim().split("Memory: ").collect::<Vec<&str>>()[1]
                    .replace("GB", "")
                    .trim()
                    .parse::<i32>()
                    .unwrap();
            }
        }
        if !found {
            return 0;
        } else {
            return 0;
        }
    }
}
#[cfg(target_os = "windows")]
impl Network {
    pub fn private_ip4() -> String {
        let ip = output_from(vec![
            "(Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString",
        ]);
        return ip.trim().to_string();
    }
    pub fn private_ip6() -> String {
        let ip = output_from(vec![
            "(Test-Connection -ComputerName (hostname) -Count 1).IPV6Address.IPAddressToString",
        ]);
        return ip.trim().to_string();
    }
    pub fn public_ip4() -> String {
        let response = output_from(vec![
            "(Invoke-WebRequest -uri http://ifconfig.me/ip).Content",
        ]);
        return response.trim().to_string();
    }
    pub fn public_ip6() -> String {
        let response = output_from(vec![
            "(Invoke-WebRequest -uri https://api6.ipify.org).Content",
        ]);
        return response.trim().to_string();
    }
}
#[cfg(target_os = "macos")]
impl Network {
    pub fn private_ip4() -> String {
        let mut command = std::process::Command::new("ipconfig");
        command.args(["getifaddr", "en0"]);

        let output = command.stdout(Stdio::piped()).output().unwrap();
        return String::from_utf8(output.stdout).unwrap().trim().to_string();
    }
    pub fn private_ip6() -> String {
        // TODO
        return String::from("0");
    }
    pub fn public_ip4() -> String {
        let mut command = std::process::Command::new("curl");
        command.arg("http://ifconfig.me/ip");

        let output = command.stdout(Stdio::piped()).output().unwrap();
        return String::from_utf8(output.stdout).unwrap();
    }
    pub fn public_ip6() -> String {
        let mut command = std::process::Command::new("curl");
        command.arg("https://api6.ipify.org");

        let output = command.stdout(Stdio::piped()).output().unwrap();
        return String::from_utf8(output.stdout).unwrap();
    }
}

// create a new Disk struct
#[cfg(target_os = "windows")]
impl Disk {
    pub fn new() -> Disk {
        let totalspace = output_from(vec!["WMIC logicaldisk get size"])
            .split("\n")
            .collect::<Vec<&str>>()[1]
            .to_string()
            .trim()
            .parse::<i64>()
            .unwrap();
        let freespace = output_from(vec!["WMIC logicaldisk get freespace"])
            .split("\n")
            .collect::<Vec<&str>>()[1]
            .to_string()
            .trim()
            .parse::<i64>()
            .unwrap();
        let usedspace: i64 = totalspace - freespace;

        return Disk {
            capacity: round::floor(totalspace as f64 / 1073741824 as f64, 2),
            free: round::floor(freespace as f64 / 1073741824 as f64, 2),
            used: round::floor(usedspace as f64 / 1073741824 as f64, 2),
        };
    }
}
#[cfg(target_os = "windows")]
impl Disk {
    pub fn new() -> Disk {
        
    }
}