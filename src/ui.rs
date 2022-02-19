#![allow(dead_code)]
#![allow(unused_assignments)]

use druid::{
    widget::{Align, Button, CrossAxisAlignment, Flex, FlexParams, Label, MainAxisAlignment},
    AppLauncher, Data, Env, Lens, LocalizedString, Widget, WindowDesc,
};
use easy_http_request::DefaultHttpRequest;
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
impl Default for State {
    fn default() -> State {
        State {
            cpu: String::new(),
            ram: 0,
            ip4: (String::new(), String::new()),
            ip6: (String::new(), String::new()),
            subnet: String::new(),
            hostname: OS::hostname(),
            username: OS::username(),
            host_os: String::new(),
        }
    }
}
#[cfg(target_os = "windows")]
pub fn dialog(title: &str, text: &str) {
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
pub fn start(window_title: LocalizedString<State>) {
    // describe the main window
    #[cfg(target_os = "macos")]
    let main_window = WindowDesc::new(build_root_widget).title(window_title);
    #[cfg(target_os = "windows")]
    let main_window = WindowDesc::new(build_root_widget)
        .title(window_title)
        .window_size(druid::Size {
            width: 450.0,
            height: 250.0,
        });

    // create the initial app state
    let initial_state = State::default();

    // start the application
    AppLauncher::with_window(main_window)
        .launch(initial_state)
        .expect("Failed to launch application");
}
fn build_root_widget() -> impl Widget<State> {
    let lbl_username =
        Label::new(|data: &State, _env: &Env| format!("username: {}", data.username));
    let lbl_hostname =
        Label::new(|data: &State, _env: &Env| format!("computername: {}", data.hostname));
        //control desk.cpl
    let btn_display = Button::new("display properties").on_click(|_ctx, _data: &mut State, _env: &Env| {
        Command::new("control.exe")
            .arg("desk.cpl")
            .spawn()
            .expect("couldn't start control.exe desk.cpl");
    });

    let btn_hardware = Button::new("hardware").on_click(|_ctx, _data: &mut State, _env: &Env| {
        let cpu = Hardware::cpu();
        let ram = Hardware::ram();
        let (size, free, used) = Disk::new_tup();

        let msg = format!(
            "cpu : {}\ncpu cores : {}\nram : {}GB\n\ndisk:\n     size => {}GB\n     free => {}GB\n     used => {}GB",
            cpu.0, cpu.1, ram, size, free, used
        );

        dialog("Hardware Info", msg.as_str())
    });
    let btn_ip_i = Button::new("internal IPs").on_click(|_ctx, _data: &mut State, _env: &Env| {
        let ips = (Network::private_ip4(), Network::private_ip6());
        let gateway = output_from(vec!["(Get-NetRoute \"0.0.0.0/0\").NextHop"]);

        dialog(
            "Internal IPs",
            format!(
                "IPv4\t\t{}\nsubnet mask\t{}\ndefault gateway\t{}\nIPv6\t\t{}",
                ips.0,
                subnet(&ips.0),
                gateway.trim(),
                ips.1
            )
            .as_str(),
        );
    });
    let btn_ip_e = Button::new("external IPs").on_click(|_ctx, _data: &mut State, _env: &Env| {
        let ips = (Network::public_ip4(), Network::public_ip6());

        dialog(
            "External IPs",
            format!("IPv4\t{}\nIPv6\t{}", ips.0, ips.1).as_str(),
        );
    });
    let btn_task = Button::new("task manager").on_click(|_ctx, _data: &mut State, _env: &Env| {
        Command::new("cmd.exe")
            .args(["/c", "start", "taskmgr"])
            .spawn()
            .expect("couldn't start task manager");
    });
    let btn_control =
        Button::new("control panel").on_click(|_ctr, _data: &mut State, _env: &Env| {
            Command::new("control.exe")
                .spawn()
                .expect("couldn't start control.exe");
        });
    let btn_printers =
        Button::new("devices & printers").on_click(|_ctr, _data: &mut State, _env: &Env| {
            Command::new("control.exe")
                .arg("printers")
                .spawn()
                .expect("couldn't run control.exe printers");
        });
    let btn_cmd = Button::new("command prompt").on_click(|_ctx, _data: &mut State, _env: &Env| {
        Command::new("cmd.exe")
            .args(["/c", "start"])
            .spawn()
            .expect("cmd.exe failed to run");
    });
    let btn_programs =
        Button::new("install/remove programs").on_click(|_ctx, _data: &mut State, _env: &Env| {
            Command::new("control.exe")
                .arg("appwiz.cpl")
                .spawn()
                .expect("failed to run control.exe");
        });
    let btn_network =
        Button::new("network connections").on_click(|_ctx, _data: &mut State, _env: &Env| {
            Command::new("control.exe")
                .arg("ncpa.cpl")
                .spawn()
                .expect("failed to run control.exe");
        });
    let btn_admin = Button::new("admin tools").on_click(|_ctx, _data: &mut State, _env: &Env| {
        Command::new("control.exe")
            .args(["/name", "Microsoft.AdministrativeTools"])
            .spawn()
            .expect("failed to run control.exe");
    });

    let btn_features =
        Button::new("windows features").on_click(|_ctx, _data: &mut State, _env: &Env| {
            Command::new("rundll32.exe")
                .args(["shell32.dll,Control_RunDLL", "appwiz.cpl,,2"])
                .spawn()
                .expect("failed to run control.exe");
        });

    // arrange the widgets vertically, with some padding
    let mut layout = Flex::column()
        .cross_axis_alignment(CrossAxisAlignment::Start)
        .with_child(lbl_username)
        .with_child(lbl_hostname)
        .with_flex_spacer(0.3)
        .with_child(
            Flex::row()
                .cross_axis_alignment(CrossAxisAlignment::Start)
                .with_child(btn_ip_i)
                .with_child(btn_ip_e)
                .with_child(btn_hardware),
        )
        .with_flex_spacer(0.3)
        .with_flex_child(
            btn_control,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        )
        .with_flex_spacer(0.1)
        .with_flex_child(
            btn_network,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        )
        .with_flex_spacer(0.1)
        .with_flex_child(
            btn_programs,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        )
        .with_flex_spacer(0.1)
        .with_flex_child(btn_display, FlexParams::new(1.0, CrossAxisAlignment::Center))
        .with_flex_spacer(0.1)
        .with_flex_child(btn_cmd, FlexParams::new(1.0, CrossAxisAlignment::Center))
        .with_flex_spacer(0.1)
        .with_flex_child(btn_task, FlexParams::new(1.0, CrossAxisAlignment::Center))
        .with_flex_spacer(0.1)
        .with_flex_child(
            btn_printers,
            FlexParams::new(1.0, CrossAxisAlignment::Center),
        )
        .with_flex_spacer(0.1)
        .with_flex_child(btn_admin, FlexParams::new(1.0, CrossAxisAlignment::Center))
        .with_flex_spacer(0.1)
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
#[cfg(target_os = "windows")]
pub fn get(url: &str) -> String {
    let response = DefaultHttpRequest::get_from_url_str(url)
        .unwrap()
        .send()
        .unwrap();
    return String::from_utf8(response.body).unwrap();
}
fn getenv(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(val) => return val,
        Err(_e) => return default.to_string(),
    }
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
    if args.is_empty() {
        return String::from("None");
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
impl OS {
    pub fn username() -> String {
        #[cfg(target_os = "windows")]
        return getenv("USERNAME", "undefined");
        #[cfg(not(target_os = "windows"))]
        return getenv("USER", "undefined");
    }
    #[cfg(target_os = "windows")]
    pub fn hostname() -> String {
        return getenv("COMPUTERNAME", "undefined");
    }
    #[cfg(not(target_os = "windows"))]
    pub fn hostname() -> String {
        let mut command = Command::new("hostname");
        let output = command.stdout(Stdio::piped()).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        return stdout.trim().to_string();
    }
    #[cfg(target_os = "windows")]
    pub fn os_version() -> String {
        let raw = output_from(vec!["(Get-WmiObject -class Win32_OperatingSystem).Caption"]);
        return raw.trim().to_string();
    }
    #[cfg(target_os = "macos")]
    pub fn os_version() -> String {
        let mut command = Command::new("sw_vers");
        let output = command.stdout(Stdio::piped()).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let os = stdout.split("\n").collect::<Vec<&str>>();
        return format!(
            "{} {} {}",
            os[0].replace("ProductName:", "").trim().to_string(),
            os[1].replace("ProductVersion:", "").trim().to_string(),
            os[2].replace("BuildVersion:", "").trim().to_string()
        );
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
        let mut cpu_r = Command::new("sysctl");
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
        get("http://ifconfig.me/ip")
    }
    pub fn public_ip6() -> String {
        get("https://api6.ipify.org")
    }
}
#[cfg(target_os = "macos")]
impl Network {
    pub fn private_ip4() -> String {
        let mut command = Command::new("ipconfig");
        command.args(["getifaddr", "en0"]);

        let output = command.stdout(Stdio::piped()).output().unwrap();
        return String::from_utf8(output.stdout).unwrap().trim().to_string();
    }
    pub fn private_ip6() -> String {
        // TODO
        return String::from("0");
    }
    pub fn public_ip4() -> String {
        let mut command = Command::new("curl");
        command.arg("http://ifconfig.me/ip");

        let output = command.stdout(Stdio::piped()).output().unwrap();
        return String::from_utf8(output.stdout).unwrap();
    }
    pub fn public_ip6() -> String {
        let mut command = Command::new("curl");
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
    pub fn new_tup() -> (f64, f64, f64) {
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
        return (
            round::floor(totalspace as f64 / 1073741824 as f64, 2),
            round::floor(freespace as f64 / 1073741824 as f64, 2),
            round::floor(usedspace as f64 / 1073741824 as f64, 2),
        );
    }
}
