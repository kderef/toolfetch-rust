# toolfetch-rust
toolfetch GUI in rust

build instructions:  
```
git clone https://github.com/x-kvoid-x/toolfetch-rust
cd toolfetch-rust
cargo build --release
```
the executable will be in target/release/  

# dependencies
[**druid**](https://docs.rs/num_cpus/latest/num_cpus/index.html)            ==> gui toolkit                  (all platforms)  
[**winapi**](https://docs.rs/winapi/0.3.9/winapi/)             ==> dialog box for windows       (windows only)  
[**libmath**](https://docs.rs/libmath/0.2.1/math/)            ==> round function for disk size (all platforms)  
[**easy-http-request**](https://docs.rs/easy-http-request/0.2.12/easy_http_request/)  ==> GET requests                 (windows only)  
[**num_cpus**](https://docs.rs/num_cpus/1.13.1/num_cpus/)           ==> get cpu cores                (unix only)  
[**winres**](https://docs.rs/winres/0.1.12/winres/)             ==> add icon to exe              (windows only)  
test
: test
---  
# TODO  
- [x] add *disk info* segment to UI  
- [x] linux/mac support
- [ ] light theme
- [ ] add taskbar icon
