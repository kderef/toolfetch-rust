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
**winapi**             ==> dialog box for windows       (windows only)  
**libmath**            ==> round function for disk size (all platforms)  
**easy-http-request**  ==> GET requests                 (windows only)  
**num_cpus**           ==> get cpu cores                (unix only)  
**winres**             ==> add icon to exe              (windows only)  

---  
# TODO  
- [x] add *disk info* segment to UI  
- [x] linux/mac support
- [ ] light theme
- [ ] add taskbar icon
