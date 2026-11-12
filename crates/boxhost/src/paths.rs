//! The files in one box directory.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BoxPaths {
    pub dir: PathBuf,
}

impl BoxPaths {
    pub fn new(dir: PathBuf) -> BoxPaths {
        BoxPaths { dir }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    pub fn vm_json(&self) -> PathBuf {
        self.file("vm.json")
    }
    pub fn api_sock(&self) -> PathBuf {
        self.file("api.sock")
    }
    pub fn vsock(&self) -> PathBuf {
        self.file("vsock.sock")
    }
    /// The Cloud Hypervisor multiplexer socket for a guest-initiated port.
    pub fn vsock_port(&self, port: u32) -> PathBuf {
        self.file(&format!("vsock.sock_{port}"))
    }
    pub fn serial(&self) -> PathBuf {
        self.file("serial.log")
    }
    pub fn ch_log(&self) -> PathBuf {
        self.file("ch.log")
    }
    pub fn root_disk(&self) -> PathBuf {
        self.file("root.qcow2")
    }
    pub fn repo_disk(&self) -> PathBuf {
        self.file("repo.img")
    }
    pub fn base_manifest(&self) -> PathBuf {
        self.file("base.json")
    }
    pub fn snapshot_dir(&self) -> PathBuf {
        self.file("snapshot")
    }
    pub fn term_cast(&self) -> PathBuf {
        self.file("term.cast")
    }
    pub fn lands_dir(&self) -> PathBuf {
        self.file("lands")
    }
    pub fn placeholder(&self) -> PathBuf {
        self.file("placeholder")
    }
    /// The longest socket path in the box dir (for sun_path length checks).
    pub fn longest_socket(&self) -> PathBuf {
        self.vsock_port(5003)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_port_naming() {
        let p = BoxPaths::new(PathBuf::from("/b/x"));
        assert!(p.vsock_port(5000).ends_with("vsock.sock_5000"));
    }
}
