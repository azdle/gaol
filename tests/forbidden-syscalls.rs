// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

extern crate gaol;
extern crate libc;

#[cfg(target_os="linux")]
use gaol::profile::Profile;
#[cfg(target_os="linux")]
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
#[cfg(target_os="linux")]
use libc::c_int;
#[cfg(target_os="linux")]
use std::env;

#[cfg(target_os="linux")]
use gaol::platform::linux::seccomp::ALLOWED_SYSCALLS;

#[cfg(target_os="linux")]
const MAX_SYSCALL: u32 = 400;

#[cfg(target_os="linux")]
fn profile() -> Profile {
    Profile::new(Vec::new()).unwrap()
}

#[cfg(target_os="linux")]
fn test_syscall(number: c_int) {
    ChildSandbox::new(profile()).activate().unwrap();
    unsafe {
        syscall(number, -1, -1, -1, -1, -1, -1);
    }
}

#[cfg(target_os="linux")]
pub fn main() {
    if let Some(arg) = env::args().skip(1).next() {
        return test_syscall(arg.parse().unwrap())
    }

    for syscall in 0..MAX_SYSCALL {
        if ALLOWED_SYSCALLS.iter().any(|number| *number == syscall) {
            continue
        }
        let arg = format!("{}", syscall);
        let status = Sandbox::new(profile()).start(&mut Command::me().unwrap().arg(&arg[..]))
                                            .unwrap()
                                            .wait()
                                            .unwrap();
        assert!(!status.success());
    }
}

#[cfg(not(target_os="linux"))]
fn main() {}

#[cfg(target_os="linux")]
extern {
    fn syscall(number: c_int, ...) -> c_int;
}

