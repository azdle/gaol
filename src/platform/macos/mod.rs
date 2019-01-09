// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandboxing on Mac OS X via Seatbelt (`sandboxd`).

use platform::unix::process::Process;
use profile::{self, AddressPattern, OperationSupport, OperationSupportLevel, PathPattern, Profile};
use sandbox::{ChildSandboxMethods, Command, SandboxMethods};

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::path::Path;
use std::ptr;
use std::str;

// some examples: https://github.com/pansen/macos-sandbox-profiles
static SANDBOX_PROFILE_PROLOGUE: &'static [u8] = br##"
(version 1)
(deny default)
(allow process-exec)
(allow file-read*
  (regex "^/System/Library")
  (regex "^/usr/lib"))
(allow sysctl-read)
"##;

impl OperationSupport for profile::Operation {
    fn support(&self) -> OperationSupportLevel {
        match *self {
            profile::Operation::FileReadAll(_) |
            profile::Operation::FileReadMetadata(_) |
            profile::Operation::NetworkOutbound(AddressPattern::All) |
            profile::Operation::NetworkOutbound(AddressPattern::Tcp(_)) |
            profile::Operation::NetworkOutbound(AddressPattern::LocalSocket(_)) |
            profile::Operation::SystemInfoRead |
            profile::Operation::PlatformSpecific(Operation::MachLookup(_)) => {
                OperationSupportLevel::CanBeAllowed
            }
        }
    }
}

/// Mac OS X-specific operations.
#[derive(Clone, Debug)]
pub enum Operation {
    /// Lookups to the given Mach service are allowed.
    MachLookup(Vec<u8>),
}

pub struct Sandbox {
    profile: Profile,
}

impl Sandbox {
    pub fn new(profile: Profile) -> Sandbox {
        Sandbox {
            profile: profile,
        }
    }
}

impl SandboxMethods for Sandbox {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn start(&self, command: &mut Command) -> io::Result<Process> {
        command.env("GAOL_CHILD_PROCESS", "1").spawn(&self)
    }
}

impl Sandbox {
    pub fn post_fork_apply(&self, system_profile: CString) -> Result<(),()> {
        let mut err = ptr::null_mut();
        unsafe {
            if sandbox_init(system_profile.as_ptr(), 0, &mut err) == 0 {
                Ok(())
            } else {
                error!("Failed to init sandbox: {:?}", CStr::from_ptr(err));
                sandbox_free_error(err);
                Err(())
            }
        }
    }

    pub fn build_system_sandbox_profile(&self) -> Result<CString, ()> {
        build_system_sandbox_profile(&self.profile)
    }
}

pub struct ChildSandbox {
    profile: Profile,
}

impl ChildSandbox {
    pub fn new(profile: Profile) -> ChildSandbox {
        ChildSandbox {
            profile: profile,
        }
    }
}

impl ChildSandboxMethods for ChildSandbox {
    fn activate(&self) -> Result<(),()> {
        let sys_profile = build_system_sandbox_profile(&self.profile)?;
        let mut err = ptr::null_mut();
        unsafe {
            if sandbox_init(sys_profile.as_ptr(), 0, &mut err) == 0 {
                Ok(())
            } else {
                error!("Failed to init sandbox: {:?}", CStr::from_ptr(err));
                sandbox_free_error(err);
                Err(())
            }
        }
    }
}

fn build_system_sandbox_profile(profile: &Profile) -> Result<CString, ()> {
        let mut sandbox_profile = Vec::new();
        sandbox_profile.write_all(SANDBOX_PROFILE_PROLOGUE).map_err(|_e| ())?;

        // allow exec to process
        /*
        sandbox_profile.write_all(b"(allow process-exec ");
        let process_file_pattern = PathPattern::Literal(command_path);
        write_file_pattern(&mut sandbox_profile, command_file_pattern)?;
        sandbox_profile.write_all(b")");
        */

        for operation in profile.allowed_operations().iter() {
            match *operation {
                profile::Operation::FileReadAll(ref file_pattern) => {
                    sandbox_profile.write_all(b"(allow file-read* ").map_err(|_e| ())?;
                    write_file_pattern(&mut sandbox_profile, file_pattern)?;
                    sandbox_profile.write_all(b")\n").map_err(|_e| ())?;
                }
                profile::Operation::FileReadMetadata(ref file_pattern) => {
                    sandbox_profile.write_all(b"(allow file-read-metadata ").map_err(|_e| ())?;
                    write_file_pattern(&mut sandbox_profile, file_pattern)?;
                    sandbox_profile.write_all(b")\n").map_err(|_e| ())?;
                }
                profile::Operation::NetworkOutbound(ref address_pattern) => {
                    sandbox_profile.write_all(b"(allow system-socket)\n").map_err(|_e| ())?;
                    sandbox_profile.write_all(b"(allow network-outbound").map_err(|_e| ())?;
                    match *address_pattern {
                        AddressPattern::All => {}
                        AddressPattern::Tcp(port) => {
                            write!(&mut sandbox_profile, " (remote tcp \"*:{}\")", port).map_err(|_e| ())?
                        }
                        AddressPattern::LocalSocket(ref path) => {
                            sandbox_profile.write_all(b"( literal ").map_err(|_e| ())?;
                            write_path(&mut sandbox_profile, path)?;
                            sandbox_profile.write_all(b")").map_err(|_e| ())?;
                        }
                    }
                    sandbox_profile.write_all(b")\n").map_err(|_e| ())?;
                }
                profile::Operation::SystemInfoRead => {
                    sandbox_profile.write_all(b"(allow sysctl-read)\n").map_err(|_e| ())?
                }
                profile::Operation::PlatformSpecific(Operation::MachLookup(ref service_name)) => {
                    sandbox_profile.write_all(b"(allow mach-lookup (global-name ").map_err(|_e| ())?;
                    write_quoted_string(&mut sandbox_profile, service_name.as_slice())?;
                    sandbox_profile.write_all(b"))\n").map_err(|_e| ())?;
                }
            }
        }

        debug!("{}", str::from_utf8(&*sandbox_profile).map_err(|_e| ())?);

        CString::new(sandbox_profile).map_err(|_e| ())
}

fn write_file_pattern(sandbox_profile: &mut Vec<u8>, path_pattern: &PathPattern) -> Result<(),()> {
    match *path_pattern {
        PathPattern::Literal(ref path) => {
            sandbox_profile.write_all(b"(literal ").map_err(|_e| ())?;
            write_path(sandbox_profile, path)?;
        }
        PathPattern::Subpath(ref path) => {
            sandbox_profile.write_all(b"(subpath ").map_err(|_e| ())?;
            write_path(sandbox_profile, path)?;
        }
    }
    sandbox_profile.write_all(b")").map_err(|_e| ())
}

fn write_path(sandbox_profile: &mut Vec<u8>, path: &Path) -> Result<(),()> {
    write_quoted_string(sandbox_profile, path.as_os_str().to_str().ok_or(())?.as_bytes())
}

fn write_quoted_string(sandbox_profile: &mut Vec<u8>, string: &[u8]) -> Result<(),()> {
    sandbox_profile.write_all(&[b'"']).map_err(|_e| ())?;
    for &byte in string.iter() {
        // FIXME(pcwalton): Is this the right way to quote strings in TinyScheme?
        // FIXME(pcwalton): Any other special characters we need to worry about in TinyScheme?
        if byte == b'"' || byte == b'\\' {
            sandbox_profile.write_all(&[b'\\']).map_err(|_e| ())?
        }
        sandbox_profile.write_all(&[byte]).map_err(|_e| ())?
    }
    sandbox_profile.write_all(&[b'"']).map_err(|_e| ())
}

extern {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

