use nix::libc::c_int;
use std::ffi::CString;

//nix::unistd does not offer Service or Netgroup functionality
//Duplicate from the group object
//TODO - formally contribute to nix::unistd
#[derive(Debug, Clone, PartialEq)]
pub struct NixService {
    pub name: CString,
    pub proto: CString,
    pub aliases: Vec<CString>,
    pub port: c_int,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NixNetgroup {
    pub host: Option<CString>,
    pub user: Option<CString>,
    pub domain: Option<CString>,
}
