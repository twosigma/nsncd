use nix::libc::{c_int, servent};
use std::{
    convert::TryFrom,
    ffi::{CStr, CString},
};

//nix::unistd does not offer Service or Netgroup functionality
//Duplicate from the group object
//TODO - formally contribute to nix::unistd
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    pub name: CString,
    pub proto: CString,
    pub aliases: Vec<CString>,
    pub port: c_int,
}

impl TryFrom<servent> for Service {
    type Error = anyhow::Error;

    fn try_from(serv: servent) -> Result<Self, Self::Error> {
        if serv.s_name.is_null() || serv.s_proto.is_null() {
            anyhow::bail!("Service name or proto are null");
        }
        let name = unsafe { CStr::from_ptr(serv.s_name) }.to_owned();
        let proto = unsafe { CStr::from_ptr(serv.s_proto) }.to_owned();

        let mut alias_ptr = serv.s_aliases;
        let mut alias_strings: Vec<CString> = vec![];

        unsafe {
            while !(*alias_ptr).is_null() {
                alias_strings.push(CStr::from_ptr(*alias_ptr).to_owned());
                alias_ptr = alias_ptr.offset(1);
            }
        }

        Ok(Service {
            name,
            proto,
            aliases: alias_strings,
            port: serv.s_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Netgroup {
    pub host: Option<CString>,
    pub user: Option<CString>,
    pub domain: Option<CString>,
}
