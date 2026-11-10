//! The check that a program the installation puts in place was signed by the release's publisher.
//!
//! A digest in a file that anyone could replace is not a check, and a manual or portable install
//! carries no list to compare with, so the elevated program asks the platform to verify each
//! payload file's signature and then compares the signer's name with the one it was built to
//! accept. The file is checked through the open handle the caller holds, so the bytes verified
//! are the bytes that are installed.

#![allow(unsafe_code)]

use std::fs::File;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::{
    CERT_NAME_STR_REVERSE_FLAG, CERT_X500_NAME_STR, CertNameToStrW, X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};

use super::ffi::{Result, error, wide_path};

/// The signer every shipped program carries. A build for a test machine sets another name in the
/// environment variable `KR_BOUNDARY_PUBLISHER`, and no release build does.
pub const PUBLISHER: &str = match option_env!("KR_BOUNDARY_PUBLISHER") {
    Some(name) => name,
    None => "CN=Kala Holdings Inc., O=Kala Holdings Inc., L=Newark, S=Delaware, C=US",
};

/// Verifies a file's signature through its open handle and returns the signer's subject.
///
/// # Errors
///
/// Returns an error when the file is unsigned, the signature does not hold, or the signer's name
/// cannot be read.
pub fn signer(file: &File, shown_path: &Path) -> Result<String> {
    let path = wide_path(shown_path);
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle() as HANDLE,
        pgKnownSubject: null_mut(),
    };
    // SAFETY: a zeroed record is the documented starting point.
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &raw mut info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the data, the file record and the path outlive both calls, and the state the first
    // call opens is closed by the second.
    unsafe {
        let status = WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &raw mut action,
            (&raw mut data).cast(),
        );
        let result = if status == 0 {
            subject_of(data.hWVTStateData)
        } else {
            Err(error(
                status as u32,
                format!(
                    "{} does not carry a signature that holds",
                    shown_path.display()
                ),
            ))
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &raw mut action,
            (&raw mut data).cast(),
        );
        result
    }
}

/// Reads the signer's subject out of the state a successful verification left open.
///
/// # Safety
///
/// `state` must be the state handle of a verification that succeeded and is still open.
unsafe fn subject_of(state: HANDLE) -> Result<String> {
    // SAFETY: the caller promises the state is open, so every pointer read below is the
    // platform's own and lives until the state is closed.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state);
        if provider.is_null() {
            return Err(error(0, "the verification left no provider data"));
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if signer.is_null() || (*signer).pasCertChain.is_null() {
            return Err(error(0, "the signature names no signer"));
        }
        let certificate = (*(*signer).pasCertChain).pCert;
        if certificate.is_null() {
            return Err(error(0, "the signature names no signer"));
        }
        let subject = &raw const (*(*certificate).pCertInfo).Subject;
        let kind = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
        let length = CertNameToStrW(X509_ASN_ENCODING, subject, kind, null_mut(), 0);
        let mut buffer = vec![0_u16; length as usize];
        CertNameToStrW(
            X509_ASN_ENCODING,
            subject,
            kind,
            buffer.as_mut_ptr(),
            length,
        );
        Ok(String::from_utf16_lossy(
            &buffer[..(length as usize).saturating_sub(1)],
        ))
    }
}
