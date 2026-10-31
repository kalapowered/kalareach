//! The security of the window stations and desktops that a headless worker is started on, for the
//! cases that need a station or the interactive desktop to be other than the system made it.
//!
//! Everything here acts as the account the test runs as, on the logon it runs in, and puts back
//! what it changed when its value is dropped. A window station made without a name belongs to the
//! logon of the process that makes it, so what a case makes here meets the starter only where this
//! test and the daemon's task share one logon; the cases check that before they rely on it.

#![cfg(windows)]
#![expect(
    unsafe_code,
    reason = "window stations, desktops and their security are user32 and advapi32 calls with no \
              safe interface"
)]

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_WINDOW_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, LABEL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
    GetProcessWindowStation, GetUserObjectInformationW, HDESK, HWINSTA, OpenDesktopW,
    OpenWindowStationW, SetProcessWindowStation, UOI_NAME,
};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;

/// A trustee that exists on no machine: an entry for it admits nobody, which is what the cases
/// that add one to the interactive station need.
const NOBODY: &str = "S-1-5-5-0-4242424";

/// A window station of the logon this test runs in, made by this test with an access list of its
/// own and held open until this is dropped.
///
/// A station is named from the logon when it is given no name, and it lasts as long as any handle
/// of it does, so a worker started while this is held meets it, with the access list given here.
pub struct HeldStation {
    handle: HWINSTA,
    /// The station's access list as the system writes it, as it was read back after it was made.
    pub access_list: String,
    /// The station's integrity label as the system writes it, as it was read back after it was
    /// made, or empty when it has none.
    pub label: String,
}

impl HeldStation {
    /// Makes the logon's station with the interactive station's access list as `change` alters it.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, including that the logon already had a station, whose access list
    /// is then not the one asked for.
    pub fn make(change: impl FnOnce(&str) -> String) -> Result<Self, String> {
        Self::make_labelled(change, "")
    }

    /// Makes the logon's station as [`Self::make`] does, with the integrity label `label` as the
    /// system writes one (`S:(ML;;NW;;;LW)`), or none when it is empty.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, including that the logon already had a station, whose access list
    /// or label is then not the one asked for.
    pub fn make_labelled(change: impl FnOnce(&str) -> String, label: &str) -> Result<Self, String> {
        let interactive = Interactive::open(READ_CONTROL)?;
        let own = access_list_text(interactive.station)?;
        let wanted = change(&own);
        let descriptor = DescriptorFromText::of(&format!("{wanted}{label}"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: a null name asks the system to name the station from the logon, and the
        // attributes point at a descriptor that lives until the call returns.
        let handle = unsafe {
            CreateWindowStationW(std::ptr::null(), 0, MAXIMUM_ALLOWED, &raw const attributes)
        };
        if handle.is_null() {
            return Err(format!(
                "the logon's window station was not made: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut held = Self {
            handle,
            access_list: String::new(),
            label: String::new(),
        };
        // MAXIMUM_ALLOWED does not always include the right to read the list, so it is read
        // through a handle opened for that.
        let name = name_of(held.handle)?;
        let reader = OpenStation::named(&name, READ_CONTROL)?;
        let read_back = access_list_text(reader.0)?;
        if read_back != normalised(&wanted)? {
            return Err(format!(
                "the logon already had a window station with another access list: {read_back} \
                 where {wanted} was asked for"
            ));
        }
        held.access_list = read_back;
        held.label = label_text(reader.0)?;
        Ok(held)
    }
}

impl Drop for HeldStation {
    fn drop(&mut self) {
        // SAFETY: the handle is this value's own, returned by the call that made it.
        unsafe { CloseWindowStation(self.handle) };
    }
}

/// A desktop made by this test on a window station it holds, with an access list of its own, and
/// held open until this is dropped.
///
/// A desktop lasts as long as any handle of it does, and a desktop that exists already keeps the
/// security it was made with, so a starter that is asked for a desktop of this name meets this one.
pub struct HeldDesktop {
    handle: HDESK,
    /// The desktop's access list as the system writes it, as it was read back after it was made.
    pub access_list: String,
}

impl HeldDesktop {
    /// Makes the desktop `name` on `station` with the interactive desktop's access list as
    /// `change` alters it.
    ///
    /// This process uses `station` for the one call that makes the desktop there, and is put back
    /// on the station it used before, so no other thread of it may use a window station meanwhile.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, including that the station already had a desktop of this name.
    pub fn make(
        station: &HeldStation,
        name: &str,
        change: impl FnOnce(&str) -> String,
    ) -> Result<Self, String> {
        let interactive = Interactive::open(READ_CONTROL)?;
        let own = access_list_text(interactive.desktop)?;
        let wanted = change(&own);
        let descriptor = DescriptorFromText::of(&wanted)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: the call has no preconditions and returns a handle the process owns.
        let previous = unsafe { GetProcessWindowStation() };
        // SAFETY: the station handle is open with the right to be used by this process.
        if unsafe { SetProcessWindowStation(station.handle) } == 0 {
            return Err(format!(
                "the held station was not used: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the name is terminated, the device and mode are absent, the attributes point at
        // a descriptor that lives until the call returns, and the call returns a handle or null.
        let handle = unsafe {
            CreateDesktopW(
                wide(name).as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                MAXIMUM_ALLOWED,
                &raw const attributes,
            )
        };
        let made = std::io::Error::last_os_error();
        // SAFETY: `previous` is the station this process was using, which it keeps open.
        unsafe { SetProcessWindowStation(previous) };
        if handle.is_null() {
            return Err(format!("the desktop {name} was not made: {made}"));
        }
        let mut held = Self {
            handle,
            access_list: String::new(),
        };
        let read_back = access_list_text(held.handle)?;
        if read_back != normalised(&wanted)? {
            return Err(format!(
                "the station already had a desktop {name} with another access list: {read_back} \
                 where {wanted} was asked for"
            ));
        }
        held.access_list = read_back;
        Ok(held)
    }
}

impl Drop for HeldDesktop {
    fn drop(&mut self) {
        // SAFETY: the handle is this value's own, returned by the call that made it.
        unsafe { CloseDesktop(self.handle) };
    }
}

/// An entry added to the interactive window station's access list and to the interactive
/// desktop's, as a "Run as different user" may add one for the account it starts a program as, and
/// taken away again when [`Self::put_back`] says so or, failing that, when this is dropped.
pub struct EntryOnInteractive {
    // Dropped in this order: the lists are put back through the handles, so the handles go last.
    station: Restore,
    desktop: Restore,
    _interactive: Interactive,
}

impl EntryOnInteractive {
    /// Adds an allowing entry for a trustee that does not exist to both lists.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, with the first list unchanged if the second could not be.
    pub fn add() -> Result<Self, String> {
        let interactive = Interactive::open(READ_CONTROL | WRITE_DAC)?;
        let station = Restore::add_to(interactive.station)?;
        let desktop = Restore::add_to(interactive.desktop)?;
        Ok(Self {
            station,
            desktop,
            _interactive: interactive,
        })
    }

    /// Puts both lists back as they were and checks that they read back so.
    ///
    /// Dropping this does the same without a word when it fails, which is for a case that has
    /// already failed; a case that means to leave the machine as it found it calls this.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, or which list did not read back as it was.
    pub fn put_back(&self) -> Result<(), String> {
        self.station.put_back()?;
        self.desktop.put_back()
    }

    /// The interactive station's access list as it is now.
    ///
    /// # Errors
    ///
    /// Returns what went wrong reading it.
    pub fn station_access_list(&self) -> Result<String, String> {
        access_list_text(self.station.object)
    }
}

/// An access list changed, and the one it had before.
struct Restore {
    object: HANDLE,
    original: *mut ACL,
    /// The list's text before it was changed.
    original_text: String,
    /// Keeps the descriptor that `original` points into.
    _descriptor: Local,
}

impl Restore {
    fn add_to(object: HANDLE) -> Result<Self, String> {
        let (original, descriptor) = dacl_of(object)?;
        let text = access_list_text(object)?;
        let changed = DescriptorFromText::of(&format!("{text}(A;;0x1;;;{NOBODY})"))?;
        set_dacl(object, dacl_in(changed.descriptor)?)?;
        Ok(Self {
            object,
            original,
            original_text: text,
            _descriptor: descriptor,
        })
    }

    fn put_back(&self) -> Result<(), String> {
        set_dacl(self.object, self.original)?;
        let now = access_list_text(self.object)?;
        if now == self.original_text {
            Ok(())
        } else {
            Err(format!(
                "the access list reads {now} after it was put back, and was {}",
                self.original_text
            ))
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = set_dacl(self.object, self.original);
    }
}

/// The interactive window station and desktop, opened for the rights asked for.
struct Interactive {
    station: HWINSTA,
    desktop: HDESK,
}

impl Interactive {
    fn open(access: u32) -> Result<Self, String> {
        // SAFETY: the name is terminated, the handle is not inherited, and the call returns a
        // handle or null.
        let station = unsafe { OpenWindowStationW(wide("WinSta0").as_ptr(), 0, access) };
        if station.is_null() {
            return Err(format!(
                "the interactive window station: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: as above, on the process's own station, which is the interactive one.
        let desktop = unsafe { OpenDesktopW(wide("Default").as_ptr(), 0, 0, access) };
        if desktop.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: the station was just opened and nothing else holds it.
            unsafe { CloseWindowStation(station) };
            return Err(format!("the interactive desktop: {error}"));
        }
        Ok(Self { station, desktop })
    }
}

impl Drop for Interactive {
    fn drop(&mut self) {
        // SAFETY: both handles were opened by `open` and nothing else holds them.
        unsafe {
            CloseDesktop(self.desktop);
            CloseWindowStation(self.station);
        }
    }
}

/// A window station opened by name, closed on drop.
struct OpenStation(HWINSTA);

impl OpenStation {
    fn named(name: &str, access: u32) -> Result<Self, String> {
        // SAFETY: the name is terminated, the handle is not inherited, and the call returns a
        // handle or null.
        let station = unsafe { OpenWindowStationW(wide(name).as_ptr(), 0, access) };
        if station.is_null() {
            return Err(format!(
                "the window station {name}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(station))
    }
}

impl Drop for OpenStation {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `named` and nothing else holds it.
        unsafe { CloseWindowStation(self.0) };
    }
}

/// Memory the system allocated, freed on drop.
struct Local(*mut core::ffi::c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the memory was allocated by a call that asks for it to be freed with this one,
        // and nothing else holds it.
        unsafe { LocalFree(self.0) };
    }
}

/// A security descriptor made from its text.
struct DescriptorFromText {
    descriptor: PSECURITY_DESCRIPTOR,
    _freed: Local,
}

impl DescriptorFromText {
    fn of(text: &str) -> Result<Self, String> {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: the text is terminated, the size is not asked for, and `descriptor` is a live
        // out parameter.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(text).as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(format!(
                "{text} is not a security descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            descriptor,
            _freed: Local(descriptor),
        })
    }
}

/// The text of an object's access list, as the system writes it.
fn access_list_text(object: HANDLE) -> Result<String, String> {
    let (_, descriptor) = dacl_of(object)?;
    text_of(descriptor.0, DACL_SECURITY_INFORMATION)
}

/// The text of an object's integrity label, as the system writes it, or empty when it has none.
fn label_text(object: HANDLE) -> Result<String, String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the object is open with the right to read its security, the other parts are
    // absent, which the call permits, and the out parameter is live.
    let status = unsafe {
        GetSecurityInfo(
            object,
            SE_WINDOW_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(format!(
            "the object's integrity label was not read: error {status}"
        ));
    }
    let held = Local(descriptor);
    text_of(held.0, LABEL_SECURITY_INFORMATION)
}

/// The text of one part of a descriptor, the access list or the integrity label.
fn text_of(descriptor: PSECURITY_DESCRIPTOR, information: u32) -> Result<String, String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: the descriptor is a live one, the length is not asked for, and `text` is a live out
    // parameter.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            information,
            &raw mut text,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || text.is_null() {
        return Err(format!(
            "the security could not be written as text: {}",
            std::io::Error::last_os_error()
        ));
    }
    let freed = Local(text.cast());
    let mut length = 0;
    // SAFETY: the call above returned a terminated string, which is read up to its end.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` units were just counted in the string that `text` points to.
    let written = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    drop(freed);
    Ok(written)
}

/// The text of `text` after the system has read it as a descriptor and written it again, which is
/// what a station made from it reads back as.
fn normalised(text: &str) -> Result<String, String> {
    text_of(
        DescriptorFromText::of(text)?.descriptor,
        DACL_SECURITY_INFORMATION,
    )
}

/// An object's access list, with the descriptor that holds it.
fn dacl_of(object: HANDLE) -> Result<(*mut ACL, Local), String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut access: *mut ACL = std::ptr::null_mut();
    // SAFETY: the object is open with the right to read its security, the other parts are
    // absent, which the call permits, and the out parameters are live.
    let status = unsafe {
        GetSecurityInfo(
            object,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut access,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(format!(
            "the object's access list was not read: error {status}"
        ));
    }
    Ok((access, Local(descriptor)))
}

/// The access list inside a descriptor.
fn dacl_in(descriptor: PSECURITY_DESCRIPTOR) -> Result<*mut ACL, String> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut access: *mut ACL = std::ptr::null_mut();
    // SAFETY: the descriptor is a live one and the out parameters are live.
    let read = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut access,
            &raw mut defaulted,
        )
    };
    if read == 0 || present == 0 {
        return Err("the descriptor has no access list".to_owned());
    }
    Ok(access)
}

/// Gives an object an access list.
fn set_dacl(object: HANDLE, access: *mut ACL) -> Result<(), String> {
    // SAFETY: the object is open with the right to change its access list, the list is live, and
    // every other part is absent, which the call permits.
    let status = unsafe {
        SetSecurityInfo(
            object,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            access,
            std::ptr::null(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("the access list was not set: error {status}"))
    }
}

/// The name of a window station.
fn name_of(station: HWINSTA) -> Result<String, String> {
    let mut buffer = [0_u16; 256];
    let mut bytes = 0_u32;
    // SAFETY: the buffer holds the number of bytes given and `bytes` is a live out parameter.
    let read = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_NAME,
            buffer.as_mut_ptr().cast(),
            u32::try_from(size_of_val(&buffer)).unwrap_or(0),
            &raw mut bytes,
        )
    };
    if read == 0 {
        return Err(format!(
            "the station's name: {}",
            std::io::Error::last_os_error()
        ));
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..end]))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
