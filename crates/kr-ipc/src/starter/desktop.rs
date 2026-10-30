//! The desktop a headless worker is started on.
//!
//! A process the starter creates without naming a desktop runs on the starter's own: the person's
//! interactive window station and desktop. A headless worker must not start there, so the starter
//! makes it a desktop of its own, on the window station this logon session has for processes that
//! show nothing, and names that desktop in the new process's startup information. The worker, and
//! every process it starts, then draws nowhere the person looks.
//!
//! The window station is the one the system forms from the logon session when it is given no name
//! (only an administrator may choose one), so every headless worker of a logon shares it and each
//! has a desktop of its own on it. The station and the desktop are made with the security of the
//! starter's own, so the worker, which runs as the starter does, is admitted to them exactly as it
//! would be to the starter's desktop, and a process the person runs for another purpose that
//! expects those grants finds them.

#![expect(
    unsafe_code,
    reason = "window stations, desktops and their security are user32 and advapi32 calls with no \
              safe interface"
)]

use std::io;
use std::os::windows::ffi::OsStrExt as _;

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_ALL, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_WINDOW_OBJECT};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
    GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW, HDESK, HWINSTA,
    OpenDesktopW, OpenWindowStationW, SetProcessWindowStation, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId};

/// A window station and a desktop made for one child, and the name that places the child on them.
///
/// Both stay open for as long as this value does, and [`Self::lend_to`] gives the child a handle of
/// each, so the objects are still there when it first connects to the window system and for as
/// long as it lives, however soon the starter ends.
#[derive(Debug)]
pub(super) struct OwnDesktop {
    station: Station,
    desktop: Desktop,
    /// `station\desktop`, terminated: what the child's startup information names.
    name: Vec<u16>,
}

impl OwnDesktop {
    /// Makes the desktop `label` on this logon session's window station for processes that show
    /// nothing, with the security of the starter's own station and desktop.
    ///
    /// The starter is single-threaded, so switching its window station for the one call that
    /// makes the desktop there is not seen by any other thread of it. The switch is undone before
    /// this returns, whatever happens.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error from the call that failed, or an invalid-input error
    /// for a label that cannot name a desktop.
    pub(super) fn create(label: &str) -> io::Result<Self> {
        if label.is_empty() || label.contains('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a desktop's name is not empty and holds no backslash",
            ));
        }
        // The security the child would have met on the starter's own station and desktop, read
        // before anything changes: opening the desktop by name is done on the current station.
        let own_station = name_of(current_station())?;
        let station_security = {
            let opened = Station::open(&own_station, READ_CONTROL)?;
            security_of(opened.0)?
        };
        let own_desktop = name_of(current_desktop())?;
        let desktop_security = {
            let opened = Desktop::open(&own_desktop, READ_CONTROL)?;
            security_of(opened.0)?
        };

        let station_attributes = attributes(&station_security);
        // SAFETY: a null name asks the system to name the station from the logon session, the
        // attributes point at a descriptor that lives until the call returns, and the call returns
        // a handle or null.
        let station = unsafe {
            CreateWindowStationW(
                std::ptr::null(),
                0,
                GENERIC_ALL,
                &raw const station_attributes,
            )
        };
        if station.is_null() {
            return Err(io::Error::last_os_error());
        }
        let station = Station(station);
        let station_name = name_of(station.0)?;

        let desktop = {
            let _switched = Switched::to(&station)?;
            let label_wide = wide(label);
            let desktop_attributes = attributes(&desktop_security);
            // SAFETY: the label is terminated, the device and mode are absent, the attributes
            // point at a descriptor that lives until the call returns, and the call returns a
            // handle or null.
            let created = unsafe {
                CreateDesktopW(
                    label_wide.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    GENERIC_ALL,
                    &raw const desktop_attributes,
                )
            };
            if created.is_null() {
                return Err(io::Error::last_os_error());
            }
            Desktop(created)
        };

        let mut name = station_name;
        name.push(u16::from(b'\\'));
        name.extend(label.encode_utf16());
        name.push(0);
        Ok(Self {
            station,
            desktop,
            name,
        })
    }

    /// The `station\desktop` name, terminated, for the child's startup information.
    pub(super) fn name(&self) -> &[u16] {
        &self.name
    }

    /// Gives `process` a handle of the station and of the desktop, which it does not inherit.
    ///
    /// A process attaches to its window station and desktop when it first calls the window
    /// system, which can be after the starter has gone. A desktop is destroyed with its last
    /// handle, so the child holds handles of its own.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when a handle cannot be duplicated into `process`.
    pub(super) fn lend_to(&self, process: HANDLE) -> io::Result<()> {
        for object in [self.station.0, self.desktop.0] {
            let mut copy: HANDLE = std::ptr::null_mut();
            // SAFETY: the source is a handle this value owns, the target process handle is open
            // with the right to receive a duplicate, and `copy` is a live out parameter. The copy
            // belongs to the child, which closes it when it ends.
            let duplicated = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    object,
                    process,
                    &raw mut copy,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if duplicated == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// A window station this value closes.
#[derive(Debug)]
struct Station(HWINSTA);

impl Station {
    fn open(name: &[u16], access: u32) -> io::Result<Self> {
        let terminated: Vec<u16> = name.iter().copied().chain(std::iter::once(0)).collect();
        // SAFETY: the name is terminated, the handle is not inherited, and the call returns a
        // handle or null.
        let opened = unsafe { OpenWindowStationW(terminated.as_ptr(), 0, access) };
        if opened.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(opened))
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        // SAFETY: the handle is this value's own, opened or created by a call that returned it.
        unsafe { CloseWindowStation(self.0) };
    }
}

/// A desktop this value closes.
#[derive(Debug)]
struct Desktop(HDESK);

impl Desktop {
    /// Opens the desktop `name` on the current window station.
    fn open(name: &[u16], access: u32) -> io::Result<Self> {
        let terminated: Vec<u16> = name.iter().copied().chain(std::iter::once(0)).collect();
        // SAFETY: the name is terminated, the handle is not inherited, and the call returns a
        // handle or null.
        let opened = unsafe { OpenDesktopW(terminated.as_ptr(), 0, 0, access) };
        if opened.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(opened))
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        // SAFETY: the handle is this value's own, opened or created by a call that returned it.
        unsafe { CloseDesktop(self.0) };
    }
}

/// This process made to use a window station, and put back to the one it used on drop.
struct Switched {
    previous: HWINSTA,
}

impl Switched {
    fn to(station: &Station) -> io::Result<Self> {
        let previous = current_station();
        // SAFETY: the station handle is open with the right to be used by this process.
        if unsafe { SetProcessWindowStation(station.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { previous })
    }
}

impl Drop for Switched {
    fn drop(&mut self) {
        // SAFETY: `previous` is the window station this process was using, which the process
        // keeps open. A failure leaves the process on the new station, which the starter ends
        // with straight after.
        unsafe { SetProcessWindowStation(self.previous) };
    }
}

/// This process's window station, which is not this value's to close.
fn current_station() -> HWINSTA {
    // SAFETY: the call has no preconditions and returns a handle the process owns.
    unsafe { GetProcessWindowStation() }
}

/// The desktop of the calling thread, which is not this value's to close.
fn current_desktop() -> HDESK {
    // SAFETY: the call takes this thread's identifier and returns a handle the process owns.
    unsafe { GetThreadDesktop(GetCurrentThreadId()) }
}

/// The name of a window station or a desktop, without its terminator.
fn name_of(object: HANDLE) -> io::Result<Vec<u16>> {
    if object.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = 0_u32;
    // SAFETY: a null buffer and a zero length ask for the size, which is all this call is for; its
    // expected failure is ignored.
    let _ = unsafe {
        GetUserObjectInformationW(object, UOI_NAME, std::ptr::null_mut(), 0, &raw mut bytes)
    };
    let mut buffer = vec![0_u16; usize::try_from(bytes).unwrap_or(0).div_ceil(2).max(1)];
    let length = u32::try_from(buffer.len() * 2).unwrap_or(u32::MAX);
    // SAFETY: the buffer holds `length` bytes, and `bytes` is a live out parameter.
    let read = unsafe {
        GetUserObjectInformationW(
            object,
            UOI_NAME,
            buffer.as_mut_ptr().cast(),
            length,
            &raw mut bytes,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    buffer.truncate(end);
    Ok(buffer)
}

/// A security descriptor read from an object, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by `GetSecurityInfo`, which asks for it to be freed
        // with this call, and nothing else holds it.
        unsafe { LocalFree(self.0) };
    }
}

/// The access list and the integrity label of an object: what decides who may use it and from
/// which level.
fn security_of(object: HANDLE) -> io::Result<Descriptor> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the object is open with the right to read its security, every other out parameter is
    // absent, which the call permits, and `descriptor` is a live out parameter.
    let status = unsafe {
        GetSecurityInfo(
            object,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    Ok(Descriptor(descriptor))
}

/// Attributes that give a new object `descriptor`, not inheritable.
fn attributes(descriptor: &Descriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

/// Encodes a name for a wide call, with its terminator.
fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
