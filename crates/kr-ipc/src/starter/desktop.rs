//! The desktop a headless worker is started on.
//!
//! A process the starter creates without naming a desktop runs on the starter's own: the person's
//! interactive window station and desktop. A headless worker must not start there, so the starter
//! makes it a desktop of its own, on the window station this logon session has for processes that
//! show nothing, and names that desktop in the new process's startup information. The worker, and
//! every process it starts, then inherits no access to the interactive desktop. That is not a
//! boundary against a process of the same account: such a process can open the interactive
//! desktop by name.
//!
//! The window station is the one the system forms from the logon session when it is given no name
//! (only an administrator may choose one), so every headless worker of a logon shares the station
//! and each has a desktop of its own on it. The clipboard and the atom table belong to the
//! station, so the headless sessions of one logon share them. The station and the desktop are
//! given the access list and integrity label of the starter's own, so the worker, which runs as
//! the starter does, is admitted to them exactly as it would be to the starter's desktop. A
//! station that exists already keeps the access list it was made with, because creating it again
//! ignores the security asked for. Where the starter's own object has an integrity label, the
//! starter applies it to the object it uses and reads the label back, whether or not the change
//! was allowed. It then reads the access list and label of each object it is about to use and
//! refuses to start a child on one that admits more than its own does, or that it cannot show to
//! admit no more. An object whose list is the starter's own with allowing entries left out and
//! denying entries put in is used: a station made before an entry was added to the interactive one
//! (a "Run as different user" may add one) has not that entry, and the worker, which runs as the
//! starter does, is admitted to it all the same. [`super::security`] says exactly what is used and
//! what is refused.
//!
//! A desktop on a window station that shows nothing has the heap the system gives such a desktop,
//! which is much smaller than the interactive one's, and all the processes of one headless session
//! share it. A session that starts very many programs which each make windows can use it up, and
//! the system then fails the next program's start without naming the desktop as the cause.
//!
//! The starter can end between lending the child its handles and letting it run only by being
//! killed there. The child is then left suspended with its handles, and the daemon, which was told
//! nothing, records a launch it cannot vouch for.

#![expect(
    unsafe_code,
    reason = "window stations, desktops and their security are user32 and advapi32 calls with no \
              safe interface"
)]

use std::io;
use std::os::windows::ffi::OsStrExt as _;

use super::security::{Texts, require_no_more};

use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_WINDOW_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAclInformation,
    InitializeSecurityDescriptor, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
    GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW, HDESK, HWINSTA,
    OpenDesktopW, OpenWindowStationW, SetProcessWindowStation, UOI_NAME,
};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;
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
        let own_station = name_of(current_station()).map_err(step("read the station's name"))?;
        let station_source = {
            let opened = Station::open(&own_station, READ_CONTROL)
                .map_err(step("open the starter's station to read its security"))?;
            security_of(opened.0).map_err(step("read the starter's station's security"))?
        };
        let own_desktop = name_of(current_desktop()).map_err(step("read the desktop's name"))?;
        let desktop_source = {
            let opened = Desktop::open(&own_desktop, READ_CONTROL)
                .map_err(step("open the starter's desktop to read its security"))?;
            security_of(opened.0).map_err(step("read the starter's desktop's security"))?
        };

        let mut station_security = station_source.access_only();
        let station_attributes = attributes(&mut station_security);
        // SAFETY: a null name asks the system to name the station from the logon session, the
        // attributes point at a descriptor that lives until the call returns, and the call returns
        // a handle or null.
        let station = unsafe {
            CreateWindowStationW(
                std::ptr::null(),
                0,
                MAXIMUM_ALLOWED,
                &raw const station_attributes,
            )
        };
        if station.is_null() {
            return Err(step("create the window station")(io::Error::last_os_error()));
        }
        let station = Station(station);
        station_source.label_onto(station.0);
        station_source
            .require_no_more_on(station.0)
            .map_err(step("check the window station's security"))?;
        let station_name = name_of(station.0).map_err(step("read the new station's name"))?;

        let desktop = {
            let _switched = Switched::to(&station).map_err(step("use the new window station"))?;
            let label_wide = wide(label);
            let mut desktop_security = desktop_source.access_only();
            let desktop_attributes = attributes(&mut desktop_security);
            // SAFETY: the label is terminated, the device and mode are absent, the attributes
            // point at a descriptor that lives until the call returns, and the call returns a
            // handle or null.
            let created = unsafe {
                CreateDesktopW(
                    label_wide.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    MAXIMUM_ALLOWED,
                    &raw const desktop_attributes,
                )
            };
            if created.is_null() {
                return Err(step("create the desktop")(io::Error::last_os_error()));
            }
            let created = Desktop(created);
            desktop_source.label_onto(created.0);
            desktop_source
                .require_no_more_on(created.0)
                .map_err(step("check the desktop's security"))?;
            created
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
                return Err(step("lend the station and desktop to the child")(
                    io::Error::last_os_error(),
                ));
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

/// The security of an object the starter reads: the descriptor that holds it, and the access list
/// and integrity label inside it.
struct Source {
    descriptor: PSECURITY_DESCRIPTOR,
    access: *mut ACL,
    label: *mut ACL,
}

impl Drop for Source {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by `GetSecurityInfo`, which asks for it to be freed
        // with this call, and nothing else holds it. The two lists point inside it. A source whose
        // descriptor is null holds nothing to free, and the call ignores a null handle.
        unsafe { LocalFree(self.descriptor) };
    }
}

impl Source {
    /// A descriptor that holds the access list alone, to give a new object. The label is applied
    /// afterwards by [`Self::label_onto`], which is also the only way to give one to a station
    /// that exists already, whose creation ignores the security asked for, so the label reaches
    /// both in one way. Giving a new object the whole descriptor read from the starter's own was
    /// refused in a service session for a privilege it did not hold (error 1314). Which part of
    /// the descriptor needed it is not read here: runs as a standard account and as an
    /// administrator give new objects a descriptor with a lower label without trouble.
    fn access_only(&self) -> SECURITY_DESCRIPTOR {
        // SAFETY: all-zero is the initial state `InitializeSecurityDescriptor` is given.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let pointer = (&raw mut descriptor).cast();
        // SAFETY: the pointer is to a live descriptor of the full size, and the access list it is
        // given lives in this value, which outlives the descriptor's use.
        unsafe {
            InitializeSecurityDescriptor(pointer, 1);
            SetSecurityDescriptorDacl(pointer, 1, self.access, 0);
        }
        descriptor
    }

    /// Gives `target` this object's integrity label, if it has one and the starter may set it.
    ///
    /// A refusal of the change is not looked at here: an object that exists already can withhold
    /// the right to change its label, with a denying entry that takes it from everyone. What
    /// decides is [`Self::require_no_more_on`], which reads the label back whether or not the
    /// change was allowed.
    fn label_onto(&self, target: HANDLE) {
        if self.label.is_null() {
            return;
        }
        // SAFETY: the target is an open handle of a station or a desktop, the label list lives in
        // this value, and every other part is absent, which the call permits. The call's refusal
        // is not looked at, as the comment above says.
        unsafe {
            SetSecurityInfo(
                target,
                SE_WINDOW_OBJECT,
                LABEL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                self.label,
            );
        }
    }

    /// Requires `target` to be one the starter uses, given that this object is the starter's own:
    /// by its access list and by its integrity label.
    ///
    /// An object whose security is the starter's own with entries left out that only narrow it, or
    /// put in that only narrow it, is used. One that admits more, or whose security differs in a
    /// way that cannot be shown to admit no more, is refused, and a child is not started on it.
    ///
    /// # Errors
    ///
    /// Returns a permission error saying whether the target admits more or is only not one the
    /// starter accepts, an invalid-data error when the text of a list cannot be read or does not
    /// account for the entries of the list, or the operating system's error when the target's
    /// security cannot be read.
    fn require_no_more_on(&self, target: HANDLE) -> io::Result<()> {
        let there = security_of(target)?;
        let (own_access, own_label) = (
            self.text(DACL_SECURITY_INFORMATION)?,
            self.text(LABEL_SECURITY_INFORMATION)?,
        );
        let (found_access, found_label) = (
            there.text(DACL_SECURITY_INFORMATION)?,
            there.text(LABEL_SECURITY_INFORMATION)?,
        );
        require_no_more(
            &Texts {
                access: &own_access,
                access_entries: self.access_entries()?,
                access_bytes: self.access_bytes()?,
                label: &own_label,
            },
            &Texts {
                access: &found_access,
                access_entries: there.access_entries()?,
                access_bytes: there.access_bytes()?,
                label: &found_label,
            },
        )
        .map_err(|stop| {
            let kind = if stop.is_unreadable() {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::PermissionDenied
            };
            io::Error::new(kind, stop.to_string())
        })
    }

    /// How the system sizes this object's access list: how many entries it holds and how many
    /// bytes it uses. An object with no list has none of either.
    fn access_size(&self) -> io::Result<ACL_SIZE_INFORMATION> {
        // SAFETY: all-zero is a valid value of this plain structure of counts.
        let mut size: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        if self.access.is_null() {
            return Ok(size);
        }
        // SAFETY: the list lives in this value's descriptor, and the structure is live and of the
        // size given.
        let read = unsafe {
            GetAclInformation(
                self.access,
                (&raw mut size).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(0),
                AclSizeInformation,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(size)
    }

    /// How many entries this object's access list holds, as the system counts them, which the
    /// text of the list must account for: a text that reads as fewer entries has hidden some.
    fn access_entries(&self) -> io::Result<usize> {
        Ok(usize::try_from(self.access_size()?.AceCount).unwrap_or(usize::MAX))
    }

    /// The entries of this object's access list as the system holds them, without the list's
    /// header, which also holds how much room the list was given, and without that room. Two lists
    /// with the same entries are the same list, which the text of a list that holds a condition
    /// does not show.
    fn access_bytes(&self) -> io::Result<&[u8]> {
        if self.access.is_null() {
            return Ok(&[]);
        }
        let used = usize::try_from(self.access_size()?.AclBytesInUse).unwrap_or(0);
        let Some(length) = used.checked_sub(size_of::<ACL>()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the access list uses fewer bytes than its header",
            ));
        };
        // SAFETY: the list lives in this value's descriptor and uses `used` bytes from its start,
        // the first `size_of::<ACL>()` of which are its header.
        Ok(unsafe {
            std::slice::from_raw_parts(self.access.cast::<u8>().add(size_of::<ACL>()), length)
        })
    }

    /// The text of one of this object's lists, as security descriptors are written in.
    fn text(&self, information: u32) -> io::Result<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: the descriptor was returned by `GetSecurityInfo` and lives in this value, the
        // length is not asked for, and `text` is a live out parameter.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.descriptor,
                SDDL_REVISION_1,
                information,
                &raw mut text,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 || text.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: the call above returned a terminated string, which is read up to its end.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` units were just counted in the string that `text` points to.
        let written = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: the string was allocated by the conversion, which asks for it to be freed with
        // this call, and nothing else holds it.
        unsafe { LocalFree(text.cast()) };
        Ok(written)
    }
}

/// The access list and the integrity label of an object: what decides who may use it and from
/// which level.
fn security_of(object: HANDLE) -> io::Result<Source> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut access: *mut ACL = std::ptr::null_mut();
    let mut label: *mut ACL = std::ptr::null_mut();
    // SAFETY: the object is open with the right to read its security, the owner and group are
    // absent, which the call permits, and the three out parameters are live.
    let status = unsafe {
        GetSecurityInfo(
            object,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut access,
            &raw mut label,
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ));
    }
    Ok(Source {
        descriptor,
        access,
        label,
    })
}

/// Attributes that give a new object `descriptor`, not inheritable.
fn attributes(descriptor: &mut SECURITY_DESCRIPTOR) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: (&raw mut *descriptor).cast(),
        bInheritHandle: 0,
    }
}

/// Names the call that failed, so that a refusal says which one it was.
fn step(what: &'static str) -> impl Fn(io::Error) -> io::Error {
    move |error| {
        let kind = error.kind();
        io::Error::new(kind, format!("{what}: {error}"))
    }
}

/// Encodes a name for a wide call, with its terminator.
fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// These cases make desktops on the window station the test runs on, give them security of their
/// own, and ask what the starter makes of each against a reference desktop they make.
///
/// Every case makes desktops, so every case needs the right to create one on the station the test
/// runs on, which the account and the session decide, and reads back what it made, which needs
/// the list it gave to leave the caller the right to read it.
///
/// The cases that judge against the reference desktop (`own`, `judged`, `refusal`) or use
/// `own_access_list` take the list of the desktop the test runs on with two entries added, and
/// depend on that list. It must be one the system writes without a condition and that a text can
/// give back: a null list cannot take entries, and a list with a condition is split at every
/// parenthesis by the order case and, with a quote the text has no form for, is not given back as
/// it is, so those cases fail by name. A list that reads the same reversed fails the order case at
/// its assertion. The case that puts a label on a desktop also needs that list to grant the
/// caller the right to change the label of the desktops it makes, which a standard account's
/// session has; without it the label stays and the case fails by name. The other cases make their
/// lists themselves and need no more than the first paragraph says, and the case with no label
/// needs a new desktop to have none, which the runs on the test machine give at the medium and the
/// high level (the case fails by name at its first assertion when it is not so).
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    };
    use windows_sys::Win32::Security::{AddAce, GetLengthSid, InitializeAcl, PSID};

    use super::*;

    /// A trustee no account has, so that an entry for it adds access that nothing else grants.
    const NOBODY: &str = "S-1-5-21-4242424-1-2-3";

    /// A name no other desktop of this station has.
    fn unique_name() -> String {
        static MADE: AtomicUsize = AtomicUsize::new(0);
        format!(
            "kr-desktop-case-{}-{}",
            std::process::id(),
            MADE.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Two entries that differ, added to the list of the desktop this thread runs on so that the
    /// list the cases take for the starter's own holds at least two.
    const ADDED: &str = "(A;;0x1;;;SY)(A;;0x2;;;BA)";

    /// The security of the desktop this thread runs on.
    fn current() -> Source {
        let name = name_of(current_desktop()).expect("the desktop's name");
        let opened = Desktop::open(&name, READ_CONTROL).expect("the desktop opens to be read");
        security_of(opened.0).expect("the desktop's security")
    }

    /// The text of the access list the cases take for the starter's own: the list of the desktop
    /// this thread runs on, with two entries added.
    fn own_access_list() -> String {
        let current = current()
            .text(DACL_SECURITY_INFORMATION)
            .expect("the current desktop's access list");
        format!("{current}{ADDED}")
    }

    /// The security of a desktop made with that list, which the cases take for the starter's own.
    fn own() -> Source {
        let reference = desktop_with(&own_access_list());
        security_of(reference.0).expect("the reference desktop's security")
    }

    /// How many entries a list the system wrote holds, counted by its parentheses alone, which is
    /// how many it holds when none holds a condition.
    fn entries_in(text: &str) -> usize {
        let mut depth = 0_u32;
        let mut entries = 0;
        for character in text.chars() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    entries += usize::from(depth == 0);
                }
                _ => {}
            }
        }
        entries
    }

    /// A desktop made on this station with the security a text describes.
    fn desktop_with(security: &str) -> Desktop {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: the text is terminated, the size is not asked for, and `descriptor` is a live
        // out parameter.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(security).as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            converted,
            0,
            "{security} is not a descriptor: {}",
            io::Error::last_os_error()
        );
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let made = desktop_made(&attributes);
        // SAFETY: the descriptor was allocated by the conversion, which asks for it to be freed
        // with this call, and the desktop has copied what it keeps.
        unsafe { LocalFree(descriptor) };
        made
    }

    /// A desktop made on this station with the attributes given.
    fn desktop_made(attributes: &SECURITY_ATTRIBUTES) -> Desktop {
        try_desktop_made(attributes)
            .unwrap_or_else(|error| panic!("the desktop was not made: {error}"))
    }

    /// A desktop made on this station with the attributes given, or the system's refusal.
    fn try_desktop_made(attributes: &SECURITY_ATTRIBUTES) -> io::Result<Desktop> {
        let name = wide(&unique_name());
        // SAFETY: the name is terminated, the device and mode are absent, the attributes point at
        // a descriptor that lives until the call returns, and the call returns a handle or null.
        let handle = unsafe {
            CreateDesktopW(
                name.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                MAXIMUM_ALLOWED,
                attributes,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Desktop(handle))
    }

    /// What the starter makes of `target` as a desktop to use, given the reference desktop as its
    /// own.
    fn judged(target: &Desktop) -> io::Result<()> {
        own().require_no_more_on(target.0)
    }

    /// The error a desktop is refused with, which it must be.
    fn refusal(target: &Desktop) -> io::Error {
        judged(target).expect_err("the desktop was used")
    }

    /// The starter's own entries are counted as the system counts them, and a desktop with the
    /// same list is used: the count that the text must account for is the list's own.
    #[test]
    fn a_desktop_with_the_starters_own_access_list_is_used_and_its_entries_are_counted() {
        let text = own_access_list();
        let counted = entries_in(&text);
        let target = desktop_with(&text);
        assert_eq!(
            own().access_entries().expect("the starter's own count"),
            counted,
            "{text}"
        );
        let there = security_of(target.0).expect("the target's security");
        assert_eq!(
            there.access_entries().expect("the target's count"),
            counted,
            "{text}"
        );
        judged(&target).expect("a desktop with the starter's own access list is used");
    }

    /// A desktop that admits an account the starter's own admits nothing of is refused as one
    /// that admits more, with the access list named, and as a permission error.
    #[test]
    fn a_desktop_that_admits_more_is_refused_as_admitting_more() {
        let target = desktop_with(&format!("{}(A;;0x1;;;{NOBODY})", own_access_list()));
        let error = refusal(&target);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let said = error.to_string();
        assert!(
            said.contains("access list") && said.contains("admits more"),
            "{said}"
        );
    }

    /// A null access list admits everyone, and the count of its entries is none.
    #[test]
    fn a_desktop_with_no_access_control_is_refused_as_admitting_more() {
        let target = desktop_with("D:NO_ACCESS_CONTROL");
        let there = security_of(target.0).expect("the target's security");
        assert_eq!(there.access_entries().expect("the target's count"), 0);
        let error = refusal(&target);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let said = error.to_string();
        assert!(
            said.contains("null") && said.contains("admits more"),
            "{said}"
        );
    }

    /// The starter's own entries in another order are not shown to admit more, and the refusal
    /// says that the desktop is not one the starter accepts.
    #[test]
    fn a_desktop_with_the_entries_in_another_order_is_refused_without_being_called_wider() {
        let text = own_access_list();
        let (flags, entries) = text.split_at(text.find('(').expect("an entry"));
        let mut each: Vec<String> = entries.split_inclusive(')').map(str::to_owned).collect();
        each.reverse();
        let reversed = format!("{flags}{}", each.concat());
        assert_ne!(
            reversed, text,
            "the starter's own list reads the same reversed: {text}"
        );
        let target = desktop_with(&reversed);
        let error = refusal(&target);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let said = error.to_string();
        assert!(
            said.contains("not one the starter accepts") && !said.contains("admits more"),
            "{said}"
        );
    }

    /// An access list that holds a condition the starter's own does not is not read, and that is
    /// an error of its own kind, not a refusal.
    #[test]
    fn a_desktop_with_a_condition_is_unreadable_and_not_a_refusal() {
        let target = desktop_with(&format!(
            "{}(XA;;0x1;;;{NOBODY};(@User.X==1))",
            own_access_list()
        ));
        let error = refusal(&target);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        let said = error.to_string();
        assert!(
            said.contains("could not be read") && said.contains("condition"),
            "{said}"
        );
    }

    /// An integrity label below the starter's own is refused as one that admits more.
    #[test]
    fn a_desktop_with_a_lower_integrity_label_is_refused_as_admitting_more() {
        let target = desktop_with(&format!("{}S:(ML;;NW;;;S-1-16-0)", own_access_list()));
        let error = refusal(&target);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let said = error.to_string();
        assert!(
            said.contains("integrity label") && said.contains("admits more"),
            "{said}"
        );
    }

    /// The starter's integrity label is put on an object that has a lower one, which is what keeps
    /// such an object from being refused when the starter may change its label.
    #[test]
    fn the_starters_label_is_put_on_an_object_that_has_a_lower_one() {
        let access = own_access_list();
        let station = Station::open(
            &name_of(current_station()).expect("the station's name"),
            READ_CONTROL,
        )
        .expect("the station opens to be read");
        println!(
            "the label of the starter's own desktop is {:?}, and of its station {:?}",
            current().text(LABEL_SECURITY_INFORMATION),
            security_of(station.0)
                .expect("the station's security")
                .text(LABEL_SECURITY_INFORMATION)
        );
        let model = desktop_with(&format!("{access}S:(ML;;NW;;;ME)"));
        let source = security_of(model.0).expect("the model's security");
        assert!(!source.label.is_null(), "the model has no integrity label");
        let lower = desktop_with(&format!("{access}S:(ML;;NW;;;S-1-16-0)"));
        let before = source
            .require_no_more_on(lower.0)
            .expect_err("a desktop with a lower label was used before the label was put on it");
        assert!(before.to_string().contains("integrity label"), "{before}");

        source.label_onto(lower.0);
        source
            .require_no_more_on(lower.0)
            .expect("the desktop is used once the starter's label is on it");
        // The flags the system writes before the entry say how the list came to be, and are not
        // the label's own.
        let there = security_of(lower.0)
            .expect("the target's security")
            .text(LABEL_SECURITY_INFORMATION)
            .expect("the target's label");
        assert!(there.contains("(ML;;NW;;;ME)"), "{there}");
    }

    /// The bytes of a security identifier, from the letters or the text the system writes for one.
    fn sid(text: &str) -> Vec<u8> {
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: the text is terminated and `sid` is a live out parameter.
        let converted = unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &raw mut sid) };
        assert_ne!(converted, 0, "{text} is not a security identifier");
        // SAFETY: the conversion returned a whole identifier, which is read up to its own length
        // and then freed with the call that asks for it.
        unsafe {
            let length = usize::try_from(GetLengthSid(sid)).unwrap_or(0);
            let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec();
            LocalFree(sid);
            bytes
        }
    }

    /// An entry of an access list in its binary form: its kind, its rights, its trustee and what
    /// follows the trustee, padded to a whole number of words.
    fn entry(kind: u8, rights: u32, trustee: &str, condition: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, 0, 0, 0];
        bytes.extend(rights.to_le_bytes());
        bytes.extend(sid(trustee));
        bytes.extend(condition);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        let size = u16::try_from(bytes.len()).expect("a short entry");
        bytes[2..4].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    /// The condition `@User.X == "<literal>"` in its binary form, whatever the literal holds, and
    /// followed by `padding` bytes of padding, which the text of the entry does not show.
    fn condition_on(literal: &str, padding: usize) -> Vec<u8> {
        let mut bytes = b"artx".to_vec();
        for (token, text) in [(0xF9_u8, "X"), (0x10, literal)] {
            let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            bytes.push(token);
            bytes.extend(
                u32::try_from(units.len())
                    .expect("a short text")
                    .to_le_bytes(),
            );
            bytes.extend(units);
        }
        bytes.push(0x80);
        bytes.extend(std::iter::repeat_n(0, padding));
        bytes
    }

    /// An access list made of the entries given, in their binary form, which the text of a
    /// descriptor has no form for when a string holds a double quote. The list is given `room`
    /// bytes more than its entries use, a multiple of four. The list is the buffer's start.
    fn acl_of(entries: &[Vec<u8>], room: usize) -> Vec<u32> {
        let size = 8 + entries.iter().map(Vec::len).sum::<usize>() + room;
        let mut words = vec![0_u32; size.div_ceil(4)];
        let acl: *mut ACL = words.as_mut_ptr().cast();
        // SAFETY: the list is a live buffer of the size given, aligned for one, and the revision
        // is the one that holds every kind of entry.
        let started = unsafe { InitializeAcl(acl, u32::try_from(words.len() * 4).unwrap_or(0), 4) };
        assert_ne!(
            started,
            0,
            "the list was not started: {}",
            io::Error::last_os_error()
        );
        for each in entries {
            let mut aligned = vec![0_u32; each.len().div_ceil(4)];
            // SAFETY: `aligned` holds at least `each.len()` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    each.as_ptr(),
                    aligned.as_mut_ptr().cast(),
                    each.len(),
                )
            };
            // SAFETY: the list has room for the entry, which is whole and aligned.
            let added = unsafe {
                AddAce(
                    acl,
                    4,
                    u32::MAX,
                    aligned.as_ptr().cast(),
                    u32::try_from(each.len()).unwrap_or(0),
                )
            };
            assert_ne!(
                added,
                0,
                "an entry was not added: {}",
                io::Error::last_os_error()
            );
        }
        words
    }

    /// The system's refusal or the desktop made with an access list of the entries given, given
    /// `room` bytes more than they use.
    fn try_desktop_with_entries(entries: &[Vec<u8>], room: usize) -> io::Result<Desktop> {
        let mut words = acl_of(entries, room);
        let acl: *mut ACL = words.as_mut_ptr().cast();
        // SAFETY: all-zero is the initial state `InitializeSecurityDescriptor` is given.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let pointer = (&raw mut descriptor).cast();
        // SAFETY: the pointer is to a live descriptor of the full size, and the list lives until
        // the desktop is made.
        unsafe {
            InitializeSecurityDescriptor(pointer, 1);
            SetSecurityDescriptorDacl(pointer, 1, acl, 0);
        }
        try_desktop_made(&attributes(&mut descriptor))
    }

    /// A desktop whose access list is made of the entries given, in their binary form.
    fn desktop_with_entries(entries: &[Vec<u8>]) -> Desktop {
        try_desktop_with_entries(entries, 0)
            .unwrap_or_else(|error| panic!("the desktop was not made: {error}"))
    }

    /// The entries of a list with a condition, padded as asked.
    fn entries_with_a_condition(padding: usize) -> Vec<Vec<u8>> {
        vec![
            entry(0x0A, 0x1, "BG", &condition_on("a", padding)),
            entry(0x00, 0x1, "SY", &[]),
        ]
    }

    /// A list that holds a condition is used beside a list of the same entries, when the text
    /// accounts for the entries it holds, and not beside a list whose text is the same and whose
    /// entries are other bytes: the text of a condition does not tell two lists apart.
    #[test]
    fn a_list_with_a_condition_is_used_only_beside_the_same_entries() {
        let own = desktop_with_entries(&entries_with_a_condition(0));
        let same = desktop_with_entries(&entries_with_a_condition(0));
        let padded = desktop_with_entries(&entries_with_a_condition(4));
        let source = security_of(own.0).expect("the starter's own security");
        let text_of = |desktop: &Desktop| {
            security_of(desktop.0)
                .expect("a desktop's security")
                .text(DACL_SECURITY_INFORMATION)
                .expect("a desktop's text")
        };
        assert_eq!(
            text_of(&padded),
            text_of(&own),
            "the system writes the padding, so the lists' text differs"
        );
        source
            .require_no_more_on(same.0)
            .expect("a list with the same entries is used");
        let error = source
            .require_no_more_on(padded.0)
            .expect_err("a list with other bytes and the same text was used");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("not the same bytes"), "{error}");
    }

    /// Entries whose strings hold a double quote, for which the text of a descriptor has no form
    /// and the system writes the quote as it is: read as the text reads, the strings end early and
    /// the entries between them are lost to the reader. The starter does not read such a text.
    #[test]
    fn a_desktop_whose_text_would_hide_entries_behind_a_string_is_unreadable() {
        let denying = 0x0A;
        let allowing = 0x00;
        let target = desktop_with_entries(&[
            entry(denying, 0x1, "BG", &condition_on("a\"b", 0)),
            entry(allowing, 0x1, NOBODY, &[]),
            entry(denying, 0x1, "BG", &condition_on("c\"d", 0)),
            entry(allowing, 0x1, "SY", &[]),
        ]);
        let there = security_of(target.0).expect("the target's security");
        assert_eq!(there.access_entries().expect("the target's count"), 4);
        let text = there
            .text(DACL_SECURITY_INFORMATION)
            .expect("the target's text");
        println!("the system wrote {text}");
        assert!(
            text.contains("a\"b"),
            "the system wrote the quote another way: {text}"
        );
        let error = refusal(&target);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(error.to_string().contains("could not be read"), "{error}");
    }

    /// A source over an access list the system did not store: the list lives in the buffer given,
    /// which must outlive the source and every slice read from it, and there is no descriptor to
    /// free. The caller keeps the buffer in a binding declared before the source.
    fn source_over(list: &[u32]) -> Source {
        Source {
            descriptor: std::ptr::null_mut(),
            access: list.as_ptr().cast_mut().cast(),
            label: std::ptr::null_mut(),
        }
    }

    /// The entries of a list are read without its header and without the room it was given: a
    /// list given more room than its entries use is the same list as one that was not, as the
    /// reading takes it from a list of its own and as the system holds one set on a desktop.
    /// Created with room, a list is stored without it, which the case prints.
    #[test]
    fn a_list_given_extra_room_is_read_as_the_entries_it_holds() {
        const ROOM: usize = 64;
        let entries = entries_with_a_condition(0);
        let held = entries.concat();
        let (tight, roomy) = (acl_of(&entries, 0), acl_of(&entries, ROOM));
        let (tight_source, roomy_source) = (source_over(&tight), source_over(&roomy));
        let size = roomy_source.access_size().expect("the roomy list's size");
        assert!(
            usize::try_from(size.AclBytesFree).is_ok_and(|free| free >= ROOM),
            "the list was given no room: {} bytes free",
            size.AclBytesFree
        );
        assert_eq!(tight_source.access_bytes().expect("the tight list"), held);
        assert_eq!(roomy_source.access_bytes().expect("the roomy list"), held);

        // Created with room, the system stores the list without it. Set on a desktop that exists,
        // it may keep the room.
        let (tight_desktop, set_desktop) = (
            desktop_with_entries(&entries),
            desktop_with_entries(&entries),
        );
        // SAFETY: the desktop is open with the right to change its list, the owner, group and
        // label are absent, and the roomy list lives in this case until the call returns.
        let set = unsafe {
            SetSecurityInfo(
                set_desktop.0,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                roomy.as_ptr().cast(),
                std::ptr::null(),
            )
        };
        assert_eq!(
            set,
            0,
            "the roomy list was not set on the desktop: {}",
            io::Error::from_raw_os_error(i32::try_from(set).unwrap_or(i32::MAX))
        );
        let (tight_security, set_security) = (
            security_of(tight_desktop.0).expect("the tight desktop's security"),
            security_of(set_desktop.0).expect("the set desktop's security"),
        );
        println!(
            "bytes free: {} for a list created tight, {} for one set with {ROOM} bytes of room",
            tight_security.access_size().expect("size").AclBytesFree,
            set_security.access_size().expect("size").AclBytesFree,
        );
        tight_security
            .require_no_more_on(set_desktop.0)
            .expect("a list set with extra room is used beside one that was not");
        set_security
            .require_no_more_on(tight_desktop.0)
            .expect("a list that was not set with extra room is used beside one that was");
    }

    /// An empty access list is a list that admits nobody, not a missing one: it has no entries and
    /// no bytes, which is not an error, it is used beside another empty one, and a list that admits
    /// someone is refused beside it.
    #[test]
    fn an_empty_access_list_has_no_entries_and_no_bytes() {
        let empty = desktop_with("D:");
        let source = security_of(empty.0).expect("the empty list's security");
        println!(
            "the empty list is read back as {:?}, with {} bytes in use",
            source.text(DACL_SECURITY_INFORMATION),
            source.access_size().expect("the size").AclBytesInUse
        );
        assert!(
            !source.access.is_null(),
            "the empty list was read back as null"
        );
        assert_eq!(source.access_entries().expect("the count"), 0);
        assert_eq!(source.access_bytes().expect("the bytes"), b"");
        source
            .require_no_more_on(desktop_with("D:").0)
            .expect("an empty list is used beside another");
        let someone = desktop_with("D:(A;;GA;;;WD)");
        let error = source
            .require_no_more_on(someone.0)
            .expect_err("a list that admits someone was used beside an empty one");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("admits more"), "{error}");
    }

    /// The starter's copy of its own list, which it gives a new object through `access_only`, is
    /// the same list: a list with a condition reaches the new object as the same entries, and the
    /// object is used beside the list it was copied from.
    #[test]
    fn the_starters_copy_of_a_list_with_a_condition_is_used() {
        let model = desktop_with_entries(&entries_with_a_condition(0));
        let source = security_of(model.0).expect("the model's security");
        let mut copied = source.access_only();
        let copy = desktop_made(&attributes(&mut copied));
        let there = security_of(copy.0).expect("the copy's security");
        assert_eq!(
            there.access_bytes().expect("the copy's entries"),
            source.access_bytes().expect("the model's entries"),
            "the system stored the entries of the copy as other bytes"
        );
        source
            .require_no_more_on(copy.0)
            .expect("the starter's copy of its own list is used");
    }

    /// An object with no integrity label has none to put on another: applying it leaves the label
    /// the other has, and the other is still refused for being below the medium level. The lists
    /// are the same on both and grant everyone every right, including the one that changes a
    /// label, so the case does not depend on the list of the desktop it runs on.
    #[test]
    fn an_object_with_no_integrity_label_leaves_the_label_it_is_applied_to() {
        let access = "D:(A;;GA;;;WD)";
        let model = desktop_with(access);
        let source = security_of(model.0).expect("the model's security");
        assert!(
            source.label.is_null(),
            "the model has an integrity label: {:?}",
            source.text(LABEL_SECURITY_INFORMATION)
        );
        let lower = desktop_with(&format!("{access}S:(ML;;NW;;;S-1-16-0)"));
        source.label_onto(lower.0);
        let there = security_of(lower.0)
            .expect("the target's security")
            .text(LABEL_SECURITY_INFORMATION)
            .expect("the target's label");
        assert!(
            there.contains("S-1-16-0"),
            "the label was taken off: {there:?}"
        );
        let error = source
            .require_no_more_on(lower.0)
            .expect_err("a desktop below the medium level was used");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("integrity label"), "{error}");
    }

    /// A callback entry that the system writes with no condition changes the list the starter
    /// judges all the same. Read by its text, a further denying entry of that kind would be one
    /// that narrows the starter's own list and the object would be used, and a further allowing one
    /// would be called wider. The starter reads such a list by its bytes instead, and stops with
    /// an error that says the lists are not the same bytes. The case prints what the system
    /// writes for the entry.
    #[test]
    fn a_callback_entry_the_text_shows_no_condition_for_is_judged_by_its_bytes() {
        let own = desktop_with_entries(&[entry(0x00, 0x1, "SY", &[])]);
        let source = security_of(own.0).expect("the starter's own security");
        for kind in [0x09, 0x0A] {
            let target =
                desktop_with_entries(&[entry(kind, 0x1, "BG", &[]), entry(0x00, 0x1, "SY", &[])]);
            println!(
                "kind {kind:#x}: the system writes {:?}",
                security_of(target.0)
                    .expect("the target's security")
                    .text(DACL_SECURITY_INFORMATION)
            );
            let error = source
                .require_no_more_on(target.0)
                .expect_err("a list with a callback entry was used beside a list without one");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "kind {kind:#x}: {error}"
            );
            assert!(
                error.to_string().contains("not the same bytes"),
                "kind {kind:#x}: {error}"
            );
        }
    }
}
