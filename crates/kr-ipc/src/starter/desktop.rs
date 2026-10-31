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
        // with this call, and nothing else holds it. The two lists point inside it.
        unsafe { LocalFree(self.descriptor) };
    }
}

impl Source {
    /// A descriptor that holds the access list alone. A descriptor that carries the label cannot
    /// be given to a new object without a privilege the starter does not hold, so the label is
    /// applied afterwards by [`Self::label_onto`], which asks for none up to the caller's own
    /// level.
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
                label: &own_label,
            },
            &Texts {
                access: &found_access,
                access_entries: there.access_entries()?,
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

    /// How many entries this object's access list holds, as the system counts them, which the
    /// text of the list must account for: a text that reads as fewer entries has hidden some.
    fn access_entries(&self) -> io::Result<usize> {
        if self.access.is_null() {
            return Ok(0);
        }
        // SAFETY: all-zero is a valid value of this plain structure of counts.
        let mut size: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
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
        Ok(usize::try_from(size.AceCount).unwrap_or(usize::MAX))
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
/// own, and ask what the starter makes of each against the security of the desktop the test runs on.
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

    /// The security of the desktop this thread runs on, which is what the starter takes for its
    /// own.
    fn own() -> Source {
        let name = name_of(current_desktop()).expect("the desktop's name");
        let opened = Desktop::open(&name, READ_CONTROL).expect("the desktop opens to be read");
        security_of(opened.0).expect("the desktop's security")
    }

    /// The text of the starter's own access list.
    fn own_access_list() -> String {
        own()
            .text(DACL_SECURITY_INFORMATION)
            .expect("the starter's own access list")
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
        assert!(
            !handle.is_null(),
            "the desktop was not made: {}",
            io::Error::last_os_error()
        );
        Desktop(handle)
    }

    /// What the starter makes of `target` as a desktop to use, given the desktop this thread runs
    /// on as its own.
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
        assert!(
            counted >= 2,
            "the starter's own access list is too short to show this: {text}"
        );
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
            own().text(LABEL_SECURITY_INFORMATION),
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
        let there = security_of(lower.0).expect("the target's security");
        assert_eq!(
            there
                .text(LABEL_SECURITY_INFORMATION)
                .expect("the target's label"),
            source
                .text(LABEL_SECURITY_INFORMATION)
                .expect("the model's label")
        );
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

    /// The condition `@User.X == "<literal>"` in its binary form, whatever the literal holds.
    fn condition_on(literal: &str) -> Vec<u8> {
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
        bytes
    }

    /// A desktop whose access list is made of the entries given, in their binary form, which the
    /// text of a descriptor has no form for when a string holds a double quote.
    fn desktop_with_entries(entries: &[Vec<u8>]) -> Desktop {
        let size = 8 + entries.iter().map(Vec::len).sum::<usize>();
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
        // SAFETY: all-zero is the initial state `InitializeSecurityDescriptor` is given.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let pointer = (&raw mut descriptor).cast();
        // SAFETY: the pointer is to a live descriptor of the full size, and the list lives until
        // the desktop is made.
        unsafe {
            InitializeSecurityDescriptor(pointer, 1);
            SetSecurityDescriptorDacl(pointer, 1, acl, 0);
        }
        desktop_made(&attributes(&mut descriptor))
    }

    /// Entries whose strings hold a double quote, for which the text of a descriptor has no form
    /// and the system writes the quote as it is: read as the text reads, the strings end early and
    /// the entries between them are lost to the reader. The starter does not read such a text.
    #[test]
    fn a_desktop_whose_text_would_hide_entries_behind_a_string_is_unreadable() {
        let denying = 0x0A;
        let allowing = 0x00;
        let target = desktop_with_entries(&[
            entry(denying, 0x1, "BG", &condition_on("a\"b")),
            entry(allowing, 0x1, NOBODY, &[]),
            entry(denying, 0x1, "BG", &condition_on("c\"d")),
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
}
