//! A small virtual disk with a file system of the case's choosing, mounted on a letter.

use std::path::Path;

/// Makes a small virtual disk with the file system given, mounted on a letter, and removes it
/// when dropped.
pub struct Disk {
    file: std::path::PathBuf,
}

impl Disk {
    pub fn new(
        scratch: &super::Scratch,
        file_system: &str,
        megabytes: u32,
        letter: char,
    ) -> Result<Disk, String> {
        let file = scratch.path(&format!("{file_system}.vhd"));
        let script = scratch.path(&format!("{file_system}.txt"));
        std::fs::write(
            &script,
            format!(
                "create vdisk file=\"{}\" maximum={megabytes} type=expandable\nselect vdisk file=\"{}\"\nattach vdisk\ncreate partition primary\nformat fs={file_system} quick\nassign letter={letter}\n",
                file.display(),
                file.display()
            ),
        )
        .unwrap();
        let out = std::process::Command::new("diskpart.exe")
            .arg("/s")
            .arg(&script)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let disk = Disk { file };
        if Path::new(&format!("{letter}:\\")).exists() {
            Ok(disk)
        } else {
            Err(text)
        }
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        let script = self.file.with_extension("detach.txt");
        let _ = std::fs::write(
            &script,
            format!(
                "select vdisk file=\"{}\"\ndetach vdisk\n",
                self.file.display()
            ),
        );
        let _ = std::process::Command::new("diskpart.exe")
            .arg("/s")
            .arg(&script)
            .output();
    }
}
