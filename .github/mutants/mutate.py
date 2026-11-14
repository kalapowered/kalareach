"""Applies one named mutation to the store's source, in place. Exits 2 when the text it replaces is not there."""
import sys

WINDOWS = "crates/kr-ipc/src/install/windows.rs"
INSTALL = "crates/kr-ipc/src/install.rs"

TAG_CHECK = """    if reparse_tag(&directory)? != Some(IO_REPARSE_TAG_MOUNT_POINT) {
        return Ok(false);
    }
"""

SWITCH_USES_IT = """        if windows::point_junction(&self.current_link(), &target)
            .map_err(|error| InstallError::io("point the link", self.current_link(), error))?
        {
            return Ok(());
        }
"""

MUTANTS = {
    # The junction is never pointed in place: the rename replaces it, as it did before.
    "M1": [(WINDOWS, "pub(super) fn point_junction(link: &Path, target: &Path) -> io::Result<bool> {\n",
            "pub(super) fn point_junction(link: &Path, target: &Path) -> io::Result<bool> {\n    return Ok(false);\n")],
    # What is there is not checked to be a junction before the target is set.
    "M2": [(WINDOWS, TAG_CHECK, "    let _ = reparse_tag(&directory)?;\n")],
    # The target is set through the name and not through the handle that was looked at.
    "M3": [(WINDOWS, "    set_reparse_data(&directory, &data)?;\n    at(Moment::JunctionPointed, link);",
            "    set_junction(link, &data)?;\n    at(Moment::JunctionPointed, link);")],
    # The change is not flushed.
    "M4": [(WINDOWS, "    directory.sync_all()?;\n    Ok(true)", "    Ok(true)")],
    # The target is not set at all, and the switch says it was.
    "M5": [(WINDOWS, "    set_reparse_data(&directory, &data)?;\n    at(Moment::JunctionPointed, link);",
            "    let _ = (&directory, &data);\n    at(Moment::JunctionPointed, link);")],
    # Where there is no junction the switch makes none.
    "M6": [(INSTALL, SWITCH_USES_IT,
            """        windows::point_junction(&self.current_link(), &target)
            .map_err(|error| InstallError::io("point the link", self.current_link(), error))?;
        return Ok(());
""")],
    # The switch says it did not point the junction after it did, so the rename replaces it too.
    "M7": [(WINDOWS, "    directory.sync_all()?;\n    Ok(true)", "    directory.sync_all()?;\n    Ok(false)")],
}


def main() -> int:
    name = sys.argv[1]
    for path, old, new in MUTANTS[name]:
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        if text.count(old) != 1:
            print(f"MUTATION-ERROR {name}: the text to replace is not there once in {path}")
            return 2
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text.replace(old, new))
    print(f"MUTATION-APPLIED {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
