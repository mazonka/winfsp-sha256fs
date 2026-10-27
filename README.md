# winfsp-sha256fs
WinFsp Content-Addressable Passthrough Filesystem

**Status:** Design specification and implementation plan  
**Platform:** Windows  
**Language:** C++  
**Filesystem framework:** WinFsp  
**Working source baseline:** Official WinFsp C++ passthrough example  
**Current status:** The baseline compiles and runs successfully. The content-addressable storage features are to be implemented incrementally.

---

## 1. Purpose

Develop a Windows filesystem mounted as a drive, for example `X:`, that behaves like an ordinary filesystem from the user's perspective while storing file contents using SHA-256 content-addressable storage in the backing directory.

The filesystem must:

1. Present a familiar directory tree with original filenames.
2. Store the contents of hashed files in a SHA-256 object store.
3. Use small `.sha256` sidecar files to represent hashed files in the backing directory.
4. Track which virtual files reference each content object.
5. Archive objects when no virtual files reference them.
6. Support normal file and directory operations, including creating, reading, writing, deleting, and renaming files.
7. Preserve filename case.
8. Restrict filenames and directory names to a configurable set of ASCII characters.
9. Avoid concurrent access to the same file by allowing only one active open handle at a time.
10. Use standard C++ facilities for backing-store operations wherever practical.

The implementation must be reliable and maintainable. The first priority is correct filesystem behaviour; content-addressable storage should be added only after the basic passthrough behaviour and filename restrictions have been tested.

## 2. Current working baseline

The official upstream WinFsp C++ example as the starting point:

https://github.com/winfsp/winfsp/blob/master/tst/passthrough-cpp/passthrough-cpp.cpp

This is the C++ implementation based on `Fsp::FileSystemBase`, not the older C passthrough sample.

## 3. Terminology and paths

Use the following example configuration:

| Item | Path |
|---|---|
| Physical backing root | `C:\mydrive` |
| Virtual mount | `X:\` |
| Content object directory | `C:\mydrive\_sha256` |
| Archived object directory | `C:\mydrive\_deleted` |

The physical backing root and virtual mount are different namespaces.

The virtual namespace is what applications see on `X:`. The physical namespace contains the real directory structure, sidecar files, content objects, reference lists, and archived objects.

The implementation must never expose its internal storage files as ordinary virtual files.

## 4. Virtual namespace

The filesystem must preserve the user's familiar directory structure and filenames.

For example, the virtual filesystem might contain:

```text
X:\
+-- docs\
¦   +-- report1.txt
+-- today_work\
¦   +-- report1.txt
+-- arxiv\
    +-- report2.txt
    +-- data.txt
```

These names and directories remain visible even when the file contents are stored elsewhere in the backing store.

Two different virtual paths may reference the same content object when their contents have identical SHA-256 hashes.

The internal directories `_sha256` and `_deleted` are reserved. They must not be exposed or manipulated as ordinary virtual directories.

A file's `.sha256` sidecar is an internal representation, not a separate visible file. For example, the physical file `report1.txt.sha256` represents the virtual file `report1.txt`.

## 5. Filename and directory-name restrictions

### 5.1 Allowed characters

Every ordinary filename and directory-name component must contain only these ASCII characters:

- Uppercase letters: `A`–`Z`
- Lowercase letters: `a`–`z`
- Digits: `0`–`9`
- Underscore: `_`
- Period: `.`
- Dash: `-`

Examples of allowed names:

```text
report1
report1.txt
My_Document
version_2.1
archive.tar.gz
A_B_123
```

Examples of rejected names:

```text
my document
my$document
file@home
café
??
```

The character rule must be implemented in one central helper function so additional permitted characters can be introduced later by modifying that helper rather than rewriting validation logic throughout the code.

### 5.2 Path validation

Validate each component of a path independently. Directory separators are path syntax, not filename characters.

The special components `.` and `..` must not be accepted as ordinary names. In particular, reject `..` as a traversable component so that a request cannot escape the configured backing root.

Names such as `report1.txt` and `archive.tar.gz` are valid; a component consisting solely of periods is not.

The validation rule applies to:

- File creation
- Directory creation
- Opening files
- Looking up attributes and security information
- Renaming source and destination paths
- Directory enumeration
- Any other callback that accepts or exposes a path or name

For names already present in the physical backing directory, entries that violate the configured rule must not be exposed as ordinary virtual entries.

Internal storage names and generated sidecar names must be handled explicitly by the filesystem's internal logic. The user-facing rule must not accidentally prevent the implementation from resolving its own internal files.

### 5.3 Case preservation

Preserve the spelling and letter case of names.

For example, `MyReport.txt` must not silently become `myreport.txt`.

Do not lowercase or uppercase paths to construct backing paths. When resolving an existing path, use the actual spelling of each existing component in the backing directory.

On Windows, path lookup is normally case-insensitive. The filesystem should follow the configured Windows/WinFsp case-matching behaviour while preserving the actual case returned by directory enumeration.

When creating a new entry, preserve the spelling supplied by the caller.

## 6. Content-addressable storage

### 6.1 Hash algorithm

Use SHA-256 over the exact file contents.

Represent the digest as 64 lowercase hexadecimal characters.

For example, the SHA-256 digest of the byte sequence `abc` is:

```text
ba7816bf8f01cfea414140de5dae2223
b00361a396177a9cb410ff61f20015ad
```

The two lines above are a display split; the stored digest must be one uninterrupted 64-character hexadecimal string.

The digest must be calculated from the actual bytes, not from a filename, text encoding, timestamps, or other metadata.

### 6.2 Object directory layout

Store objects under `_sha256`, using prefixes of the digest to distribute objects across subdirectories.

The intended layout is:

```text
C:\mydrive\_sha256\
    ba\
        ba78\
            ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

The object filename is the complete 64-character digest.

The directory layout above repeats the first two and first four hexadecimal characters of the hash in the two directory names. Keep this convention consistent across object creation, lookup, deletion, and recovery.

The object contains the original file bytes.

### 6.3 Deduplication

When a file is hashed:

1. Calculate its SHA-256 digest.
2. Determine the corresponding object path.
3. Check whether an object with that digest already exists.
4. If it exists, reuse it rather than storing a duplicate.
5. If it does not exist, publish the content as a new object.
6. Create or update the object's reference list.
7. Replace the virtual file's physical representation with its `.sha256` sidecar.

A matching hash identifies the same content for deduplication purposes. The implementation should still handle file-operation failures and incomplete updates rather than assuming every operation succeeds.

### 6.4 Publishing objects

Prefer moving the completed file into the object store when the source and destination permit a move. Avoid copying the entire file unnecessarily.

If a move is not possible, use a safe alternative that ensures a complete object is available before publishing the virtual reference to it.

Do not leave a partially written object exposed as a valid content object.

## 7. SHA-256 sidecar files

For each hashed virtual file, keep a small sidecar in the corresponding physical directory.

For example:

```text
Virtual file:
X:\docs\report1.txt

Physical sidecar:
C:\mydrive\docs\report1.txt.sha256
```

The sidecar contains the full lowercase SHA-256 digest, followed by a newline.

Example:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

When an application opens `X:\docs\report1.txt`, the filesystem must:

1. Resolve the virtual path to its physical representation.
2. Detect the `.sha256` sidecar.
3. Read and validate the digest.
4. Resolve the digest to the object path.
5. Open the actual content object.
6. Return the object's contents through the ordinary virtual file interface.

The sidecar must never be returned as the file contents of the virtual file.

If a sidecar is malformed or references a missing object, return an appropriate filesystem error. Do not silently treat the sidecar text as the file's contents.

## 8. Object reference lists

Each content object has an associated `.refs` file stored alongside it.

For example:

```text
C:\mydrive\_sha256\ba\ba78\
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.refs
```

The `.refs` file lists the virtual paths that currently refer to the object, using paths relative to the virtual root.

For example:

```text
docs\report1.txt
today_work\report1.txt
```

These paths may share the same object because the files have identical content.

Maintain the reference list when files are:

- Created and hashed
- Deleted
- Renamed
- Replaced with different content
- Modified and rehashed

Each virtual path should appear at most once in the reference list.

Reference operations must be idempotent where practical: retrying a failed or repeated operation must not create duplicate references or remove unrelated references.

Do not create empty or orphan `.refs` files in arbitrary locations, particularly under `_deleted`.

## 9. Unreferenced object archival

When a virtual file stops referring to an object, remove its reference from the object's `.refs` file.

If other references remain, keep the object in `_sha256`.

If no references remain, archive the object and its associated internal metadata under `_deleted`.

The intended archive layout is:

```text
C:\mydrive\_deleted\
    YYMMDD_HHMMSS_nanosecs\
        <last-reference-name-or-path>
```

The timestamp directory name contains:

- Two-digit year
- Month
- Day
- Underscore
- Hour
- Minute
- Second
- Underscore
- Nanosecond component

Use a collision-safe naming strategy so two archival operations do not overwrite one another.

The archived object's final name should be derived from the last reference name or path, as required by the original design. Preserve enough information to identify the archived content and its origin.

The archive operation must not leave an object in an inconsistent state where its references have been removed but its content has been lost.

If reference metadata or archival operations fail, report the failure and preserve recoverable data wherever possible.

## 10. Creating and writing files

A newly created or modified file must be writable through the ordinary virtual filesystem interface.

An implementation may use an ordinary physical file as a temporary working representation while a file is being written. Such a file does not yet need a `.sha256` sidecar.

Once writing has completed and the file is ready to be committed:

1. Flush and close the writable representation as required.
2. Calculate the SHA-256 digest of the completed content.
3. Publish or reuse the corresponding content object.
4. Write the sidecar containing the digest.
5. Register the virtual path in the object's `.refs` file.
6. Remove the temporary physical file once the new representation is safely committed.

The exact point at which hashing occurs must be implemented consistently with WinFsp's file lifecycle. In particular, distinguish closing a handle from completing the final update: WinFsp may invoke `Cleanup` and `Close` separately.

Do not hash a file before all intended writes and size changes are complete.

## 11. Modifying existing hashed files

Modifying an existing hashed file must not corrupt content shared by other virtual files.

Use copy-on-write semantics.

When an application opens a hashed file for modification:

1. Resolve the existing sidecar and object.
2. Create a separate writable working copy.
3. Keep the existing object unchanged.
4. Direct modifications to the working copy.
5. When the modification is complete, calculate the new content hash.
6. Publish or reuse the new object.
7. Update the sidecar to reference the new hash.
8. Remove the virtual path from the old object's reference list.
9. Add the virtual path to the new object's reference list.
10. Archive the old object if its reference count becomes zero.

If the modified content has the same hash as before, avoid unnecessary object replacement and metadata churn where practical.

The original shared object must remain intact until the new representation has been safely committed.

A failed write or commit must not destroy the last valid version of the file.

## 12. Concurrency and file access

The filesystem should use a deliberately simple access model.

**Only one active open handle is permitted for a given virtual file at a time.** A second open of the same file must fail with an appropriate sharing or access error, regardless of whether the second request is for reading or writing.

This means the implementation does not need to support multiple simultaneous readers, a reader and a writer at the same time, or multiple writers.

Different files may be handled independently, subject to the selected WinFsp dispatch configuration.

Implement an active-open registry keyed by the resolved virtual path. Use a consistent comparison policy that matches the filesystem's Windows case-matching behaviour while retaining the original spelling.

The registry must:

- Register a file when its open succeeds.
- Reject another open while the file remains active.
- Release the entry on every relevant cleanup, close, and error path.
- Avoid stale entries when an operation fails.
- Handle rename and deletion without corrupting registry state.

Do not assume that selecting a single dispatch thread automatically guarantees all required file-access semantics. Verify the WinFsp host's dispatch configuration and enforce the single-open rule explicitly.

The design does not require complex multi-handle coordination, shared write locks, or concurrent modifications of the same file.

## 13. File and directory operations

The implementation must support ordinary filesystem operations while preserving the storage model.

### Lookup and open

- Resolve existing names using actual backing-directory spelling.
- Recognize sidecars as representations of virtual files.
- Resolve the hash to the object.
- Validate the path and verify that the object exists.
- Enforce the single-open rule.

### Creation

- Validate the new name.
- Create the physical directory or temporary file as appropriate.
- Preserve the requested name and case.
- Register the active open if a handle is returned.

### Directory enumeration

- Enumerate ordinary visible files and directories.
- Hide `.sha256` sidecars and internal object-store files.
- Hide `_sha256` and `_deleted`.
- Preserve the actual case of enumerated names.
- Apply the name-validation rule to physical entries.
- Present a sidecar-backed file under its original virtual name.

### Deletion

- Resolve the virtual file to its physical representation.
- Remove the virtual representation.
- Remove its path from the object's reference list.
- Archive the object if it becomes unreferenced.
- Do not archive a shared object while another reference remains.

### Rename

Renaming must preserve virtual filesystem semantics.

For a hashed file, the physical operation is not simply renaming the sidecar: the reference list must be updated to reflect the new virtual path.

The operation must validate both the source and destination paths and handle destination replacement according to WinFsp's `ReplaceIfExists` semantics.

If the destination is another hashed file, its existing reference must be removed and its object archived if it becomes unreferenced.

Where an operation affects multiple physical files or metadata records, define a safe ordering and error-recovery strategy. Do not report success if the virtual namespace and reference metadata have become inconsistent.

### Metadata and security

Continue to implement the WinFsp callbacks required by the upstream example, including file information, basic attributes, file size, directory enumeration, and security operations.

Use the content object's size and appropriate timestamps or metadata for sidecar-backed files. The metadata policy should be consistent across ordinary and hashed files.

## 14. Implementation technology

Use the upstream WinFsp C++ class structure as the integration layer.

The existing source uses `Fsp::FileSystemBase` and implements callbacks including:

- `GetSecurityByName`
- `Create`
- `Open`
- `Overwrite`
- `Cleanup`
- `Close`
- `Read`
- `Write`
- `Flush`
- `GetFileInfo`
- `SetBasicInfo`
- `SetFileSize`
- `CanDelete`
- `Rename`
- `ReadDirectory`
- `ReadDirectoryEntry`

Use portable standard C++ facilities for backing-file operations wherever feasible:

- `std::filesystem` for path construction, existence checks, directory iteration, moves, deletion, and file sizes.
- `std::ifstream`, `std::ofstream`, or `std::fstream` for content access where their semantics suffice.
- A standard or well-tested SHA-256 implementation for hashing.

WinFsp callbacks and Windows-specific metadata, security, and host integration may still require Win32 and WinFsp APIs. The goal is to avoid unnecessary Win32 calls for ordinary backing-file manipulation, not to remove the Windows-specific integration layer.

For file content, ensure that streams support the required byte-level and offset-based behaviour. Standard C++ streams do not automatically provide all the semantics of Windows file handles, so implement and test seeking, truncation, flushing, and error handling explicitly.

Use wide-character Windows paths where required by WinFsp. ASCII-only filename validation should not require converting names through a Unicode-to-UTF-8 transformation.

## 15. Error handling and consistency

The filesystem must treat object content, sidecars, and reference lists as related state.

Potential failure cases include:

- Hash computation failure
- Object already exists
- Object creation or move failure
- Sidecar write failure
- Reference-list update failure
- Missing or malformed sidecar
- Missing object
- Disk-full errors
- Failed rename or replacement
- Failed deletion or archival
- Unexpected interruption during commit

Avoid deleting the old valid content before the new content and its metadata have been safely published.

Where possible, write temporary metadata and publish it through a final rename. A single filesystem operation may be atomic under certain conditions, but a sequence of changes to an object, sidecar, and reference list is not automatically atomic as a group.

Define the order of operations so that an interruption leaves recoverable state rather than silently losing file contents.

The design should favour preserving content over aggressive cleanup when an operation fails.

## 16. Recommended implementation stages

Implement and test each stage before proceeding.

### Stage 1 — Preserve the working baseline

- Save the current compiling and running passthrough source.
- Confirm the mount and ordinary file operations work.
- Record the exact command-line build configuration.

**Acceptance:** The unmodified baseline can be rebuilt and mounted reliably.

### Stage 2 — Filename validation

- Add the central configurable character predicate.
- Add whole-name and path-component validation.
- Enforce the rule for files and directories.
- Reject traversal components.
- Validate rename source and destination.
- Filter unsupported names from directory enumeration.
- Keep case unchanged.

**Acceptance:** Valid names work, invalid names are rejected, and existing valid files retain their original case.

### Stage 3 — Single-open behaviour

- Add an active-open registry.
- Reject a second open of the same resolved virtual path.
- Release the registry entry on all appropriate cleanup and error paths.
- Verify the case-matching policy.

**Acceptance:** A second open fails while the first is active; reopening works after the first handle is fully released.

### Stage 4 — Sidecar-backed reads

- Implement SHA-256 calculation.
- Implement object-path construction and lookup.
- Read and validate `.sha256` sidecars.
- Resolve virtual file reads to content objects.
- Hide internal storage from directory enumeration.

**Acceptance:** A correctly constructed sidecar-backed file can be opened and read with the expected bytes.

### Stage 5 — Object publishing and references

- Implement object creation and deduplication.
- Implement `.refs` creation and updates.
- Convert a completed ordinary file into a sidecar-backed file.
- Ensure no duplicate references or spurious `.refs` files are created.

**Acceptance:** Two files with identical content share one object and have two correct references.

### Stage 6 — Copy-on-write updates

- Create a separate writable copy when modifying a hashed file.
- Commit the new content object and sidecar.
- Update old and new reference lists.
- Preserve the original content if the update fails.

**Acceptance:** Modifying one of two files sharing an object changes only the modified file's content.

### Stage 7 — Delete, rename, and archive

- Implement reference removal on deletion.
- Update references on rename.
- Handle replacement of an existing destination.
- Archive unreferenced objects under `_deleted`.
- Validate all path and reference transitions.

**Acceptance:** Objects remain available while referenced and are archived only when their last reference is removed.

### Stage 8 — Failure and recovery tests

Test interrupted and failed operations, missing objects, malformed sidecars, disk-full conditions where practical, and inconsistent reference metadata.

**Acceptance:** Failures return appropriate errors and do not silently destroy the last valid file contents.

## 17. Test plan

At minimum, test the following scenarios.

| Test | Expected result |
|---|---|
| Create and read a normal file | Contents match exactly |
| Create a directory | Directory is visible |
| Create `Report_1.txt` | Accepted |
| Create `Report-1.txt` | Rejected |
| Create a name containing spaces | Rejected |
| Create a name containing non-ASCII characters | Rejected |
| Create `archive.tar.gz` | Accepted |
| Create `.` or `..` as an ordinary component | Rejected |
| Enumerate a mixed-case filename | Original case is preserved |
| Open a file twice simultaneously | Second open fails |
| Reopen after closing the first handle | Succeeds |
| Hash two identical files | Both refer to the same object |
| Read a sidecar-backed file | Returns object contents, not digest text |
| Modify one shared file | Other file remains unchanged |
| Delete one of two references | Object remains |
| Delete the last reference | Object is archived |
| Rename a hashed file | Virtual name and reference list agree |
| Replace an existing destination | Old destination reference is correctly removed |
| Encounter a malformed sidecar | Appropriate error; no false content |
| Encounter an orphan object | No incorrect virtual file is exposed |
| Fail a commit midway | Existing valid content is preserved where possible |

## 18. Unresolved design decisions

The following points must be decided explicitly during implementation rather than guessed.

1. **Hashing and commit timing:** Determine the correct WinFsp callback lifecycle for finalizing writes, particularly the roles of `Cleanup` and `Close`.
2. **Reference-file format:** The initial design uses one relative virtual path per line. Define escaping or another representation if future filename rules permit newline characters; the current ASCII rule excludes them.
3. **Archive naming:** Finalize whether the archive filename preserves the complete virtual path or only the final component, and how collisions are handled.
4. **Metadata policy:** Decide which timestamps and attributes should survive conversion between an ordinary file and a sidecar-backed file.
5. **Recovery:** Define how to detect and repair stale sidecars, missing objects, and inconsistent `.refs` files after an interrupted operation.
6. **Case matching:** Confirm that lookup and open-registry comparisons match the intended WinFsp/Windows behaviour, without altering stored spelling.
7. **Commit ordering:** Define the precise safe ordering for object publication, sidecar updates, and reference changes for create, modify, rename, and delete operations.

These decisions should be documented alongside the corresponding implementation and tests.

## 19. Core invariants

The implementation is correct only while these invariants hold:

1. Every valid sidecar refers to a valid content object.
2. Every hashed virtual file has exactly one corresponding virtual path reference in its object's `.refs` list.
3. A shared object is not modified in place when one virtual file changes.
4. An object is archived only when it has no remaining references.
5. Internal object-store and archive files never appear as ordinary virtual entries.
6. All visible names comply with the configured character rule.
7. Existing names retain their actual case.
8. No file has more than one active open handle.
9. A failed update does not silently destroy the last valid content.
10. The virtual directory tree remains consistent with the physical sidecars and reference metadata.

**Final implementation principle:** Start from the working WinFsp C++ passthrough example, make one small change at a time, and test after every stage. Do not reintroduce the previous implementation's complex behaviour all at once. The content-addressable storage layer must be built on top of a proven, working passthrough filesystem.
