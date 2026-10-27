#!/usr/bin/env bash
# Integration checks for omtfs. Run from MSYS2 Bash while the test volume is mounted.
# The script only creates/removes one uniquely named directory in the virtual volume.

set -u
shopt -s nullglob

MOUNT_ROOT="${MOUNT_ROOT:-x:/}"
BACKING_ROOT="${BACKING_ROOT:-c:/mydrive}"
KEEP_TEST_DATA="${KEEP_TEST_DATA:-0}"

MOUNT_ROOT="${MOUNT_ROOT%/}"
[[ "$MOUNT_ROOT" == *: ]] && MOUNT_ROOT+="/"
BACKING_ROOT="${BACKING_ROOT%/}"

RUN_ID="$(date +%Y%m%d-%H%M%S)-${RANDOM}-$$"
TEST_NAME="codex-test-${RUN_ID}"
TEST_ROOT="${MOUNT_ROOT%/}/${TEST_NAME}"
PHYSICAL_TEST_ROOT="${BACKING_ROOT}/${TEST_NAME}"
FAILURES=0
PASSES=0
ARCHIVE_MATCHES=()

pass()
{
    PASSES=$((PASSES + 1))
    printf '[PASS] %s\n' "$1"
}

fail()
{
    FAILURES=$((FAILURES + 1))
    printf '[FAIL] %s\n' "$1" >&2
}

assert_equal()
{
    local expected="$1" actual="$2" label="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

assert_exists()
{
    if [[ -e "$1" ]]; then pass "$2"; else fail "$2 (missing: $1)"; fi
}

assert_missing()
{
    if [[ ! -e "$1" ]]; then pass "$2"; else fail "$2 (unexpected path: $1)"; fi
}

hash_file()
{
    sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
}

hash_text()
{
    printf '%s' "$1" | sha256sum | awk '{print $1}'
}

object_path()
{
    local hash="$1"
    printf '%s/_sha256/%s/%s/%s' "$BACKING_ROOT" "${hash:0:2}" "${hash:0:4}" "$hash"
}

physical_path()
{
    local relative="$1"
    relative="${relative#"$TEST_NAME"/}"
    relative="${relative//\\//}"
    printf '%s/%s' "$PHYSICAL_TEST_ROOT" "$relative"
}

assert_bytes()
{
    local expected="$1" path="$2" label="$3"
    if printf '%s' "$expected" | cmp - "$path" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label (contents differ or file is unavailable: $path)"
    fi
}

assert_hash()
{
    local expected="$1" path="$2" label="$3" actual
    if [[ ! -f "$path" ]]; then fail "$label (missing file: $path)"; return; fi
    actual="$(hash_file "$path")" || { fail "$label (could not hash $path)"; return; }
    assert_equal "$expected" "$actual" "$label"
}

assert_sidecar()
{
    local relative="$1" expected_hash="$2" sidecar actual
    sidecar="$(physical_path "$relative").sha256"
    if [[ ! -f "$sidecar" ]]; then fail "sidecar exists for '$relative'"; return; fi
    actual="$(tr -d '\r\n' < "$sidecar")"
    assert_equal "$expected_hash" "$actual" "sidecar hash for '$relative'"
}

assert_refs()
{
    local refs="$1" label="$2"
    shift 2
    local expected actual
    if [[ ! -f "$refs" ]]; then fail "$label (missing: $refs)"; return; fi
    actual="$(tr -d '\r' < "$refs" | tr '[:upper:]' '[:lower:]' | LC_ALL=C sort)"
    # Windows virtual paths are case-insensitive; compare reference membership
    # without treating case-only spelling changes as missing references.
    expected="$(printf '%s\n' "$@" | tr '[:upper:]' '[:lower:]' | LC_ALL=C sort)"
    assert_equal "$expected" "$actual" "$label"

    local byte
    local bytes
    bytes="$(od -An -v -t u1 "$refs" 2>/dev/null)" || { fail "$label (could not inspect encoding)"; return; }
    for byte in $bytes; do
        if (( byte == 0 || byte > 127 )); then
            fail "$label is not plain 7-bit ASCII"
            return
        fi
    done
    pass "$label uses plain ASCII"
}

find_archive()
{
    local relative="$1" expected_hash="$2" candidate
    relative="${relative//\\//}"
    ARCHIVE_MATCHES=()
    for candidate in "$BACKING_ROOT"/_deleted/*/"$TEST_NAME"/"$relative"; do
        [[ -f "$candidate" ]] || continue
        [[ "$(hash_file "$candidate")" == "$expected_hash" ]] || continue
        ARCHIVE_MATCHES+=( "$candidate" )
    done
}

assert_archived()
{
    local relative="$1" content="$2" expected_hash="$3" reference="$4"
    local archived timestamp archive_relative
    find_archive "$relative" "$expected_hash"
    if (( ${#ARCHIVE_MATCHES[@]} != 1 )); then
        fail "one archived copy of '$relative' exists (found ${#ARCHIVE_MATCHES[@]})"
        return
    fi
    archived="${ARCHIVE_MATCHES[0]}"
    pass "'$relative' is archived with its virtual path"
    assert_bytes "$content" "$archived" "archived bytes for '$relative'"
    assert_hash "$expected_hash" "$archived" "archived SHA-256 for '$relative'"
    if [[ -f "${archived}.sha256" ]]; then
        local archived_sidecar
        archived_sidecar="$(tr -d '\r\n' < "${archived}.sha256")"
        assert_equal "$expected_hash" "$archived_sidecar" "archived sidecar hash for '$relative'"
    else
        fail "archived sidecar exists for '$relative'"
    fi
    # Archive metadata lives beside the archived object, not in the live object store.
    assert_refs "${archived}.refs" "archive provenance for '$relative'" "$reference"

    archive_relative="${archived#"$BACKING_ROOT"/_deleted/}"
    timestamp="${archive_relative%%/*}"
    if [[ "$timestamp" =~ ^[0-9]{6}_[0-9]{6}_[0-9]{9}_[0-9]{3}$ ]]; then
        pass "archive directory has the expected timestamp and collision suffix"
    else
        fail "archive directory name is malformed: $timestamp"
    fi
}

finish()
{
    local status=$?
    if [[ -d "$TEST_ROOT" ]]; then
        if (( FAILURES == 0 )) && [[ "$KEEP_TEST_DATA" != 1 ]]; then
            rm -rf -- "$TEST_ROOT" || printf '[WARN] Could not remove test directory: %s\n' "$TEST_ROOT" >&2
        else
            printf '[INFO] Keeping test directory for inspection: %s\n' "$TEST_ROOT"
        fi
    fi
    return "$status"
}
trap finish EXIT

printf 'Mount:   %s\nBacking: %s\nTest:    %s\n\n' "$MOUNT_ROOT" "$BACKING_ROOT" "$TEST_ROOT"

for command in sha256sum cmp od awk sort tr; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf '[FATAL] Required command is unavailable: %s\n' "$command" >&2
        exit 2
    fi
done

if ! ls "$MOUNT_ROOT" >/dev/null 2>&1; then
    printf '[FATAL] Cannot read mounted volume root: %s\n' "$MOUNT_ROOT" >&2
    exit 2
fi
if [[ ! -d "$BACKING_ROOT" ]]; then
    printf '[FATAL] Backing directory is unavailable: %s\n' "$BACKING_ROOT" >&2
    exit 2
fi
if [[ -e "$TEST_ROOT" || -e "$PHYSICAL_TEST_ROOT" ]]; then
    printf '[FATAL] Unique test path already exists; refusing to touch it: %s\n' "$TEST_ROOT" >&2
    exit 2
fi

if ! mkdir -- "$TEST_ROOT"; then
    printf '[FATAL] Could not create test directory on the mounted volume.\n' >&2
    exit 2
fi
pass "mounted volume accepts a new test directory"

# Root and filename behavior, including the newly allowed hyphen.
empty_listing="$(ls -A "$TEST_ROOT" 2>&1)"
assert_equal "" "$empty_listing" "new test directory lists as empty"

if mkdir -- "$TEST_ROOT/folder-with-hyphen" && touch -- "$TEST_ROOT/file-with-hyphen.txt"; then
    pass "hyphens are accepted in file and directory names"
else
    fail "hyphens are accepted in file and directory names"
fi
rm -- "$TEST_ROOT/file-with-hyphen.txt"
if touch -- "$TEST_ROOT/bad@name" >/dev/null 2>&1; then
    fail "invalid punctuation is rejected"
else
    pass "invalid punctuation is rejected"
fi
assert_missing "$TEST_ROOT/bad@name" "invalid name did not create a file"
assert_missing "$MOUNT_ROOT/_sha256" "reserved object-store directory is hidden"
assert_missing "$MOUNT_ROOT/_deleted" "reserved archive directory is hidden"

# Empty-file hashing and the standard SHA-256 empty-content vector.
EMPTY_HASH="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EMPTY_FILE="$TEST_ROOT/empty-file"
: > "$EMPTY_FILE"
assert_exists "$(physical_path "${TEST_NAME}/empty-file.sha256")" "empty file sidecar is created"
assert_sidecar "${TEST_NAME}/empty-file" "$EMPTY_HASH"
assert_exists "$(object_path "$EMPTY_HASH")" "empty-content object is present"
assert_bytes "" "$(object_path "$EMPTY_HASH")" "empty-content object has zero bytes"
rm -- "$EMPTY_FILE"
assert_missing "$(physical_path "${TEST_NAME}/empty-file.sha256")" "empty-file sidecar is removed on delete"

# Identical files must deduplicate; deleting one reference must retain the object.
SHARED_CONTENT="codex-shared-${RUN_ID}"
SHARED_HASH="$(hash_text "$SHARED_CONTENT")"
SHARED_OBJECT="$(object_path "$SHARED_HASH")"
SHARED_REFS="${SHARED_OBJECT}.refs"
FIRST="$TEST_ROOT/original-file.txt"
SECOND="$TEST_ROOT/folder-with-hyphen/copy-of-file.txt"
REF_FIRST="${TEST_NAME}\\original-file.txt"
REF_SECOND="${TEST_NAME}\\folder-with-hyphen\\copy-of-file.txt"
printf '%s' "$SHARED_CONTENT" > "$FIRST"
cp -- "$FIRST" "$SECOND"
assert_sidecar "${TEST_NAME}/original-file.txt" "$SHARED_HASH"
assert_sidecar "${TEST_NAME}/folder-with-hyphen/copy-of-file.txt" "$SHARED_HASH"
assert_hash "$SHARED_HASH" "$SHARED_OBJECT" "identical files share the expected object"
assert_refs "$SHARED_REFS" "deduplicated object has exactly two references" "$REF_FIRST" "$REF_SECOND"
rm -- "$FIRST"
assert_missing "$(physical_path "${TEST_NAME}/original-file.txt.sha256")" "first reference sidecar is removed"
assert_hash "$SHARED_HASH" "$SHARED_OBJECT" "object remains while the second reference exists"
assert_refs "$SHARED_REFS" "one reference remains after deleting the first file" "$REF_SECOND"
assert_bytes "$SHARED_CONTENT" "$SECOND" "second virtual file remains readable"
rm -- "$SECOND"
assert_missing "$SHARED_OBJECT" "last deletion removes object from live store"
assert_archived "folder-with-hyphen/copy-of-file.txt" "$SHARED_CONTENT" "$SHARED_HASH" "$REF_SECOND"
rmdir -- "$TEST_ROOT/folder-with-hyphen"

# Modifying one of two identical files must not change the other copy.
OLD_CONTENT="codex-old-${RUN_ID}"
NEW_CONTENT="codex-new-${RUN_ID}"
OLD_HASH="$(hash_text "$OLD_CONTENT")"
NEW_HASH="$(hash_text "$NEW_CONTENT")"
OLD_OBJECT="$(object_path "$OLD_HASH")"
NEW_OBJECT="$(object_path "$NEW_HASH")"
MUTABLE_ONE="$TEST_ROOT/mutable-one"
MUTABLE_TWO="$TEST_ROOT/mutable-two"
REF_MUTABLE_ONE="${TEST_NAME}\\mutable-one"
REF_MUTABLE_TWO="${TEST_NAME}\\mutable-two"
printf '%s' "$OLD_CONTENT" > "$MUTABLE_ONE"
cp -- "$MUTABLE_ONE" "$MUTABLE_TWO"
printf '%s' "$NEW_CONTENT" > "$MUTABLE_ONE"
assert_bytes "$NEW_CONTENT" "$MUTABLE_ONE" "modified copy contains new bytes"
assert_bytes "$OLD_CONTENT" "$MUTABLE_TWO" "unmodified copy retains old bytes"
assert_refs "${OLD_OBJECT}.refs" "old object references only the unchanged copy" "$REF_MUTABLE_TWO"
assert_refs "${NEW_OBJECT}.refs" "new object references only the modified copy" "$REF_MUTABLE_ONE"
rm -- "$MUTABLE_TWO"
assert_archived "mutable-two" "$OLD_CONTENT" "$OLD_HASH" "$REF_MUTABLE_TWO"
rm -- "$MUTABLE_ONE"
assert_archived "mutable-one" "$NEW_CONTENT" "$NEW_HASH" "$REF_MUTABLE_ONE"

# Renaming a hashed file must move its reference and sidecar to the new path.
RENAME_CONTENT="codex-rename-${RUN_ID}"
RENAME_HASH="$(hash_text "$RENAME_CONTENT")"
RENAME_OBJECT="$(object_path "$RENAME_HASH")"
RENAME_OLD="$TEST_ROOT/rename-old"
RENAME_NEW="$TEST_ROOT/rename-new"
REF_RENAME_NEW="${TEST_NAME}\\rename-new"
printf '%s' "$RENAME_CONTENT" > "$RENAME_OLD"
mv -- "$RENAME_OLD" "$RENAME_NEW"
assert_missing "$(physical_path "${TEST_NAME}/rename-old.sha256")" "old rename sidecar is removed"
assert_sidecar "${TEST_NAME}/rename-new" "$RENAME_HASH"
assert_refs "${RENAME_OBJECT}.refs" "rename updates the reference path" "$REF_RENAME_NEW"
rm -- "$RENAME_NEW"
assert_archived "rename-new" "$RENAME_CONTENT" "$RENAME_HASH" "$REF_RENAME_NEW"

# Copy over an existing destination: the destination should adopt source content,
# and the displaced content should be archived when it has no other references.
COPY_SOURCE_CONTENT="codex-copy-source-${RUN_ID}"
COPY_DEST_CONTENT="codex-copy-old-dest-${RUN_ID}"
COPY_SOURCE_HASH="$(hash_text "$COPY_SOURCE_CONTENT")"
COPY_DEST_HASH="$(hash_text "$COPY_DEST_CONTENT")"
COPY_SOURCE_OBJECT="$(object_path "$COPY_SOURCE_HASH")"
COPY_DEST_OBJECT="$(object_path "$COPY_DEST_HASH")"
COPY_SOURCE="$TEST_ROOT/copy-source"
COPY_DEST="$TEST_ROOT/copy-destination"
REF_COPY_SOURCE="${TEST_NAME}\\copy-source"
REF_COPY_DEST="${TEST_NAME}\\copy-destination"
printf '%s' "$COPY_SOURCE_CONTENT" > "$COPY_SOURCE"
printf '%s' "$COPY_DEST_CONTENT" > "$COPY_DEST"
cp -- "$COPY_SOURCE" "$COPY_DEST"
assert_bytes "$COPY_SOURCE_CONTENT" "$COPY_DEST" "copy over replaces destination contents"
assert_refs "${COPY_SOURCE_OBJECT}.refs" "source and overwritten destination share new object" "$REF_COPY_SOURCE" "$REF_COPY_DEST"
assert_archived "copy-destination" "$COPY_DEST_CONTENT" "$COPY_DEST_HASH" "$REF_COPY_DEST"
rm -- "$COPY_SOURCE"
assert_hash "$COPY_SOURCE_HASH" "$COPY_SOURCE_OBJECT" "copy object remains while destination refers to it"
assert_refs "${COPY_SOURCE_OBJECT}.refs" "one reference remains after deleting copy source" "$REF_COPY_DEST"
rm -- "$COPY_DEST"
assert_archived "copy-destination" "$COPY_SOURCE_CONTENT" "$COPY_SOURCE_HASH" "$REF_COPY_DEST"

# The test's own virtual directory should now contain no entries.
remaining="$(ls -A "$TEST_ROOT" 2>&1)"
assert_equal "" "$remaining" "all test files and child directories were removed"

printf '\nCompleted: %d passed, %d failed.\n' "$PASSES" "$FAILURES"
if (( FAILURES != 0 )); then
    printf 'Inspect the preserved test directory and debug log before retrying.\n' >&2
    exit 1
fi
printf 'The test directory will be removed; archive artifacts remain in _deleted.\n'
exit 0
