/**
 * @file passthrough-cpp.cpp
 *
 * @copyright 2015-2026 Bill Zissimopoulos
 */
/*
 * This file is part of WinFsp.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 3 as published by the Free Software
 * Foundation.
 *
 * Licensees holding a valid commercial license may use this software
 * in accordance with the commercial license agreement provided in
 * conjunction with the software.  The terms and conditions of any such
 * commercial license agreement shall govern, supersede, and render
 * ineffective any application of the GPLv3 license to this software,
 * notwithstanding of any reference thereto in the software or
 * associated repository.
 */

#include <winfsp/winfsp.hpp>
#include <strsafe.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <algorithm>
#include <cwctype>
#include <shlwapi.h>
#include <stdarg.h>

#define PROGNAME                        "passthrough-cpp"

#define ALLOCATION_UNIT                 4096
#define FULLPATH_SIZE                   (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#define info(format, ...)               Service::Log(EVENTLOG_INFORMATION_TYPE, format, __VA_ARGS__)
#define warn(...)                       LogWarning(__VA_ARGS__)
#define fail(...)                       LogFailure(__VA_ARGS__)

#define HandleFromFileDesc(FD)          ((PtfsFileDesc *)(FD))->Handle
#define SIDECAR_SUFFIX                  L".sha256"

using namespace Fsp;

static WCHAR DebugLogPath[FULLPATH_SIZE] = { 0 };

static VOID LogFailure(PCWSTR Format, ...)
{
    WCHAR Message[2048], Line[2080];
    va_list Args;
    va_start(Args, Format);
    HRESULT FormatResult = StringCchVPrintfW(Message, ARRAYSIZE(Message), Format, Args);
    va_end(Args);
    if (FAILED(FormatResult)) StringCchCopyW(Message, ARRAYSIZE(Message), L"error message formatting failed");
    Service::Log(EVENTLOG_ERROR_TYPE, L"%s", Message);

    if (L'\0' == DebugLogPath[0]) return;
    if (FAILED(StringCchPrintfW(Line, ARRAYSIZE(Line), L"ERROR: %s\r\n", Message))) return;
    int ByteCount = WideCharToMultiByte(CP_UTF8, 0, Line, -1, 0, 0, 0, 0);
    if (ByteCount <= 1) return;
    std::vector<CHAR> Utf8((size_t)ByteCount);
    if (0 == WideCharToMultiByte(CP_UTF8, 0, Line, -1, Utf8.data(), ByteCount, 0, 0)) return;
    HANDLE Log = CreateFileW(DebugLogPath, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == Log) return;
    DWORD Written;
    WriteFile(Log, Utf8.data(), (DWORD)ByteCount - 1, &Written, 0);
    CloseHandle(Log);
}

static VOID LogWarning(PCWSTR Format, ...)
{
    WCHAR Message[2048], Line[2080];
    va_list Args;
    va_start(Args, Format);
    HRESULT FormatResult = StringCchVPrintfW(Message, ARRAYSIZE(Message), Format, Args);
    va_end(Args);
    if (FAILED(FormatResult)) StringCchCopyW(Message, ARRAYSIZE(Message), L"warning message formatting failed");
    Service::Log(EVENTLOG_WARNING_TYPE, L"%s", Message);

    if (L'\0' == DebugLogPath[0] || FAILED(StringCchPrintfW(Line, ARRAYSIZE(Line), L"WARNING: %s\r\n", Message))) return;
    int ByteCount = WideCharToMultiByte(CP_UTF8, 0, Line, -1, 0, 0, 0, 0);
    if (ByteCount <= 1) return;
    std::vector<CHAR> Utf8((size_t)ByteCount);
    if (0 == WideCharToMultiByte(CP_UTF8, 0, Line, -1, Utf8.data(), ByteCount, 0, 0)) return;
    HANDLE Log = CreateFileW(DebugLogPath, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == Log) return;
    DWORD Written;
    WriteFile(Log, Utf8.data(), (DWORD)ByteCount - 1, &Written, 0);
    CloseHandle(Log);
}

struct PtfsFileDesc;

static NTSTATUS NtStatusFromWin32(DWORD Error)
{
    return FspNtStatusFromWin32(Error);
}

static NTSTATUS HashHandle(HANDLE Handle, PWSTR Hash)
{
    BCRYPT_ALG_HANDLE Algorithm = 0;
    BCRYPT_HASH_HANDLE HashHandle0 = 0;
    DWORD ObjectLength = 0, ResultLength = 0;
    LARGE_INTEGER Start = { 0 };
    BYTE Buffer[64 * 1024], Digest[32];
    std::vector<BYTE> Object;
    DWORD BytesRead;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (0 > BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_SHA256_ALGORITHM, 0, 0))
        return STATUS_UNSUCCESSFUL;
    if (0 > BCryptGetProperty(Algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ObjectLength,
                              sizeof ObjectLength, &ResultLength, 0))
        goto done;
    Object.resize(ObjectLength);
    if (0 > BCryptCreateHash(Algorithm, &HashHandle0, Object.data(), ObjectLength, 0, 0, 0))
        goto done;
    if (!SetFilePointerEx(Handle, Start, 0, FILE_BEGIN))
    {
        Status = FspNtStatusFromWin32(GetLastError());
        goto done;
    }
    for (;;)
    {
        if (!ReadFile(Handle, Buffer, sizeof Buffer, &BytesRead, 0))
        {
            Status = FspNtStatusFromWin32(GetLastError());
            goto done;
        }
        if (0 == BytesRead)
            break;
        if (0 > BCryptHashData(HashHandle0, Buffer, BytesRead, 0))
            goto done;
    }
    if (0 > BCryptFinishHash(HashHandle0, Digest, sizeof Digest, 0))
        goto done;
    for (ULONG I = 0; I < sizeof Digest; I++)
        StringCchPrintfW(Hash + I * 2, 3, L"%02x", Digest[I]);
    Status = STATUS_SUCCESS;

done:
    if (HashHandle0) BCryptDestroyHash(HashHandle0);
    if (Algorithm) BCryptCloseAlgorithmProvider(Algorithm, 0);
    return Status;
}

static BOOLEAN IsHexHash(PCWSTR Hash)
{
    if (0 == Hash || 64 != wcslen(Hash)) return FALSE;
    for (ULONG I = 0; I < 64; I++)
        if (!((L'0' <= Hash[I] && Hash[I] <= L'9') || (L'a' <= Hash[I] && Hash[I] <= L'f')))
            return FALSE;
    return TRUE;
}

static NTSTATUS ReadSidecar(PCWSTR SidecarPath, PWSTR Hash)
{
    DWORD Attributes = GetFileAttributesW(SidecarPath);
    if (INVALID_FILE_ATTRIBUTES != Attributes && (Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return STATUS_FILE_CORRUPT_ERROR;
    HANDLE Handle = CreateFileW(SidecarPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == Handle) return FspNtStatusFromWin32(GetLastError());
    CHAR Bytes[80] = { 0 };
    DWORD Count = 0;
    BOOL Ok = ReadFile(Handle, Bytes, sizeof Bytes - 1, &Count, 0);
    DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Handle);
    if (!Ok) return FspNtStatusFromWin32(Error);
    while (Count && ('\r' == Bytes[Count - 1] || '\n' == Bytes[Count - 1])) Count--;
    if (64 != Count) return STATUS_FILE_CORRUPT_ERROR;
    for (ULONG I = 0; I < 64; I++)
    {
        CHAR C = Bytes[I];
        if (!((C >= '0' && C <= '9') || (C >= 'a' && C <= 'f'))) return STATUS_FILE_CORRUPT_ERROR;
        Hash[I] = (WCHAR)C;
    }
    Hash[64] = L'\0';
    return STATUS_SUCCESS;
}

class Ptfs : public FileSystemBase
{
    public:
        Ptfs();
        ~Ptfs();
        NTSTATUS SetPath(PWSTR Path);

    protected:
        static NTSTATUS GetFileInfoInternal(HANDLE Handle, FileInfo * FileInfo);
        NTSTATUS Init(PVOID Host);
        NTSTATUS GetVolumeInfo(
            VolumeInfo * VolumeInfo);
        NTSTATUS GetSecurityByName(
            PWSTR FileName,
            PUINT32 PFileAttributes/* or ReparsePointIndex */,
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            SIZE_T * PSecurityDescriptorSize);
        NTSTATUS Create(
            PWSTR FileName,
            UINT32 CreateOptions,
            UINT32 GrantedAccess,
            UINT32 FileAttributes,
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            UINT64 AllocationSize,
            PVOID * PFileNode,
            PVOID * PFileDesc,
            OpenFileInfo * OpenFileInfo);
        NTSTATUS Open(
            PWSTR FileName,
            UINT32 CreateOptions,
            UINT32 GrantedAccess,
            PVOID * PFileNode,
            PVOID * PFileDesc,
            OpenFileInfo * OpenFileInfo);
        NTSTATUS Overwrite(
            PVOID FileNode,
            PVOID FileDesc,
            UINT32 FileAttributes,
            BOOLEAN ReplaceFileAttributes,
            UINT64 AllocationSize,
            FileInfo * FileInfo);
        VOID Cleanup(
            PVOID FileNode,
            PVOID FileDesc,
            PWSTR FileName,
            ULONG Flags);
        VOID Close(
            PVOID FileNode,
            PVOID FileDesc);
        NTSTATUS Read(
            PVOID FileNode,
            PVOID FileDesc,
            PVOID Buffer,
            UINT64 Offset,
            ULONG Length,
            PULONG PBytesTransferred);
        NTSTATUS Write(
            PVOID FileNode,
            PVOID FileDesc,
            PVOID Buffer,
            UINT64 Offset,
            ULONG Length,
            BOOLEAN WriteToEndOfFile,
            BOOLEAN ConstrainedIo,
            PULONG PBytesTransferred,
            FileInfo * FileInfo);
        NTSTATUS Flush(
            PVOID FileNode,
            PVOID FileDesc,
            FileInfo * FileInfo);
        NTSTATUS GetFileInfo(
            PVOID FileNode,
            PVOID FileDesc,
            FileInfo * FileInfo);
        NTSTATUS SetBasicInfo(
            PVOID FileNode,
            PVOID FileDesc,
            UINT32 FileAttributes,
            UINT64 CreationTime,
            UINT64 LastAccessTime,
            UINT64 LastWriteTime,
            UINT64 ChangeTime,
            FileInfo * FileInfo);
        NTSTATUS SetFileSize(
            PVOID FileNode,
            PVOID FileDesc,
            UINT64 NewSize,
            BOOLEAN SetAllocationSize,
            FileInfo * FileInfo);
        NTSTATUS CanDelete(
            PVOID FileNode,
            PVOID FileDesc,
            PWSTR FileName);
        NTSTATUS Rename(
            PVOID FileNode,
            PVOID FileDesc,
            PWSTR FileName,
            PWSTR NewFileName,
            BOOLEAN ReplaceIfExists);
        NTSTATUS GetSecurity(
            PVOID FileNode,
            PVOID FileDesc,
            PSECURITY_DESCRIPTOR SecurityDescriptor,
            SIZE_T * PSecurityDescriptorSize);
        NTSTATUS SetSecurity(
            PVOID FileNode,
            PVOID FileDesc,
            SECURITY_INFORMATION SecurityInformation,
            PSECURITY_DESCRIPTOR ModificationDescriptor);
        NTSTATUS ReadDirectory(
            PVOID FileNode,
            PVOID FileDesc,
            PWSTR Pattern,
            PWSTR Marker,
            PVOID Buffer,
            ULONG Length,
            PULONG PBytesTransferred);
        NTSTATUS ReadDirectoryEntry(
            PVOID FileNode,
            PVOID FileDesc,
            PWSTR Pattern,
            PWSTR Marker,
            PVOID * PContext,
            DirInfo * DirInfo);

    private:
        BOOLEAN BuildPath(PWSTR FileName, PWSTR FullPath);
        BOOLEAN IsValidVirtualPath(PWSTR FileName, BOOLEAN AllowRoot);
        NTSTATUS ResolveFilePath(PWSTR FileName, PWSTR PhysicalPath, PWSTR Hash, BOOLEAN * Hashed);
        NTSTATUS GetObjectPath(PCWSTR Hash, PWSTR ObjectPath, BOOLEAN CreateDirectories);
        NTSTATUS CommitFile(PtfsFileDesc * FileDesc);
        NTSTATUS RemoveReference(PCWSTR Hash, PCWSTR VirtualPath, BOOLEAN ArchiveIfEmpty = TRUE);
        NTSTATUS AddReference(PCWSTR Hash, PCWSTR VirtualPath);
        NTSTATUS ArchiveIfUnreferenced(PCWSTR Hash, PCWSTR LastReference);
        NTSTATUS ArchiveObject(PCWSTR Hash, PCWSTR LastReference);
        PWSTR _Path;
        UINT64 _CreationTime;
        std::mutex _StoreLock;
        std::set<std::wstring> _ActiveFiles;
};

struct PtfsFileDesc
{
    PtfsFileDesc() : Handle(INVALID_HANDLE_VALUE), DirBuffer(), Writable(FALSE), Hashed(FALSE), DeleteRequested(FALSE), Dirty(FALSE), Registered(FALSE), ArchivePending(FALSE)
    {
        VirtualPath[0] = PhysicalPath[0] = BackingPath[0] = TempPath[0] = OldHash[0] = ArchiveHash[0] = L'\0';
    }
    ~PtfsFileDesc()
    {
        CloseHandle(Handle);
        Ptfs::DeleteDirectoryBuffer(&DirBuffer);
    }
    HANDLE Handle;
    PVOID DirBuffer;
    WCHAR VirtualPath[FULLPATH_SIZE];
    WCHAR PhysicalPath[FULLPATH_SIZE];
    WCHAR BackingPath[FULLPATH_SIZE];
    WCHAR TempPath[FULLPATH_SIZE];
    WCHAR OldHash[65];
    WCHAR ArchiveHash[65];
    BOOLEAN Writable;
    BOOLEAN Hashed;
    BOOLEAN DeleteRequested;
    BOOLEAN Dirty;
    BOOLEAN Registered;
    BOOLEAN ArchivePending;
    std::mutex IoLock;
};

Ptfs::Ptfs() : FileSystemBase(), _Path()
{
}

Ptfs::~Ptfs()
{
    delete[] _Path;
}

NTSTATUS Ptfs::SetPath(PWSTR Path)
{
    WCHAR FullPath[FULLPATH_SIZE];
    ULONG Length;
    HANDLE Handle;
    FILETIME CreationTime;
    DWORD LastError;

    Handle = CreateFileW(
                 Path, FILE_READ_ATTRIBUTES, 0, 0,
                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (INVALID_HANDLE_VALUE == Handle)
        return NtStatusFromWin32(GetLastError());

    Length = GetFinalPathNameByHandleW(Handle, FullPath, FULLPATH_SIZE - 1, 0);
    if (0 == Length)
    {
        LastError = GetLastError();
        CloseHandle(Handle);
        return NtStatusFromWin32(LastError);
    }
    if (Length >= FULLPATH_SIZE - 1)
    {
        CloseHandle(Handle);
        return STATUS_OBJECT_NAME_INVALID;
    }
    FILE_ATTRIBUTE_TAG_INFO RootInfo;
    if (!GetFileInformationByHandleEx(Handle, FileAttributeTagInfo, &RootInfo, sizeof RootInfo))
    {
        LastError = GetLastError(); CloseHandle(Handle);
        return NtStatusFromWin32(LastError);
    }
    if (!(RootInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        CloseHandle(Handle);
        return STATUS_NOT_A_DIRECTORY;
    }
    if (L'\\' == FullPath[Length - 1])
        FullPath[--Length] = L'\0';

    if (!GetFileTime(Handle, &CreationTime, 0, 0))
    {
        LastError = GetLastError();
        CloseHandle(Handle);
        return NtStatusFromWin32(LastError);
    }

    CloseHandle(Handle);

    Length++;
    _Path = new WCHAR[Length];
    memcpy(_Path, FullPath, Length * sizeof(WCHAR));

    _CreationTime = ((PLARGE_INTEGER)&CreationTime)->QuadPart;

    return STATUS_SUCCESS;
}

BOOLEAN Ptfs::IsValidVirtualPath(PWSTR FileName, BOOLEAN AllowRoot)
{
    WCHAR Component[FULLPATH_SIZE];
    ULONG Count = 0;
    BOOLEAN First = TRUE;

    if (0 == FileName) return FALSE;
    while (L'\\' == *FileName || L'/' == *FileName) FileName++;
    if (L'\0' == *FileName) return AllowRoot;
    for (;; FileName++)
    {
        WCHAR C = *FileName;
        if (L'\0' == C || L'\\' == C || L'/' == C)
        {
            if (0 == Count || (1 == Count && L'.' == Component[0]) ||
                (2 == Count && L'.' == Component[0] && L'.' == Component[1]))
                return FALSE;
            Component[Count] = L'\0';
            for (ULONG I = 0; I < Count; I++)
            {
                WCHAR N = Component[I];
                if (!((L'A' <= N && N <= L'Z') || (L'a' <= N && N <= L'z') ||
                      (L'0' <= N && N <= L'9') || L'_' == N || L'-' == N || L'.' == N))
                    return FALSE;
            }
            if (First && (0 == _wcsicmp(Component, L"_sha256") || 0 == _wcsicmp(Component, L"_deleted")))
                return FALSE;
            if (0 == _wcsicmp(Component + (Count >= 7 ? Count - 7 : Count), SIDECAR_SUFFIX))
                return FALSE;
            if (L'\0' == C) return TRUE;
            First = FALSE;
            Count = 0;
        }
        else
        {
            if (L':' == C || Count + 1 >= ARRAYSIZE(Component)) return FALSE;
            Component[Count++] = C;
        }
    }
}

NTSTATUS Ptfs::GetObjectPath(PCWSTR Hash, PWSTR ObjectPath, BOOLEAN CreateDirectories)
{
    WCHAR Store[FULLPATH_SIZE], Dir2[FULLPATH_SIZE], Dir4[FULLPATH_SIZE];
    if (!IsHexHash(Hash)) return STATUS_FILE_CORRUPT_ERROR;
    if (0 != StringCbPrintfW(Store, sizeof Store, L"%s\\_sha256", _Path) ||
        0 != StringCbPrintfW(Dir2, sizeof Dir2, L"%s\\%.2s", Store, Hash) ||
        0 != StringCbPrintfW(Dir4, sizeof Dir4, L"%s\\%.4s", Dir2, Hash) ||
        0 != StringCbPrintfW(ObjectPath, FULLPATH_SIZE * sizeof(WCHAR), L"%s\\%s", Dir4, Hash))
        return STATUS_OBJECT_NAME_INVALID;
    const PWSTR Dirs[] = { Store, Dir2, Dir4 };
    for (ULONG I = 0; I < ARRAYSIZE(Dirs); I++)
    {
        DWORD Attributes = GetFileAttributesW(Dirs[I]);
        if (INVALID_FILE_ATTRIBUTES == Attributes && CreateDirectories)
        {
            if (!CreateDirectoryW(Dirs[I], 0) && ERROR_ALREADY_EXISTS != GetLastError())
                return NtStatusFromWin32(GetLastError());
            Attributes = GetFileAttributesW(Dirs[I]);
        }
        if (INVALID_FILE_ATTRIBUTES == Attributes)
            return CreateDirectories ? NtStatusFromWin32(GetLastError()) : STATUS_OBJECT_NAME_NOT_FOUND;
        if (!(Attributes & FILE_ATTRIBUTE_DIRECTORY) || (Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            return STATUS_NOT_A_DIRECTORY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::ResolveFilePath(PWSTR FileName, PWSTR PhysicalPath, PWSTR Hash, BOOLEAN * Hashed)
{
    WCHAR Sidecar[FULLPATH_SIZE], ObjectPath[FULLPATH_SIZE];
    DWORD Attributes;
    if (!IsValidVirtualPath(FileName, FALSE) || !BuildPath(FileName, PhysicalPath))
        return STATUS_OBJECT_NAME_INVALID;
    if (0 != StringCbPrintfW(Sidecar, sizeof Sidecar, L"%s%s", PhysicalPath, SIDECAR_SUFFIX))
        return STATUS_OBJECT_NAME_INVALID;
    Attributes = GetFileAttributesW(Sidecar);
    if (INVALID_FILE_ATTRIBUTES == Attributes)
    {
        *Hashed = FALSE;
        Hash[0] = L'\0';
        return STATUS_SUCCESS;
    }
    NTSTATUS Result = ReadSidecar(Sidecar, Hash);
    if (!NT_SUCCESS(Result)) return Result;
    Result = GetObjectPath(Hash, ObjectPath, FALSE);
    if (!NT_SUCCESS(Result)) return Result;
    Attributes = GetFileAttributesW(ObjectPath);
    if (INVALID_FILE_ATTRIBUTES == Attributes) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (Attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) return STATUS_FILE_CORRUPT_ERROR;
    if (0 != StringCchCopyW(PhysicalPath, FULLPATH_SIZE, ObjectPath)) return STATUS_OBJECT_NAME_INVALID;
    *Hashed = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS ReadReferences(PCWSTR RefsPath, std::vector<std::wstring> & Refs)
{
    DWORD Attributes = GetFileAttributesW(RefsPath);
    if (INVALID_FILE_ATTRIBUTES != Attributes && (Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return STATUS_FILE_CORRUPT_ERROR;
    HANDLE Handle = CreateFileW(RefsPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == Handle)
        return ERROR_FILE_NOT_FOUND == GetLastError() ? STATUS_SUCCESS : NtStatusFromWin32(GetLastError());
    LARGE_INTEGER Size;
    if (!GetFileSizeEx(Handle, &Size))
    {
        DWORD Error = GetLastError(); CloseHandle(Handle);
        return NtStatusFromWin32(Error);
    }
    if (Size.QuadPart > 16 * 1024 * 1024)
    {
        CloseHandle(Handle);
        return STATUS_FILE_CORRUPT_ERROR;
    }
    if (0 == Size.QuadPart)
    {
        CloseHandle(Handle);
        return STATUS_SUCCESS;
    }
    std::vector<CHAR> Data((size_t)Size.QuadPart);
    DWORD Read = 0;
    BOOL Ok = ReadFile(Handle, Data.data(), (DWORD)Size.QuadPart, &Read, 0);
    DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Handle);
    if (!Ok || Read != Size.QuadPart)
        return Ok ? STATUS_FILE_CORRUPT_ERROR : NtStatusFromWin32(Error);
    std::wstring All;
    BOOLEAN IsUtf16 = 0 == (Read % 2);
    size_t StartByte = 0;
    if (Read >= 2 && (BYTE)Data[0] == 0xff && (BYTE)Data[1] == 0xfe)
        StartByte = 2;
    else if (Read >= 2 && (BYTE)Data[0] == 0xfe && (BYTE)Data[1] == 0xff)
        return STATUS_FILE_CORRUPT_ERROR;
    else
    {
        IsUtf16 = IsUtf16 && 0 != memchr(Data.data(), 0, Read);
        if (IsUtf16)
            for (size_t I = 1; I < Read; I += 2)
                if (0 != Data[I]) return STATUS_FILE_CORRUPT_ERROR;
    }
    if (IsUtf16)
    {
        if ((Read - StartByte) % 2) return STATUS_FILE_CORRUPT_ERROR;
        for (size_t I = StartByte; I < Read; I += 2)
        {
            BYTE C = (BYTE)Data[I];
            if (C > 0x7f || 0 != Data[I + 1]) return STATUS_FILE_CORRUPT_ERROR;
            All.push_back((WCHAR)C);
        }
    }
    else
    {
        for (size_t I = 0; I < Read; I++)
        {
            BYTE C = (BYTE)Data[I];
            if (C > 0x7f) return STATUS_FILE_CORRUPT_ERROR;
            All.push_back((WCHAR)C);
        }
    }
    size_t Start = 0;
    while (Start < All.size())
    {
        size_t End = All.find(L'\n', Start);
        if (std::wstring::npos == End) End = All.size();
        size_t Stop = End;
        if (Stop > Start && L'\r' == All[Stop - 1]) Stop--;
        if (Stop > Start) Refs.push_back(All.substr(Start, Stop - Start));
        Start = End + 1;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN CreateTempSibling(PCWSTR Path, PCWSTR Prefix, PWSTR TempPath)
{
    WCHAR Parent[FULLPATH_SIZE];
    if (0 != StringCchCopyW(Parent, ARRAYSIZE(Parent), Path)) return FALSE;
    PWSTR Slash = wcsrchr(Parent, L'\\');
    if (0 == Slash) return FALSE;
    *Slash = L'\0';
    return 0 != GetTempFileNameW(Parent, Prefix, 0, TempPath);
}

static NTSTATUS WriteReferences(PCWSTR RefsPath, const std::vector<std::wstring> & Refs)
{
    WCHAR Temp[FULLPATH_SIZE];
    std::string Data;
    for (const auto & Ref : Refs)
    {
        for (WCHAR C : Ref)
        {
            if (C > 0x7f || L'\r' == C || L'\n' == C || L'\0' == C)
                return STATUS_OBJECT_NAME_INVALID;
            Data.push_back((CHAR)C);
        }
        Data += "\r\n";
    }
    if (!CreateTempSibling(RefsPath, L"~rf", Temp)) return NtStatusFromWin32(GetLastError());
    HANDLE Handle = CreateFileW(Temp, GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, 0);
    if (INVALID_HANDLE_VALUE == Handle) { DWORD E = GetLastError(); DeleteFileW(Temp); return NtStatusFromWin32(E); }
    DWORD Written = 0;
    BOOL Ok = Data.empty() ||
              (WriteFile(Handle, Data.data(), (DWORD)Data.size(), &Written, 0) && Written == Data.size());
    if (Ok) Ok = FlushFileBuffers(Handle);
    DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Handle);
    if (!Ok) { DeleteFileW(Temp); return NtStatusFromWin32(Error); }
    SetFileAttributesW(Temp, FILE_ATTRIBUTE_HIDDEN);
    if (!MoveFileExW(Temp, RefsPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    { Error = GetLastError(); DeleteFileW(Temp); return NtStatusFromWin32(Error); }
    return STATUS_SUCCESS;
}

static NTSTATUS WriteSidecar(PCWSTR SidecarPath, PCWSTR Hash)
{
    WCHAR Temp[FULLPATH_SIZE];
    if (!IsHexHash(Hash))
        return STATUS_OBJECT_NAME_INVALID;
    if (!CreateTempSibling(SidecarPath, L"~sc", Temp)) return NtStatusFromWin32(GetLastError());
    HANDLE Handle = CreateFileW(Temp, GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, 0);
    if (INVALID_HANDLE_VALUE == Handle) { DWORD E = GetLastError(); DeleteFileW(Temp); return NtStatusFromWin32(E); }
    CHAR Data[66];
    for (ULONG I = 0; I < 64; I++) Data[I] = (CHAR)Hash[I];
    Data[64] = '\r'; Data[65] = '\n';
    DWORD Written = 0;
    BOOL Ok = WriteFile(Handle, Data, sizeof Data, &Written, 0) && Written == sizeof Data && FlushFileBuffers(Handle);
    DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(Handle);
    if (!Ok) { DeleteFileW(Temp); return NtStatusFromWin32(Error); }
    SetFileAttributesW(Temp, FILE_ATTRIBUTE_HIDDEN);
    if (!MoveFileExW(Temp, SidecarPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    { Error = GetLastError(); DeleteFileW(Temp); return NtStatusFromWin32(Error); }
    return STATUS_SUCCESS;
}

static std::wstring NormalizeVirtualPath(PCWSTR Path)
{
    std::wstring Key = Path ? Path : L"";
    while (!Key.empty() && (L'\\' == Key[0] || L'/' == Key[0])) Key.erase(Key.begin());
    std::replace(Key.begin(), Key.end(), L'/', L'\\');
    std::transform(Key.begin(), Key.end(), Key.begin(), towlower);
    return Key;
}

static std::wstring DisplayVirtualPath(PCWSTR Path)
{
    std::wstring Value = Path ? Path : L"";
    while (!Value.empty() && (L'\\' == Value[0] || L'/' == Value[0])) Value.erase(Value.begin());
    std::replace(Value.begin(), Value.end(), L'/', L'\\');
    return Value;
}

static NTSTATUS RewriteReferencePrefix(PCWSTR Root, PCWSTR OldPrefix, PCWSTR NewPrefix)
{
    WCHAR Store[FULLPATH_SIZE], Search2[FULLPATH_SIZE];
    if (0 != StringCbPrintfW(Store, sizeof Store, L"%s\\_sha256", Root) ||
        0 != StringCbPrintfW(Search2, sizeof Search2, L"%s\\*", Store))
        return STATUS_OBJECT_NAME_INVALID;
    struct RefFileUpdate { std::wstring Path; std::vector<std::wstring> OldRefs, NewRefs; };
    std::vector<RefFileUpdate> Updates;
    WIN32_FIND_DATAW Data2;
    HANDLE Find2 = FindFirstFileW(Search2, &Data2);
    if (INVALID_HANDLE_VALUE == Find2)
        return ERROR_FILE_NOT_FOUND == GetLastError() || ERROR_PATH_NOT_FOUND == GetLastError() ? STATUS_SUCCESS : NtStatusFromWin32(GetLastError());
    do
    {
        if (!(Data2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || L'.' == Data2.cFileName[0]) continue;
        WCHAR Dir2[FULLPATH_SIZE], Search4[FULLPATH_SIZE];
        if (0 != StringCbPrintfW(Dir2, sizeof Dir2, L"%s\\%s", Store, Data2.cFileName) ||
            0 != StringCbPrintfW(Search4, sizeof Search4, L"%s\\*", Dir2)) continue;
        WIN32_FIND_DATAW Data4;
        HANDLE Find4 = FindFirstFileW(Search4, &Data4);
        if (INVALID_HANDLE_VALUE == Find4) continue;
        do
        {
            if (!(Data4.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || L'.' == Data4.cFileName[0]) continue;
            WCHAR Dir4[FULLPATH_SIZE], SearchRefs[FULLPATH_SIZE];
            if (0 != StringCbPrintfW(Dir4, sizeof Dir4, L"%s\\%s", Dir2, Data4.cFileName) ||
                0 != StringCbPrintfW(SearchRefs, sizeof SearchRefs, L"%s\\*.refs", Dir4)) continue;
            WIN32_FIND_DATAW RefData;
            HANDLE FindRefs = FindFirstFileW(SearchRefs, &RefData);
            if (INVALID_HANDLE_VALUE == FindRefs) continue;
            do
            {
                WCHAR Path[FULLPATH_SIZE];
                if (0 != StringCbPrintfW(Path, sizeof Path, L"%s\\%s", Dir4, RefData.cFileName)) continue;
                RefFileUpdate Update;
                Update.Path = Path;
                NTSTATUS Result = ReadReferences(Path, Update.OldRefs);
                if (!NT_SUCCESS(Result)) { FindClose(FindRefs); FindClose(Find4); FindClose(Find2); return Result; }
                Update.NewRefs = Update.OldRefs;
                BOOLEAN Changed = FALSE;
                for (auto & Ref : Update.NewRefs)
                {
                    size_t PrefixLength = wcslen(OldPrefix);
                    if (Ref.size() < PrefixLength) continue;
                    if (0 != CompareStringOrdinal(Ref.c_str(), (int)PrefixLength, OldPrefix, (int)PrefixLength, TRUE)) continue;
                    if (Ref.size() != PrefixLength && L'\\' != Ref[PrefixLength]) continue;
                    Ref = std::wstring(NewPrefix) + Ref.substr(PrefixLength);
                    Changed = TRUE;
                }
                if (Changed) Updates.push_back(Update);
            } while (FindNextFileW(FindRefs, &RefData));
            FindClose(FindRefs);
        } while (FindNextFileW(Find4, &Data4));
        FindClose(Find4);
    } while (FindNextFileW(Find2, &Data2));
    FindClose(Find2);
    size_t Completed = 0;
    for (; Completed < Updates.size(); Completed++)
    {
        NTSTATUS Result = WriteReferences(Updates[Completed].Path.c_str(), Updates[Completed].NewRefs);
        if (!NT_SUCCESS(Result))
        {
            while (Completed) { Completed--; WriteReferences(Updates[Completed].Path.c_str(), Updates[Completed].OldRefs); }
            return Result;
        }
    }
    return STATUS_SUCCESS;
}

static BOOLEAN IsWritableAccess(UINT32 Access)
{
    return 0 != (Access & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                           FILE_WRITE_EA | WRITE_DAC | WRITE_OWNER));
}

NTSTATUS Ptfs::AddReference(PCWSTR Hash, PCWSTR VirtualPath)
{
    WCHAR ObjectPath[FULLPATH_SIZE], RefsPath[FULLPATH_SIZE];
    NTSTATUS Result = GetObjectPath(Hash, ObjectPath, FALSE);
    if (!NT_SUCCESS(Result)) return Result;
    if (0 != StringCbPrintfW(RefsPath, sizeof RefsPath, L"%s.refs", ObjectPath)) return STATUS_OBJECT_NAME_INVALID;
    std::vector<std::wstring> Refs;
    Result = ReadReferences(RefsPath, Refs);
    if (!NT_SUCCESS(Result)) return Result;
    const std::wstring VirtualKey = NormalizeVirtualPath(VirtualPath);
    for (auto & Ref : Refs)
        if (NormalizeVirtualPath(Ref.c_str()) == VirtualKey)
        {
            if (0 == wcscmp(Ref.c_str(), VirtualPath)) return STATUS_SUCCESS;
            Ref = VirtualPath;
            return WriteReferences(RefsPath, Refs);
        }
    Refs.push_back(VirtualPath);
    return WriteReferences(RefsPath, Refs);
}

NTSTATUS Ptfs::RemoveReference(PCWSTR Hash, PCWSTR VirtualPath, BOOLEAN ArchiveIfEmpty)
{
    WCHAR ObjectPath[FULLPATH_SIZE], RefsPath[FULLPATH_SIZE];
    NTSTATUS Result = GetObjectPath(Hash, ObjectPath, FALSE);
    if (!NT_SUCCESS(Result)) return Result;
    if (0 != StringCbPrintfW(RefsPath, sizeof RefsPath, L"%s.refs", ObjectPath)) return STATUS_OBJECT_NAME_INVALID;
    std::vector<std::wstring> Refs, Kept;
    Result = ReadReferences(RefsPath, Refs);
    if (!NT_SUCCESS(Result)) return Result;
    const std::wstring VirtualKey = NormalizeVirtualPath(VirtualPath);
    for (const auto & Ref : Refs)
        if (NormalizeVirtualPath(Ref.c_str()) != VirtualKey) Kept.push_back(Ref);
    if (Kept.size() == Refs.size()) return STATUS_SUCCESS;
    if (!Kept.empty()) return WriteReferences(RefsPath, Kept);
    if (!ArchiveIfEmpty) return WriteReferences(RefsPath, Kept);
    /* Keep the final reference in the archived metadata as provenance. */
    Result = WriteReferences(RefsPath, Refs);
    if (!NT_SUCCESS(Result)) return Result;
    return ArchiveObject(Hash, VirtualPath);
}

NTSTATUS Ptfs::ArchiveIfUnreferenced(PCWSTR Hash, PCWSTR LastReference)
{
    WCHAR ObjectPath[FULLPATH_SIZE], RefsPath[FULLPATH_SIZE];
    NTSTATUS Result = GetObjectPath(Hash, ObjectPath, FALSE);
    if (!NT_SUCCESS(Result)) return Result;
    if (0 != StringCbPrintfW(RefsPath, sizeof RefsPath, L"%s.refs", ObjectPath)) return STATUS_OBJECT_NAME_INVALID;
    std::vector<std::wstring> Refs, Kept;
    Result = ReadReferences(RefsPath, Refs);
    if (!NT_SUCCESS(Result)) return Result;
    const std::wstring LastReferenceKey = NormalizeVirtualPath(LastReference);
    for (const auto & Ref : Refs)
        if (NormalizeVirtualPath(Ref.c_str()) != LastReferenceKey) Kept.push_back(Ref);
    if (!Kept.empty())
    {
        if (Kept.size() != Refs.size())
        {
            Result = WriteReferences(RefsPath, Kept);
            if (!NT_SUCCESS(Result)) return Result;
        }
        /* Keeping a shared object is normal when a virtual reference is removed. */
        return STATUS_SUCCESS;
    }
    /* The caller removed this reference's sidecar; keep it as archive provenance. */
    Kept.push_back(LastReference);
    Result = WriteReferences(RefsPath, Kept);
    if (!NT_SUCCESS(Result)) return Result;
    return ArchiveObject(Hash, LastReference);
}

NTSTATUS Ptfs::ArchiveObject(PCWSTR Hash, PCWSTR LastReference)
{
    WCHAR ObjectPath[FULLPATH_SIZE], RefsPath[FULLPATH_SIZE], DeletedPath[FULLPATH_SIZE], Dest[FULLPATH_SIZE];
    NTSTATUS Result = GetObjectPath(Hash, ObjectPath, FALSE);
    if (!NT_SUCCESS(Result)) return Result;
    DWORD ObjectAttrs = GetFileAttributesW(ObjectPath);
    if (INVALID_FILE_ATTRIBUTES == ObjectAttrs) return NtStatusFromWin32(GetLastError());
    if (ObjectAttrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) return STATUS_FILE_CORRUPT_ERROR;
    if (0 != StringCbPrintfW(RefsPath, sizeof RefsPath, L"%s.refs", ObjectPath) ||
        0 != StringCbPrintfW(DeletedPath, sizeof DeletedPath, L"%s\\_deleted", _Path)) return STATUS_OBJECT_NAME_INVALID;
    CreateDirectoryW(DeletedPath, 0);
    DWORD DeletedAttrs = GetFileAttributesW(DeletedPath);
    if (INVALID_FILE_ATTRIBUTES == DeletedAttrs || !(DeletedAttrs & FILE_ATTRIBUTE_DIRECTORY) ||
        (DeletedAttrs & FILE_ATTRIBUTE_REPARSE_POINT))
        return STATUS_NOT_A_DIRECTORY;
    SYSTEMTIME Now; FILETIME Precise;
    GetSystemTime(&Now);
    GetSystemTimePreciseAsFileTime(&Precise);
    UINT64 Ticks = ((UINT64)Precise.dwHighDateTime << 32) | Precise.dwLowDateTime;
    UINT64 Nanoseconds = (Ticks % 10000000) * 100;
    for (ULONG Suffix = 0; Suffix < 1000; Suffix++)
    {
        if (0 != StringCbPrintfW(Dest, sizeof Dest,
            L"%s\\%02u%02u%02u_%02u%02u%02u_%09I64u_%03u", DeletedPath,
            Now.wYear % 100, Now.wMonth, Now.wDay, Now.wHour, Now.wMinute, Now.wSecond, Nanoseconds, Suffix))
            return STATUS_OBJECT_NAME_INVALID;
        if (CreateDirectoryW(Dest, 0)) break;
        if (ERROR_ALREADY_EXISTS != GetLastError()) return NtStatusFromWin32(GetLastError());
        if (999 == Suffix) return STATUS_OBJECT_NAME_COLLISION;
    }
    WCHAR DestObject[FULLPATH_SIZE], DestRefs[FULLPATH_SIZE], DestHashSidecar[FULLPATH_SIZE], RelativePath[FULLPATH_SIZE];
    PCWSTR RelativeReference = LastReference;
    while (L'\\' == *RelativeReference || L'/' == *RelativeReference) RelativeReference++;
    if (L'\0' == *RelativeReference || !IsValidVirtualPath((PWSTR)LastReference, FALSE))
    { RemoveDirectoryW(Dest); return STATUS_OBJECT_NAME_INVALID; }
    if (FAILED(StringCchCopyW(RelativePath, ARRAYSIZE(RelativePath), RelativeReference)))
    { RemoveDirectoryW(Dest); return STATUS_OBJECT_NAME_INVALID; }
    for (PWSTR P = RelativePath; L'\0' != *P; P++) if (L'/' == *P) *P = L'\\';
    if (0 != StringCbPrintfW(DestObject, sizeof DestObject, L"%s\\%s", Dest, RelativePath) ||
        0 != StringCbPrintfW(DestRefs, sizeof DestRefs, L"%s.refs", DestObject) ||
        0 != StringCbPrintfW(DestHashSidecar, sizeof DestHashSidecar, L"%s.sha256", DestObject)) return STATUS_OBJECT_NAME_INVALID;
    /* Preserve the virtual path inside the timestamped archive directory. */
    WCHAR Parent[FULLPATH_SIZE];
    if (0 != StringCchCopyW(Parent, ARRAYSIZE(Parent), DestObject)) return STATUS_OBJECT_NAME_INVALID;
    PWSTR FinalSlash = wcsrchr(Parent, L'\\');
    if (0 == FinalSlash) return STATUS_OBJECT_NAME_INVALID;
    *FinalSlash = L'\0';
    size_t BaseLength = wcslen(Dest);
    for (PWSTR P = Parent + BaseLength + 1; L'\0' != *P; P++)
    {
        if (L'\\' != *P) continue;
        WCHAR Saved = *P;
        *P = L'\0';
        if (!CreateDirectoryW(Parent, 0))
        {
            DWORD Error = GetLastError();
            DWORD Attr = GetFileAttributesW(Parent);
            if (ERROR_ALREADY_EXISTS != Error || INVALID_FILE_ATTRIBUTES == Attr ||
                !(Attr & FILE_ATTRIBUTE_DIRECTORY) || (Attr & FILE_ATTRIBUTE_REPARSE_POINT))
            { RemoveDirectoryW(Dest); return NtStatusFromWin32(Error); }
        }
        *P = Saved;
    }
    /* The loop creates intermediate folders at separators; create the leaf parent too. */
    if (!CreateDirectoryW(Parent, 0))
    {
        DWORD Error = GetLastError();
        DWORD Attr = GetFileAttributesW(Parent);
        if (ERROR_ALREADY_EXISTS != Error || INVALID_FILE_ATTRIBUTES == Attr ||
            !(Attr & FILE_ATTRIBUTE_DIRECTORY) || (Attr & FILE_ATTRIBUTE_REPARSE_POINT))
            return NtStatusFromWin32(Error);
    }
    if (!MoveFileExW(ObjectPath, DestObject, MOVEFILE_WRITE_THROUGH))
    { DWORD E = GetLastError(); RemoveDirectoryW(Dest); return NtStatusFromWin32(E); }
    if (INVALID_FILE_ATTRIBUTES != GetFileAttributesW(RefsPath) &&
        !MoveFileExW(RefsPath, DestRefs, MOVEFILE_WRITE_THROUGH))
    { DWORD E = GetLastError(); MoveFileExW(DestObject, ObjectPath, MOVEFILE_WRITE_THROUGH); RemoveDirectoryW(Dest); return NtStatusFromWin32(E); }
    Result = WriteSidecar(DestHashSidecar, Hash);
    if (!NT_SUCCESS(Result))
    {
        MoveFileExW(DestRefs, RefsPath, MOVEFILE_WRITE_THROUGH);
        MoveFileExW(DestObject, ObjectPath, MOVEFILE_WRITE_THROUGH);
        RemoveDirectoryW(Dest);
        return Result;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::CommitFile(PtfsFileDesc * FileDesc)
{
    std::lock_guard<std::mutex> IoLock(FileDesc->IoLock);
    if (!FileDesc->Writable || !FileDesc->Dirty) return STATUS_SUCCESS;
    std::lock_guard<std::mutex> Lock(_StoreLock);
    WCHAR Hash[65], ObjectPath[FULLPATH_SIZE], Sidecar[FULLPATH_SIZE], TempObject[FULLPATH_SIZE];
    HANDLE HashingHandle = CreateFileW(FileDesc->BackingPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if (INVALID_HANDLE_VALUE == HashingHandle)
    {
        DWORD Error = GetLastError();
        fail(L"cannot open staged content for SHA-256 (0x%08x)", Error);
        return NtStatusFromWin32(Error);
    }
    NTSTATUS Result = HashHandle(HashingHandle, Hash);
    CloseHandle(HashingHandle);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot calculate SHA-256 (0x%08x)", Result);
        return Result;
    }
    Result = GetObjectPath(Hash, ObjectPath, TRUE);
    if (!NT_SUCCESS(Result)) return Result;
    DWORD Attributes = GetFileAttributesW(ObjectPath);
    /* This implementation stores filesystem metadata on the content object.
     * Updating metadata without changing bytes therefore updates the shared object. */
    BOOLEAN ReplaceSharedMetadata = INVALID_FILE_ATTRIBUTES != Attributes && FileDesc->Hashed &&
                                    0 == _wcsicmp(FileDesc->OldHash, Hash);
    if (INVALID_FILE_ATTRIBUTES == Attributes || ReplaceSharedMetadata)
    {
        WCHAR ObjectDir[FULLPATH_SIZE];
        if (0 != StringCchCopyW(ObjectDir, ARRAYSIZE(ObjectDir), ObjectPath)) return STATUS_OBJECT_NAME_INVALID;
        PWSTR Slash = wcsrchr(ObjectDir, L'\\');
        if (0 == Slash) return STATUS_OBJECT_NAME_INVALID;
        *Slash = L'\0';
        if (!GetTempFileNameW(ObjectDir, L"obj", 0, TempObject))
            return NtStatusFromWin32(GetLastError());
        DeleteFileW(TempObject);
        if (!CopyFileW(FileDesc->BackingPath, TempObject, TRUE))
        {
            DWORD Error = GetLastError(); DeleteFileW(TempObject);
            return NtStatusFromWin32(Error);
        }
        DWORD MoveFlags = MOVEFILE_WRITE_THROUGH | (ReplaceSharedMetadata ? MOVEFILE_REPLACE_EXISTING : 0);
        if (!MoveFileExW(TempObject, ObjectPath, MoveFlags))
        {
            DWORD Error = GetLastError(); DeleteFileW(TempObject);
            if (ReplaceSharedMetadata || (ERROR_ALREADY_EXISTS != Error && ERROR_FILE_EXISTS != Error))
                return NtStatusFromWin32(Error);
        }
    }
    else if (Attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        return STATUS_FILE_CORRUPT_ERROR;

    if (0 != StringCbPrintfW(Sidecar, sizeof Sidecar, L"%s%s", FileDesc->PhysicalPath, SIDECAR_SUFFIX))
        return STATUS_OBJECT_NAME_INVALID;
    Result = AddReference(Hash, FileDesc->VirtualPath);
    if (!NT_SUCCESS(Result)) return Result;
    Result = WriteSidecar(Sidecar, Hash);
    if (!NT_SUCCESS(Result))
    {
        if (0 != _wcsicmp(FileDesc->OldHash, Hash) && IsHexHash(Hash))
            RemoveReference(Hash, FileDesc->VirtualPath);
        return Result;
    }

    if (FileDesc->Hashed && 0 != _wcsicmp(FileDesc->OldHash, Hash))
    {
        Result = RemoveReference(FileDesc->OldHash, FileDesc->VirtualPath);
        if (!NT_SUCCESS(Result))
        {
            WriteSidecar(Sidecar, FileDesc->OldHash);
            RemoveReference(Hash, FileDesc->VirtualPath);
            return Result;
        }
    }
    StringCchCopyW(FileDesc->OldHash, ARRAYSIZE(FileDesc->OldHash), Hash);
    FileDesc->Hashed = TRUE;
    FileDesc->Dirty = FALSE;
    return STATUS_SUCCESS;
}

BOOLEAN Ptfs::BuildPath(PWSTR FileName, PWSTR FullPath)
{
    PWSTR Component;
    WCHAR Probe[FULLPATH_SIZE];

    if (0 == FileName || 0 == _Path)
        return FALSE;

    /* WinFsp names are rooted at the virtual volume. Do not let a name
     * address another drive or walk above the configured backing directory. */
    while (L'\\' == *FileName || L'/' == *FileName)
        FileName++;
    for (Component = FileName; L'\0' != *Component; )
    {
        PWSTR End = Component;
        while (L'\0' != *End && L'\\' != *End && L'/' != *End)
        {
            if (L':' == *End)
                return FALSE;
            End++;
        }
        if (End - Component == 2 && L'.' == Component[0] && L'.' == Component[1])
            return FALSE;
        Component = L'\0' == *End ? End : End + 1;
    }

    if (0 != StringCbPrintfW(FullPath, FULLPATH_SIZE * sizeof(WCHAR), L"%s\\%s", _Path, FileName))
        return FALSE;
    for (PWSTR P = FullPath; L'\0' != *P; P++)
        if (L'/' == *P) *P = L'\\';

    /* Refuse reparse-point components so links and junctions cannot escape
     * the configured backing directory. */
    if (0 != StringCchCopyW(Probe, ARRAYSIZE(Probe), _Path)) return FALSE;
    SIZE_T ProbeLength = wcslen(Probe), RootLength = ProbeLength;
    PCWSTR Relative = FullPath + RootLength;
    while (L'\\' == *Relative) Relative++;
    if (ProbeLength + 1 >= ARRAYSIZE(Probe)) return FALSE;
    Probe[ProbeLength++] = L'\\';
    Probe[ProbeLength] = L'\0';
    for (PCWSTR P = Relative; ; P++)
    {
        if (L'\\' == *P || L'\0' == *P)
        {
            Probe[ProbeLength] = L'\0';
            HANDLE Handle = CreateFileW(Probe, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0);
            if (INVALID_HANDLE_VALUE == Handle)
            {
                DWORD Error = GetLastError();
                if (ERROR_FILE_NOT_FOUND == Error || ERROR_PATH_NOT_FOUND == Error) return TRUE;
                return FALSE;
            }
            FILE_ATTRIBUTE_TAG_INFO TagInfo;
            BOOL Ok = GetFileInformationByHandleEx(Handle, FileAttributeTagInfo, &TagInfo, sizeof TagInfo);
            CloseHandle(Handle);
            if (!Ok || (TagInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return FALSE;
            if (L'\0' == *P) break;
            if (ProbeLength + 1 >= ARRAYSIZE(Probe)) return FALSE;
            Probe[ProbeLength++] = L'\\';
            Probe[ProbeLength] = L'\0';
        }
        else
        {
            if (ProbeLength + 1 >= ARRAYSIZE(Probe)) return FALSE;
            Probe[ProbeLength++] = *P;
        }
    }
    return TRUE;
}

NTSTATUS Ptfs::GetFileInfoInternal(HANDLE Handle, FileInfo * FileInfo)
{
    BY_HANDLE_FILE_INFORMATION ByHandleFileInfo;

    if (!GetFileInformationByHandle(Handle, &ByHandleFileInfo))
        return NtStatusFromWin32(GetLastError());

    FileInfo->FileAttributes = ByHandleFileInfo.dwFileAttributes;
    FileInfo->ReparseTag = 0;
    FileInfo->FileSize =
        ((UINT64)ByHandleFileInfo.nFileSizeHigh << 32) | (UINT64)ByHandleFileInfo.nFileSizeLow;
    FileInfo->AllocationSize = (FileInfo->FileSize + ALLOCATION_UNIT - 1)
                               / ALLOCATION_UNIT * ALLOCATION_UNIT;
    FileInfo->CreationTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftCreationTime)->QuadPart;
    FileInfo->LastAccessTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastAccessTime)->QuadPart;
    FileInfo->LastWriteTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastWriteTime)->QuadPart;
    FileInfo->ChangeTime = FileInfo->LastWriteTime;
    FileInfo->IndexNumber = 0;
    FileInfo->HardLinks = 0;

    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::Init(PVOID Host0)
{
    FileSystemHost * Host = (FileSystemHost *)Host0;
    Host->SetSectorSize(ALLOCATION_UNIT);
    Host->SetSectorsPerAllocationUnit(1);
    Host->SetFileInfoTimeout(1000);
    Host->SetCaseSensitiveSearch(FALSE);
    Host->SetCasePreservedNames(TRUE);
    Host->SetUnicodeOnDisk(TRUE);
    Host->SetPersistentAcls(TRUE);
    Host->SetPostCleanupWhenModifiedOnly(TRUE);
    Host->SetPassQueryDirectoryPattern(TRUE);
    Host->SetVolumeCreationTime(_CreationTime);
    Host->SetVolumeSerialNumber(0);
    Host->SetFlushAndPurgeOnCleanup(TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::GetVolumeInfo(
    VolumeInfo * VolumeInfo)
{
    WCHAR Root[MAX_PATH];
    ULARGE_INTEGER TotalSize, FreeSize;

    if (!GetVolumePathNameW(_Path, Root, MAX_PATH))
        return NtStatusFromWin32(GetLastError());

    if (!GetDiskFreeSpaceExW(Root, 0, &TotalSize, &FreeSize))
        return NtStatusFromWin32(GetLastError());

    VolumeInfo->TotalSize = TotalSize.QuadPart;
    VolumeInfo->FreeSize = FreeSize.QuadPart;

    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::GetSecurityByName(
    PWSTR FileName,
    PUINT32 PFileAttributes/* or ReparsePointIndex */,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T * PSecurityDescriptorSize)
{
    WCHAR FullPath[FULLPATH_SIZE], Hash[65];
    HANDLE Handle;
    FILE_ATTRIBUTE_TAG_INFO AttributeTagInfo;
    DWORD SecurityDescriptorSizeNeeded = 0;
    NTSTATUS Result;

    BOOLEAN Hashed = FALSE;
    if (L'\0' == *FileName || (L'\\' == *FileName && L'\0' == FileName[1]))
    {
        if (!IsValidVirtualPath(FileName, TRUE) || !BuildPath(FileName, FullPath))
        {
            warn(L"cannot resolve backing root for virtual root request");
            return STATUS_OBJECT_NAME_INVALID;
        }
    }
    else
    {
        Result = ResolveFilePath(FileName, FullPath, Hash, &Hashed);
        if (!NT_SUCCESS(Result)) return Result;
    }

    Handle = CreateFileW(FullPath,
                         FILE_READ_ATTRIBUTES | READ_CONTROL, 0, 0,
                         OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (INVALID_HANDLE_VALUE == Handle)
    {
        Result = NtStatusFromWin32(GetLastError());
        if (L'\0' == *FileName || (L'\\' == *FileName && L'\0' == FileName[1]))
            warn(L"cannot open backing root for virtual root request (0x%08x)", Result);
        goto exit;
    }

    if (0 != PFileAttributes)
    {
        if (!GetFileInformationByHandleEx(Handle,
                                          FileAttributeTagInfo, &AttributeTagInfo, sizeof AttributeTagInfo))
        {
            Result = NtStatusFromWin32(GetLastError());
            goto exit;
        }

        *PFileAttributes = AttributeTagInfo.FileAttributes;
    }

    if (0 != PSecurityDescriptorSize)
    {
        if (!GetKernelObjectSecurity(Handle,
                                     OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                     SecurityDescriptor, (DWORD)*PSecurityDescriptorSize, &SecurityDescriptorSizeNeeded))
        {
            *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
            Result = NtStatusFromWin32(GetLastError());
            goto exit;
        }

        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
    }

    Result = STATUS_SUCCESS;

exit:
    if (INVALID_HANDLE_VALUE != Handle)
        CloseHandle(Handle);

    return Result;
}

NTSTATUS Ptfs::Create(
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    UINT32 FileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    UINT64 AllocationSize,
    PVOID * PFileNode,
    PVOID * PFileDesc,
    OpenFileInfo * OpenFileInfo)
{
    WCHAR FullPath[FULLPATH_SIZE];
    SECURITY_ATTRIBUTES SecurityAttributes;
    ULONG CreateFlags;
    PtfsFileDesc * FileDesc;

    BOOLEAN IsDirectory = 0 != (CreateOptions & FILE_DIRECTORY_FILE);
    if (!IsValidVirtualPath(FileName, FALSE) || !BuildPath(FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    FileDesc = new PtfsFileDesc;
    std::wstring Key = NormalizeVirtualPath(FileName);
    StringCchCopyW(FileDesc->VirtualPath, ARRAYSIZE(FileDesc->VirtualPath), DisplayVirtualPath(FileName).c_str());
    if (!IsDirectory)
    {
        std::lock_guard<std::mutex> Lock(_StoreLock);
        if (!_ActiveFiles.insert(Key).second) { delete FileDesc; return STATUS_SHARING_VIOLATION; }
        FileDesc->Registered = TRUE;
    }
    StringCchCopyW(FileDesc->PhysicalPath, ARRAYSIZE(FileDesc->PhysicalPath), FullPath);
    StringCchCopyW(FileDesc->BackingPath, ARRAYSIZE(FileDesc->BackingPath), FullPath);
    FileDesc->Writable = !IsDirectory;
    FileDesc->Dirty = !IsDirectory;

    SecurityAttributes.nLength = sizeof SecurityAttributes;
    SecurityAttributes.lpSecurityDescriptor = SecurityDescriptor;
    SecurityAttributes.bInheritHandle = FALSE;

    CreateFlags = FILE_FLAG_BACKUP_SEMANTICS;
    if (CreateOptions & FILE_DIRECTORY_FILE)
    {
        /*
         * It is not widely known but CreateFileW can be used to create directories!
         * It requires the specification of both FILE_FLAG_BACKUP_SEMANTICS and
         * FILE_FLAG_POSIX_SEMANTICS. It also requires that FileAttributes has
         * FILE_ATTRIBUTE_DIRECTORY set.
         */
        CreateFlags |= FILE_FLAG_POSIX_SEMANTICS;
        FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else
        FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;

    if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    FileDesc->Handle = CreateFileW(FullPath,
                                   GrantedAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &SecurityAttributes,
                                   CREATE_NEW, CreateFlags | FileAttributes, 0);
    if (INVALID_HANDLE_VALUE == FileDesc->Handle)
    {
        if (FileDesc->Registered) { std::lock_guard<std::mutex> Lock(_StoreLock); _ActiveFiles.erase(Key); }
        delete FileDesc;
        return NtStatusFromWin32(GetLastError());
    }

    NTSTATUS Result = GetFileInfoInternal(FileDesc->Handle, &OpenFileInfo->FileInfo);
    if (!NT_SUCCESS(Result))
    {
        if (FileDesc->Registered) { std::lock_guard<std::mutex> Lock(_StoreLock); _ActiveFiles.erase(Key); }
        delete FileDesc; DeleteFileW(FullPath); RemoveDirectoryW(FullPath); return Result;
    }
    *PFileDesc = FileDesc;
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::Open(
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    PVOID * PFileNode,
    PVOID * PFileDesc,
    OpenFileInfo * OpenFileInfo)
{
    WCHAR FullPath[FULLPATH_SIZE], LogicalPath[FULLPATH_SIZE], Hash[65], Store[FULLPATH_SIZE];
    ULONG CreateFlags;
    PtfsFileDesc * FileDesc;
    BOOLEAN Hashed = FALSE;
    BOOLEAN IsRoot = L'\0' == *FileName || (L'\\' == *FileName && L'\0' == FileName[1]);
    if ((!IsRoot && !IsValidVirtualPath(FileName, FALSE)) || !BuildPath(FileName, LogicalPath))
        return STATUS_OBJECT_NAME_INVALID;
    NTSTATUS Result;
    if (IsRoot)
    {
        StringCchCopyW(FullPath, ARRAYSIZE(FullPath), LogicalPath);
        Hash[0] = L'\0';
    }
    else
        Result = ResolveFilePath(FileName, FullPath, Hash, &Hashed);
    if (!IsRoot && !NT_SUCCESS(Result))
        return Result;

    DWORD Attributes = GetFileAttributesW(FullPath);
    if (INVALID_FILE_ATTRIBUTES == Attributes) return NtStatusFromWin32(GetLastError());
    BOOLEAN IsDirectory = 0 != (Attributes & FILE_ATTRIBUTE_DIRECTORY);
    std::wstring Key = NormalizeVirtualPath(FileName);

    FileDesc = new PtfsFileDesc;
    StringCchCopyW(FileDesc->VirtualPath, ARRAYSIZE(FileDesc->VirtualPath), DisplayVirtualPath(FileName).c_str());
    if (!IsDirectory)
    {
        std::lock_guard<std::mutex> Lock(_StoreLock);
        if (!_ActiveFiles.insert(Key).second) { delete FileDesc; return STATUS_SHARING_VIOLATION; }
        FileDesc->Registered = TRUE;
    }
    StringCchCopyW(FileDesc->PhysicalPath, ARRAYSIZE(FileDesc->PhysicalPath), LogicalPath);
    StringCchCopyW(FileDesc->BackingPath, ARRAYSIZE(FileDesc->BackingPath), FullPath);
    FileDesc->Writable = !IsDirectory && IsWritableAccess(GrantedAccess);
    FileDesc->Hashed = Hashed;
    if (Hashed) StringCchCopyW(FileDesc->OldHash, ARRAYSIZE(FileDesc->OldHash), Hash);

    if (Hashed && FileDesc->Writable)
    {
        StringCchCopyW(Store, ARRAYSIZE(Store), FullPath);
        PWSTR Slash = wcsrchr(Store, L'\\');
        if (0 == Slash) Result = STATUS_OBJECT_NAME_INVALID;
        else
        {
            *Slash = L'\0';
            if (!GetTempFileNameW(Store, L"wrk", 0, FileDesc->TempPath)) Result = NtStatusFromWin32(GetLastError());
            else
            {
                DeleteFileW(FileDesc->TempPath);
                if (!CopyFileW(FullPath, FileDesc->TempPath, TRUE)) Result = NtStatusFromWin32(GetLastError());
                else StringCchCopyW(FileDesc->BackingPath, ARRAYSIZE(FileDesc->BackingPath), FileDesc->TempPath);
            }
        }
        if (!NT_SUCCESS(Result))
        {
            if (FileDesc->Registered) { std::lock_guard<std::mutex> Lock(_StoreLock); _ActiveFiles.erase(Key); }
            if (L'\0' != FileDesc->TempPath[0]) DeleteFileW(FileDesc->TempPath);
            delete FileDesc; return Result;
        }
    }

    CreateFlags = FILE_FLAG_BACKUP_SEMANTICS;
    /* Writable hashed files must be edited through the private working copy.
     * Opening FullPath here would write directly into the shared object and
     * corrupt every virtual file that references it. */
    FileDesc->Handle = CreateFileW(FileDesc->BackingPath,
                                   GrantedAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0,
                                   OPEN_EXISTING, CreateFlags, 0);
    if (INVALID_HANDLE_VALUE == FileDesc->Handle)
    {
        DWORD Error = GetLastError();
        if (FileDesc->Registered) { std::lock_guard<std::mutex> Lock(_StoreLock); _ActiveFiles.erase(Key); }
        if (L'\0' != FileDesc->TempPath[0]) DeleteFileW(FileDesc->TempPath);
        delete FileDesc;
        return NtStatusFromWin32(Error);
    }

    Result = GetFileInfoInternal(FileDesc->Handle, &OpenFileInfo->FileInfo);
    if (!NT_SUCCESS(Result))
    {
        if (FileDesc->Registered) { std::lock_guard<std::mutex> Lock(_StoreLock); _ActiveFiles.erase(Key); }
        delete FileDesc; return Result;
    }
    *PFileDesc = FileDesc;
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::Overwrite(
    PVOID FileNode,
    PVOID FileDesc,
    UINT32 FileAttributes,
    BOOLEAN ReplaceFileAttributes,
    UINT64 AllocationSize,
    FileInfo * FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;
    std::lock_guard<std::mutex> IoLock(Desc->IoLock);
    FILE_BASIC_INFO BasicInfo = { 0 };
    FILE_ALLOCATION_INFO AllocationInfo = { 0 };
    FILE_ATTRIBUTE_TAG_INFO AttributeTagInfo;

    if (ReplaceFileAttributes)
    {
        if (0 == FileAttributes)
            FileAttributes = FILE_ATTRIBUTE_NORMAL;

        BasicInfo.FileAttributes = FileAttributes;
        if (!SetFileInformationByHandle(Handle,
                                        FileBasicInfo, &BasicInfo, sizeof BasicInfo))
            return NtStatusFromWin32(GetLastError());
    }
    else if (0 != FileAttributes)
    {
        if (!GetFileInformationByHandleEx(Handle,
                                          FileAttributeTagInfo, &AttributeTagInfo, sizeof AttributeTagInfo))
            return NtStatusFromWin32(GetLastError());

        BasicInfo.FileAttributes = FileAttributes | AttributeTagInfo.FileAttributes;
        if (BasicInfo.FileAttributes ^ FileAttributes)
        {
            if (!SetFileInformationByHandle(Handle,
                                            FileBasicInfo, &BasicInfo, sizeof BasicInfo))
                return NtStatusFromWin32(GetLastError());
        }
    }

    if (!SetFileInformationByHandle(Handle,
                                    FileAllocationInfo, &AllocationInfo, sizeof AllocationInfo))
        return NtStatusFromWin32(GetLastError());

    Desc->Dirty = Desc->Writable;
    return GetFileInfoInternal(Handle, FileInfo);
}

VOID Ptfs::Cleanup(
    PVOID FileNode,
    PVOID FileDesc,
    PWSTR FileName,
    ULONG Flags)
{
    PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;
    if (Flags & CleanupDelete)
    {
        std::lock_guard<std::mutex> IoLock(Desc->IoLock);
        WCHAR Sidecar[FULLPATH_SIZE];
        BOOLEAN SidecarRemoved = FALSE;
        if (Desc->Hashed && L'\0' != Desc->OldHash[0])
        {
            if (0 == StringCbPrintfW(Sidecar, sizeof Sidecar, L"%s%s", Desc->PhysicalPath, SIDECAR_SUFFIX))
            {
                SidecarRemoved = DeleteFileW(Sidecar) || ERROR_FILE_NOT_FOUND == GetLastError();
                if (SidecarRemoved)
                {
                    StringCchCopyW(Desc->ArchiveHash, ARRAYSIZE(Desc->ArchiveHash), Desc->OldHash);
                    Desc->ArchivePending = TRUE;
                }
                else
                    fail(L"cannot remove content sidecar '%s' (Win32 error %u)", Sidecar, GetLastError());
            }
            else fail(L"cannot form content sidecar path for '%s'", Desc->VirtualPath);
        }
        if (Desc->Handle != INVALID_HANDLE_VALUE)
        {
            FILE_INFO_BY_HANDLE_CLASS InfoClass = FileBasicInfo;
            FILE_BASIC_INFO Basic = { 0 };
            if (GetFileInformationByHandleEx(Desc->Handle, InfoClass, &Basic, sizeof Basic) &&
                (Basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                RemoveDirectoryW(Desc->PhysicalPath);
            else if (!Desc->Hashed || SidecarRemoved)
                DeleteFileW(Desc->PhysicalPath);
        }
        if (L'\0' != Desc->TempPath[0]) DeleteFileW(Desc->TempPath);
        Desc->Dirty = FALSE;
    }
    else
    {
        NTSTATUS Result = CommitFile(Desc);
        if (!NT_SUCCESS(Result)) fail(L"cannot commit content-addressed file '%s' (0x%08x)", Desc->VirtualPath, Result);
    }
}

VOID Ptfs::Close(
    PVOID FileNode,
    PVOID FileDesc0)
{
    PtfsFileDesc * FileDesc = (PtfsFileDesc *)FileDesc0;
    NTSTATUS CommitResult = CommitFile(FileDesc);
    BOOLEAN Committed = NT_SUCCESS(CommitResult);
    if (!Committed) fail(L"cannot finalize content-addressed file '%s' (0x%08x)", FileDesc->VirtualPath, CommitResult);
    if (Committed && FileDesc->Hashed && 0 == _wcsicmp(FileDesc->BackingPath, FileDesc->PhysicalPath))
        DeleteFileW(FileDesc->PhysicalPath);
    std::wstring Key = NormalizeVirtualPath(FileDesc->VirtualPath);
    if (FileDesc->Registered)
    {
        std::lock_guard<std::mutex> Lock(_StoreLock);
        _ActiveFiles.erase(Key);
    }
    HANDLE Handle = FileDesc->Handle;
    FileDesc->Handle = INVALID_HANDLE_VALUE;
    if (INVALID_HANDLE_VALUE != Handle) CloseHandle(Handle);
    if (L'\0' != FileDesc->TempPath[0]) DeleteFileW(FileDesc->TempPath);
    if (FileDesc->ArchivePending)
    {
        std::lock_guard<std::mutex> Lock(_StoreLock);
        NTSTATUS ArchiveResult = RemoveReference(FileDesc->ArchiveHash, FileDesc->VirtualPath, FALSE);
        if (NT_SUCCESS(ArchiveResult))
            ArchiveResult = ArchiveIfUnreferenced(FileDesc->ArchiveHash, FileDesc->VirtualPath);
        if (!NT_SUCCESS(ArchiveResult))
            fail(L"cannot archive deleted file '%s' (0x%08x); content remains recoverable in the object store",
                FileDesc->VirtualPath, ArchiveResult);
    }
    delete FileDesc;
}

NTSTATUS Ptfs::Read(
    PVOID FileNode,
    PVOID FileDesc,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    PULONG PBytesTransferred)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    std::lock_guard<std::mutex> IoLock(((PtfsFileDesc *)FileDesc)->IoLock);
    OVERLAPPED Overlapped = { 0 };

    Overlapped.Offset = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    if (!ReadFile(Handle, Buffer, Length, PBytesTransferred, &Overlapped))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::Write(
    PVOID FileNode,
    PVOID FileDesc,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    BOOLEAN WriteToEndOfFile,
    BOOLEAN ConstrainedIo,
    PULONG PBytesTransferred,
    FileInfo * FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    std::lock_guard<std::mutex> IoLock(((PtfsFileDesc *)FileDesc)->IoLock);
    LARGE_INTEGER FileSize;
    OVERLAPPED Overlapped = { 0 };

    *PBytesTransferred = 0;

    if (WriteToEndOfFile)
    {
        if (!GetFileSizeEx(Handle, &FileSize))
            return NtStatusFromWin32(GetLastError());
        Offset = (UINT64)FileSize.QuadPart;
    }

    if (ConstrainedIo)
    {
        if (!GetFileSizeEx(Handle, &FileSize))
            return NtStatusFromWin32(GetLastError());

        if (Offset >= (UINT64)FileSize.QuadPart)
            return STATUS_SUCCESS;
        if ((UINT64)Length > (UINT64)FileSize.QuadPart - Offset)
            Length = (ULONG)((UINT64)FileSize.QuadPart - Offset);
    }

    Overlapped.Offset = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    if (!WriteFile(Handle, Buffer, Length, PBytesTransferred, &Overlapped))
        return NtStatusFromWin32(GetLastError());

    ((PtfsFileDesc *)FileDesc)->Dirty = TRUE;
    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS Ptfs::Flush(
    PVOID FileNode,
    PVOID FileDesc,
    FileInfo * FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;

    /* we do not flush the whole volume, so just return SUCCESS */
    if (0 == Handle)
        return STATUS_SUCCESS;

    NTSTATUS Result;
    {
        std::lock_guard<std::mutex> IoLock(Desc->IoLock);
        if (!FlushFileBuffers(Handle)) return NtStatusFromWin32(GetLastError());
        Result = GetFileInfoInternal(Handle, FileInfo);
    }
    if (NT_SUCCESS(Result)) Result = CommitFile(Desc);
    return Result;
}

NTSTATUS Ptfs::GetFileInfo(
    PVOID FileNode,
    PVOID FileDesc,
    FileInfo * FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    std::lock_guard<std::mutex> IoLock(((PtfsFileDesc *)FileDesc)->IoLock);

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS Ptfs::SetBasicInfo(
    PVOID FileNode,
    PVOID FileDesc,
    UINT32 FileAttributes,
    UINT64 CreationTime,
    UINT64 LastAccessTime,
    UINT64 LastWriteTime,
    UINT64 ChangeTime,
    FileInfo * FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    std::lock_guard<std::mutex> IoLock(((PtfsFileDesc *)FileDesc)->IoLock);
    FILE_BASIC_INFO BasicInfo = { 0 };

    if (INVALID_FILE_ATTRIBUTES == FileAttributes)
        FileAttributes = 0;
    else if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    BasicInfo.FileAttributes = FileAttributes;
    BasicInfo.CreationTime.QuadPart = CreationTime;
    BasicInfo.LastAccessTime.QuadPart = LastAccessTime;
    BasicInfo.LastWriteTime.QuadPart = LastWriteTime;
    //BasicInfo.ChangeTime = ChangeTime;

    if (!SetFileInformationByHandle(Handle,
                                    FileBasicInfo, &BasicInfo, sizeof BasicInfo))
        return NtStatusFromWin32(GetLastError());

    ((PtfsFileDesc *)FileDesc)->Dirty = ((PtfsFileDesc *)FileDesc)->Writable;
    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS Ptfs::SetFileSize(
    PVOID FileNode,
    PVOID FileDesc,
    UINT64 NewSize,
    BOOLEAN SetAllocationSize,
    FileInfo * FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    std::lock_guard<std::mutex> IoLock(((PtfsFileDesc *)FileDesc)->IoLock);
    FILE_ALLOCATION_INFO AllocationInfo;
    FILE_END_OF_FILE_INFO EndOfFileInfo;

    if (SetAllocationSize)
    {
        /*
         * This file system does not maintain AllocationSize, although NTFS clearly can.
         * However it must always be FileSize <= AllocationSize and NTFS will make sure
         * to truncate the FileSize if it sees an AllocationSize < FileSize.
         *
         * If OTOH a very large AllocationSize is passed, the call below will increase
         * the AllocationSize of the underlying file, although our file system does not
         * expose this fact. This AllocationSize is only temporary as NTFS will reset
         * the AllocationSize of the underlying file when it is closed.
         */

        AllocationInfo.AllocationSize.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
                                        FileAllocationInfo, &AllocationInfo, sizeof AllocationInfo))
            return NtStatusFromWin32(GetLastError());
    }
    else
    {
        EndOfFileInfo.EndOfFile.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
                                        FileEndOfFileInfo, &EndOfFileInfo, sizeof EndOfFileInfo))
            return NtStatusFromWin32(GetLastError());
    }

    ((PtfsFileDesc *)FileDesc)->Dirty = ((PtfsFileDesc *)FileDesc)->Writable;
    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS Ptfs::CanDelete(
    PVOID FileNode,
    PVOID FileDesc,
    PWSTR FileName)
{
    PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;
    std::lock_guard<std::mutex> IoLock(Desc->IoLock);
    if (!IsValidVirtualPath(FileName, FALSE)) return STATUS_OBJECT_NAME_INVALID;
    if (Desc->Handle == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    FILE_BASIC_INFO Basic = { 0 };
    if (GetFileInformationByHandleEx(Desc->Handle, FileBasicInfo, &Basic, sizeof Basic) &&
        (Basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        WCHAR Pattern[FULLPATH_SIZE];
        if (0 != StringCbPrintfW(Pattern, sizeof Pattern, L"%s\\*", Desc->PhysicalPath))
            return STATUS_OBJECT_NAME_INVALID;
        WIN32_FIND_DATAW FindData;
        HANDLE Find = FindFirstFileW(Pattern, &FindData);
        if (INVALID_HANDLE_VALUE != Find)
        {
            do
            {
                if (0 != wcscmp(FindData.cFileName, L".") && 0 != wcscmp(FindData.cFileName, L".."))
                { FindClose(Find); return STATUS_DIRECTORY_NOT_EMPTY; }
            } while (FindNextFileW(Find, &FindData));
            FindClose(Find);
        }
    }
    Desc->DeleteRequested = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::Rename(
    PVOID FileNode,
    PVOID FileDesc,
    PWSTR FileName,
    PWSTR NewFileName,
    BOOLEAN ReplaceIfExists)
{
    PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;
    WCHAR NewFullPath[FULLPATH_SIZE], NewSidecar[FULLPATH_SIZE], OldSidecar[FULLPATH_SIZE];
    if (!IsValidVirtualPath(FileName, FALSE) || !IsValidVirtualPath(NewFileName, FALSE) ||
        !BuildPath(NewFileName, NewFullPath))
        return STATUS_OBJECT_NAME_INVALID;

    std::unique_lock<std::mutex> IoLock;
    for (;;)
    {
        NTSTATUS Result = CommitFile(Desc);
        if (!NT_SUCCESS(Result)) return Result;
        IoLock = std::unique_lock<std::mutex>(Desc->IoLock);
        if (!Desc->Dirty) break;
        IoLock.unlock();
    }

    std::wstring OldKey = NormalizeVirtualPath(Desc->VirtualPath);
    std::wstring NewKey = NormalizeVirtualPath(NewFileName);
    {
        std::lock_guard<std::mutex> Lock(_StoreLock);
        auto It = _ActiveFiles.find(NewKey);
        if (It != _ActiveFiles.end() && NewKey != OldKey) return STATUS_SHARING_VIOLATION;
    }

    if (Desc->Hashed)
    {
        WCHAR DestHash[65] = { 0 };
        BOOLEAN DestHashed = FALSE;
        WCHAR DestResolved[FULLPATH_SIZE];
        NTSTATUS Result = ResolveFilePath(NewFileName, DestResolved, DestHash, &DestHashed);
        if (!NT_SUCCESS(Result) && STATUS_OBJECT_NAME_NOT_FOUND != Result) return Result;
        DWORD DestAttrs = GetFileAttributesW(NewFullPath);
        BOOLEAN DestExists = INVALID_FILE_ATTRIBUTES != DestAttrs || DestHashed;
        BOOLEAN SameVirtualPath = 0 == CompareStringOrdinal(OldKey.c_str(), -1, NewKey.c_str(), -1, TRUE);
        if (DestExists && !ReplaceIfExists && !SameVirtualPath) return STATUS_OBJECT_NAME_COLLISION;
        std::wstring NewDisplay = DisplayVirtualPath(NewFileName);
        if (0 != StringCbPrintfW(OldSidecar, sizeof OldSidecar, L"%s%s", Desc->PhysicalPath, SIDECAR_SUFFIX) ||
            0 != StringCbPrintfW(NewSidecar, sizeof NewSidecar, L"%s%s", NewFullPath, SIDECAR_SUFFIX))
            return STATUS_OBJECT_NAME_INVALID;
        if (DestHashed && 0 == _wcsicmp(DestHash, Desc->OldHash) && SameVirtualPath)
        {
            std::lock_guard<std::mutex> Lock(_StoreLock);
            NTSTATUS RefResult = AddReference(Desc->OldHash, NewDisplay.c_str());
            if (!NT_SUCCESS(RefResult)) return RefResult;
            if (0 != wcscmp(Desc->VirtualPath, NewDisplay.c_str()))
            {
                WCHAR Parent[FULLPATH_SIZE], TempSidecar[FULLPATH_SIZE];
                StringCchCopyW(Parent, ARRAYSIZE(Parent), OldSidecar);
                PWSTR Slash = wcsrchr(Parent, L'\\');
                if (0 == Slash) return STATUS_OBJECT_NAME_INVALID;
                *Slash = L'\0';
                if (!GetTempFileNameW(Parent, L"csn", 0, TempSidecar))
                { DWORD E = GetLastError(); AddReference(Desc->OldHash, Desc->VirtualPath); return NtStatusFromWin32(E); }
                DeleteFileW(TempSidecar);
                if (!MoveFileExW(OldSidecar, TempSidecar, MOVEFILE_WRITE_THROUGH))
                { DWORD E = GetLastError(); AddReference(Desc->OldHash, Desc->VirtualPath); return NtStatusFromWin32(E); }
                if (!MoveFileExW(TempSidecar, NewSidecar, MOVEFILE_WRITE_THROUGH))
                {
                    DWORD E = GetLastError(); MoveFileExW(TempSidecar, OldSidecar, MOVEFILE_WRITE_THROUGH);
                    AddReference(Desc->OldHash, Desc->VirtualPath);
                    return NtStatusFromWin32(E);
                }
            }
            StringCchCopyW(Desc->VirtualPath, ARRAYSIZE(Desc->VirtualPath), DisplayVirtualPath(NewFileName).c_str());
            StringCchCopyW(Desc->PhysicalPath, ARRAYSIZE(Desc->PhysicalPath), NewFullPath);
            return STATUS_SUCCESS;
        }

        std::lock_guard<std::mutex> Lock(_StoreLock);
        Result = AddReference(Desc->OldHash, NewDisplay.c_str());
        if (!NT_SUCCESS(Result)) return Result;
        Result = WriteSidecar(NewSidecar, Desc->OldHash);
        if (!NT_SUCCESS(Result)) { RemoveReference(Desc->OldHash, NewDisplay.c_str()); return Result; }
        if (DestHashed && 0 != _wcsicmp(DestHash, Desc->OldHash))
        {
            Result = RemoveReference(DestHash, NewDisplay.c_str(), FALSE);
            if (!NT_SUCCESS(Result))
            {
                WriteSidecar(NewSidecar, DestHash);
                RemoveReference(Desc->OldHash, NewDisplay.c_str());
                return Result;
            }
        }
        Result = RemoveReference(Desc->OldHash, OldKey.c_str(), FALSE);
        if (!NT_SUCCESS(Result))
        {
            if (DestHashed)
            {
                WriteSidecar(NewSidecar, DestHash);
                if (0 != _wcsicmp(DestHash, Desc->OldHash)) AddReference(DestHash, NewDisplay.c_str());
            }
            else DeleteFileW(NewSidecar);
            RemoveReference(Desc->OldHash, NewDisplay.c_str());
            return Result;
        }
        if (!DeleteFileW(OldSidecar) && ERROR_FILE_NOT_FOUND != GetLastError())
        {
            DWORD Error = GetLastError();
            AddReference(Desc->OldHash, OldKey.c_str());
            if (DestHashed)
            {
                WriteSidecar(NewSidecar, DestHash);
                if (0 != _wcsicmp(DestHash, Desc->OldHash)) AddReference(DestHash, NewDisplay.c_str());
            }
            else DeleteFileW(NewSidecar);
            RemoveReference(Desc->OldHash, NewDisplay.c_str(), FALSE);
            return NtStatusFromWin32(Error);
        }
        if (INVALID_FILE_ATTRIBUTES != DestAttrs) DeleteFileW(NewFullPath);
        if (DestHashed && 0 != _wcsicmp(DestHash, Desc->OldHash))
        {
            Result = ArchiveIfUnreferenced(DestHash, NewDisplay.c_str());
            if (!NT_SUCCESS(Result)) warn(L"cannot archive replaced content object (0x%08x)", Result);
        }
        Result = ArchiveIfUnreferenced(Desc->OldHash, Desc->VirtualPath);
        if (!NT_SUCCESS(Result)) warn(L"cannot archive renamed content object (0x%08x)", Result);
        Desc->Hashed = TRUE;
    }
    else
    {
        DWORD DestAttrs = GetFileAttributesW(NewFullPath);
        FILE_BASIC_INFO SourceBasic = { 0 };
        BOOLEAN IsDirectory = GetFileInformationByHandleEx(Desc->Handle, FileBasicInfo, &SourceBasic, sizeof SourceBasic) &&
                              0 != (SourceBasic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        BOOLEAN ReferencesRenamed = FALSE;
        WCHAR DestResolved[FULLPATH_SIZE], DestHash[65], DestSidecar[FULLPATH_SIZE], BackupSidecar[FULLPATH_SIZE];
        BOOLEAN DestHashed = FALSE, SidecarBackedUp = FALSE;
        NTSTATUS ResolveResult = ResolveFilePath(NewFileName, DestResolved, DestHash, &DestHashed);
        if (!NT_SUCCESS(ResolveResult)) return ResolveResult;
        if ((INVALID_FILE_ATTRIBUTES != DestAttrs || DestHashed) && !ReplaceIfExists) return STATUS_OBJECT_NAME_COLLISION;
        if (DestHashed)
        {
            if (0 != StringCbPrintfW(DestSidecar, sizeof DestSidecar, L"%s%s", NewFullPath, SIDECAR_SUFFIX))
                return STATUS_OBJECT_NAME_INVALID;
            WCHAR Parent[FULLPATH_SIZE];
            if (0 != StringCchCopyW(Parent, ARRAYSIZE(Parent), DestSidecar)) return STATUS_OBJECT_NAME_INVALID;
            PWSTR Slash = wcsrchr(Parent, L'\\');
            if (0 == Slash) return STATUS_OBJECT_NAME_INVALID;
            *Slash = L'\0';
            if (!GetTempFileNameW(Parent, L"~rb", 0, BackupSidecar)) return NtStatusFromWin32(GetLastError());
            DeleteFileW(BackupSidecar);
            if (!MoveFileExW(DestSidecar, BackupSidecar, MOVEFILE_WRITE_THROUGH))
                return NtStatusFromWin32(GetLastError());
            SidecarBackedUp = TRUE;
        }
        if (IsDirectory)
        {
            std::lock_guard<std::mutex> Lock(_StoreLock);
            for (const auto & Active : _ActiveFiles)
            {
                BOOLEAN UnderOld = Active.size() > OldKey.size() &&
                    0 == CompareStringOrdinal(Active.c_str(), (int)OldKey.size(), OldKey.c_str(), (int)OldKey.size(), TRUE) &&
                    L'\\' == Active[OldKey.size()];
                BOOLEAN UnderNew = Active.size() > NewKey.size() &&
                    0 == CompareStringOrdinal(Active.c_str(), (int)NewKey.size(), NewKey.c_str(), (int)NewKey.size(), TRUE) &&
                    L'\\' == Active[NewKey.size()];
                if (UnderOld || UnderNew)
                {
                    if (SidecarBackedUp) MoveFileExW(BackupSidecar, DestSidecar, MOVEFILE_WRITE_THROUGH);
                    return STATUS_SHARING_VIOLATION;
                }
            }
            NTSTATUS RefResult = RewriteReferencePrefix(_Path, Desc->VirtualPath, DisplayVirtualPath(NewFileName).c_str());
            if (!NT_SUCCESS(RefResult))
            {
                if (SidecarBackedUp) MoveFileExW(BackupSidecar, DestSidecar, MOVEFILE_WRITE_THROUGH);
                return RefResult;
            }
            ReferencesRenamed = TRUE;
        }
        SIZE_T NameBytes = wcslen(NewFullPath) * sizeof(WCHAR);
        SIZE_T RenameInfoSize = FIELD_OFFSET(FILE_RENAME_INFO, FileName) + NameBytes;
        PFILE_RENAME_INFO RenameInfo = (PFILE_RENAME_INFO)new BYTE[RenameInfoSize];
        memset(RenameInfo, 0, RenameInfoSize);
        RenameInfo->ReplaceIfExists = ReplaceIfExists;
        RenameInfo->RootDirectory = 0;
        RenameInfo->FileNameLength = (DWORD)NameBytes;
        memcpy(RenameInfo->FileName, NewFullPath, NameBytes);
        BOOL Renamed = SetFileInformationByHandle(Desc->Handle, FileRenameInfo, RenameInfo, (DWORD)RenameInfoSize);
        DWORD Error = Renamed ? ERROR_SUCCESS : GetLastError();
        delete[] (PBYTE)RenameInfo;
        if (!Renamed)
        {
            if (SidecarBackedUp) MoveFileExW(BackupSidecar, DestSidecar, MOVEFILE_WRITE_THROUGH);
            if (ReferencesRenamed)
            {
                std::lock_guard<std::mutex> Lock(_StoreLock);
                RewriteReferencePrefix(_Path, DisplayVirtualPath(NewFileName).c_str(), Desc->VirtualPath);
            }
            return NtStatusFromWin32(Error);
        }
        if (SidecarBackedUp)
        {
            std::lock_guard<std::mutex> Lock(_StoreLock);
            NTSTATUS RefResult = RemoveReference(DestHash, DisplayVirtualPath(NewFileName).c_str());
            if (!NT_SUCCESS(RefResult))
            {
                WCHAR OldFullPath[FULLPATH_SIZE];
                if (BuildPath(FileName, OldFullPath))
                {
                    SIZE_T OldNameBytes = wcslen(OldFullPath) * sizeof(WCHAR);
                    SIZE_T OldInfoSize = FIELD_OFFSET(FILE_RENAME_INFO, FileName) + OldNameBytes;
                    PFILE_RENAME_INFO OldInfo = (PFILE_RENAME_INFO)new BYTE[OldInfoSize];
                    memset(OldInfo, 0, OldInfoSize);
                    OldInfo->FileNameLength = (DWORD)OldNameBytes;
                    memcpy(OldInfo->FileName, OldFullPath, OldNameBytes);
                    SetFileInformationByHandle(Desc->Handle, FileRenameInfo, OldInfo, (DWORD)OldInfoSize);
                    delete[] (PBYTE)OldInfo;
                }
                MoveFileExW(BackupSidecar, DestSidecar, MOVEFILE_WRITE_THROUGH);
                return RefResult;
            }
            DeleteFileW(BackupSidecar);
        }
        StringCchCopyW(Desc->BackingPath, ARRAYSIZE(Desc->BackingPath), NewFullPath);
    }

    {
        std::lock_guard<std::mutex> Lock(_StoreLock);
        if (Desc->Registered) { _ActiveFiles.erase(OldKey); _ActiveFiles.insert(NewKey); }
    }
    StringCchCopyW(Desc->VirtualPath, ARRAYSIZE(Desc->VirtualPath), DisplayVirtualPath(NewFileName).c_str());
    StringCchCopyW(Desc->PhysicalPath, ARRAYSIZE(Desc->PhysicalPath), NewFullPath);

    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::GetSecurity(
    PVOID FileNode,
    PVOID FileDesc,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T * PSecurityDescriptorSize)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    HANDLE SecurityHandle = Handle;
    HANDLE ReopenedHandle = INVALID_HANDLE_VALUE;
    DWORD SecurityDescriptorSizeNeeded = 0;

    BOOL Ok = GetKernelObjectSecurity(SecurityHandle,
                                 OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                 SecurityDescriptor, (DWORD)*PSecurityDescriptorSize, &SecurityDescriptorSizeNeeded);
    DWORD Error = Ok ? ERROR_SUCCESS : GetLastError();
    if (!Ok && ERROR_ACCESS_DENIED == Error)
    {
        PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;
        ReopenedHandle = CreateFileW(Desc->BackingPath, READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, 0);
        if (INVALID_HANDLE_VALUE == ReopenedHandle)
        {
            WCHAR Path[FULLPATH_SIZE];
            DWORD Length = GetFinalPathNameByHandleW(Handle, Path, ARRAYSIZE(Path), 0);
            if (0 != Length && Length < ARRAYSIZE(Path))
            {
                ReopenedHandle = CreateFileW(Path, READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, 0);
                if (INVALID_HANDLE_VALUE == ReopenedHandle)
                    Error = GetLastError();
            }
            else Error = 0 == Length ? GetLastError() : ERROR_FILENAME_EXCED_RANGE;
        }
        if (INVALID_HANDLE_VALUE != ReopenedHandle)
        {
            SecurityHandle = ReopenedHandle;
            Ok = GetKernelObjectSecurity(SecurityHandle,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                SecurityDescriptor, (DWORD)*PSecurityDescriptorSize, &SecurityDescriptorSizeNeeded);
            Error = Ok ? ERROR_SUCCESS : GetLastError();
        }
    }

    if (INVALID_HANDLE_VALUE != ReopenedHandle) CloseHandle(ReopenedHandle);
    if (!Ok)
    {
        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
        fail(L"cannot read security descriptor for '%s' (Win32 error %u)",
            ((PtfsFileDesc *)FileDesc)->VirtualPath, Error);
        return NtStatusFromWin32(Error);
    }
    *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;

    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::SetSecurity(
    PVOID FileNode,
    PVOID FileDesc,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    HANDLE Handle = HandleFromFileDesc(FileDesc);
    PtfsFileDesc * Desc = (PtfsFileDesc *)FileDesc;
    std::lock_guard<std::mutex> IoLock(Desc->IoLock);

    if (!SetKernelObjectSecurity(Handle, SecurityInformation, ModificationDescriptor))
        return NtStatusFromWin32(GetLastError());

    Desc->Dirty = Desc->Writable;
    return STATUS_SUCCESS;
}

NTSTATUS Ptfs::ReadDirectory(
    PVOID FileNode,
    PVOID FileDesc0,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID Buffer,
    ULONG Length,
    PULONG PBytesTransferred)
{
    PtfsFileDesc * FileDesc = (PtfsFileDesc *)FileDesc0;
    return BufferedReadDirectory(&FileDesc->DirBuffer,
                                 FileNode, FileDesc, Pattern, Marker, Buffer, Length, PBytesTransferred);
}

NTSTATUS Ptfs::ReadDirectoryEntry(
    PVOID FileNode,
    PVOID FileDesc0,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID * PContext,
    DirInfo * DirInfo)
{
    PtfsFileDesc * FileDesc = (PtfsFileDesc *)FileDesc0;
    HANDLE Handle = FileDesc->Handle;
    WCHAR FullPath[FULLPATH_SIZE];
    ULONG Length;
    HANDLE FindHandle;
    WIN32_FIND_DATAW FindData;

    if (0 == *PContext)
    {
        Length = GetFinalPathNameByHandleW(Handle, FullPath, FULLPATH_SIZE - 1, 0);
        if (0 == Length)
            return NtStatusFromWin32(GetLastError());
        if (Length >= FULLPATH_SIZE - 1)
            return STATUS_OBJECT_NAME_INVALID;

        if (L'\\' != FullPath[Length - 1])
            FullPath[Length++] = L'\\';
        FullPath[Length++] = L'*';
        FullPath[Length] = L'\0';

        FindHandle = FindFirstFileW(FullPath, &FindData);
        if (INVALID_HANDLE_VALUE == FindHandle)
        {
            DWORD Error = GetLastError();
            return ERROR_FILE_NOT_FOUND == Error || ERROR_PATH_NOT_FOUND == Error ?
                STATUS_NO_MORE_FILES : NtStatusFromWin32(Error);
        }

        *PContext = FindHandle;
    }
    else
    {
        FindHandle = *PContext;
        if (!FindNextFileW(FindHandle, &FindData))
        {
            DWORD Error = GetLastError();
            FindClose(FindHandle);
            *PContext = 0;
            return ERROR_NO_MORE_FILES == Error ? STATUS_NO_MORE_FILES : NtStatusFromWin32(Error);
        }
    }

    for (;;)
    {
        WCHAR VisibleName[MAX_PATH], VirtualName[FULLPATH_SIZE], CandidatePath[FULLPATH_SIZE], Hash[65];
        BOOLEAN IsSidecar = FALSE, UseObjectInfo = FALSE, IsDotEntry = FALSE;
        DWORD Attrs = FindData.dwFileAttributes;
        Length = (ULONG)wcslen(FindData.cFileName);
        if (Attrs & FILE_ATTRIBUTE_REPARSE_POINT) goto next_entry;
        if (Length >= ARRAYSIZE(VisibleName)) goto next_entry;
        StringCchCopyW(VisibleName, ARRAYSIZE(VisibleName), FindData.cFileName);
        IsDotEntry = 0 == wcscmp(VisibleName, L".") || 0 == wcscmp(VisibleName, L"..");
        if (!IsDotEntry && !(Attrs & FILE_ATTRIBUTE_DIRECTORY) && Length >= 7 &&
            0 == _wcsicmp(VisibleName + Length - 7, SIDECAR_SUFFIX))
        {
            VisibleName[Length - 7] = L'\0';
            IsSidecar = TRUE;
        }
        if (0 == FileDesc->VirtualPath[0] && (Attrs & FILE_ATTRIBUTE_DIRECTORY) &&
            (0 == _wcsicmp(VisibleName, L"_sha256") || 0 == _wcsicmp(VisibleName, L"_deleted")))
            goto next_entry;
        if (0 != FileDesc->VirtualPath[0])
            StringCchPrintfW(VirtualName, ARRAYSIZE(VirtualName), L"%s\\%s", FileDesc->VirtualPath, VisibleName);
        else
            StringCchCopyW(VirtualName, ARRAYSIZE(VirtualName), VisibleName);
        if (!IsDotEntry && !IsValidVirtualPath(VirtualName, FALSE)) goto next_entry;
        if (0 != Pattern && L'\0' != *Pattern && !PathMatchSpecW(VisibleName, Pattern)) goto next_entry;
        if (IsSidecar)
        {
            if (!BuildPath(VirtualName, CandidatePath)) goto next_entry;
            WCHAR Sidecar[FULLPATH_SIZE];
            if (0 != StringCbPrintfW(Sidecar, sizeof Sidecar, L"%s%s", CandidatePath, SIDECAR_SUFFIX)) goto next_entry;
            if (!NT_SUCCESS(ReadSidecar(Sidecar, Hash))) goto next_entry;
            WCHAR ObjectPath[FULLPATH_SIZE];
            if (!NT_SUCCESS(GetObjectPath(Hash, ObjectPath, FALSE))) goto next_entry;
            HANDLE Object = CreateFileW(ObjectPath, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
            if (INVALID_HANDLE_VALUE == Object) goto next_entry;
            NTSTATUS InfoResult = GetFileInfoInternal(Object, &DirInfo->FileInfo);
            CloseHandle(Object);
            if (!NT_SUCCESS(InfoResult)) goto next_entry;
            UseObjectInfo = TRUE;
            Attrs = DirInfo->FileInfo.FileAttributes;
        }
        else
        {
            if (!(Attrs & FILE_ATTRIBUTE_DIRECTORY))
            {
                WCHAR CandidateSidecar[FULLPATH_SIZE];
                if (!BuildPath(VirtualName, CandidatePath) ||
                    0 != StringCbPrintfW(CandidateSidecar, sizeof CandidateSidecar, L"%s%s", CandidatePath, SIDECAR_SUFFIX))
                    goto next_entry;
                if (INVALID_FILE_ATTRIBUTES != GetFileAttributesW(CandidateSidecar)) goto next_entry;
            }
        }
        if (!UseObjectInfo)
        {
            memset(&DirInfo->FileInfo, 0, sizeof DirInfo->FileInfo);
            DirInfo->FileInfo.FileAttributes = FindData.dwFileAttributes;
            DirInfo->FileInfo.FileSize = ((UINT64)FindData.nFileSizeHigh << 32) | FindData.nFileSizeLow;
            DirInfo->FileInfo.AllocationSize = (DirInfo->FileInfo.FileSize + ALLOCATION_UNIT - 1) / ALLOCATION_UNIT * ALLOCATION_UNIT;
            DirInfo->FileInfo.CreationTime = ((PLARGE_INTEGER)&FindData.ftCreationTime)->QuadPart;
            DirInfo->FileInfo.LastAccessTime = ((PLARGE_INTEGER)&FindData.ftLastAccessTime)->QuadPart;
            DirInfo->FileInfo.LastWriteTime = ((PLARGE_INTEGER)&FindData.ftLastWriteTime)->QuadPart;
            DirInfo->FileInfo.ChangeTime = DirInfo->FileInfo.LastWriteTime;
        }
        DirInfo->FileInfo.FileAttributes = Attrs;
        DirInfo->FileInfo.ReparseTag = 0;
        DirInfo->FileInfo.IndexNumber = 0;
        DirInfo->FileInfo.HardLinks = 0;
        Length = (ULONG)wcslen(VisibleName);
        DirInfo->Size = (UINT16)(FIELD_OFFSET(Ptfs::DirInfo, FileNameBuf) + Length * sizeof(WCHAR));
        memcpy(DirInfo->FileNameBuf, VisibleName, Length * sizeof(WCHAR));
        return STATUS_SUCCESS;

next_entry:
        if (!FindNextFileW(FindHandle, &FindData))
        {
            DWORD Error = GetLastError();
            FindClose(FindHandle);
            *PContext = 0;
            return ERROR_NO_MORE_FILES == Error ? STATUS_NO_MORE_FILES : NtStatusFromWin32(Error);
        }
    }
}

class PtfsService : public Service
{
    public:
        PtfsService();

    protected:
        NTSTATUS OnStart(ULONG Argc, PWSTR * Argv);
        NTSTATUS OnStop();

    private:
        Ptfs _Ptfs;
        FileSystemHost _Host;
};

static NTSTATUS EnableBackupRestorePrivileges(VOID)
{
    union
    {
        TOKEN_PRIVILEGES P;
        UINT8 B[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
    } Privileges;
    HANDLE Token;

    Privileges.P.PrivilegeCount = 2;
    Privileges.P.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Privileges.P.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(0, L"SeBackupPrivilege", &Privileges.P.Privileges[0].Luid) ||
            !LookupPrivilegeValueW(0,  L"SeRestorePrivilege", &Privileges.P.Privileges[1].Luid))
        return FspNtStatusFromWin32(GetLastError());

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FspNtStatusFromWin32(GetLastError());

    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(Token, FALSE, &Privileges.P, 0, 0, 0))
    {
        CloseHandle(Token);

        return FspNtStatusFromWin32(GetLastError());
    }

    if (ERROR_NOT_ALL_ASSIGNED == GetLastError())
    {
        CloseHandle(Token);
        return FspNtStatusFromWin32(ERROR_NOT_ALL_ASSIGNED);
    }

    CloseHandle(Token);

    return STATUS_SUCCESS;
}

static ULONG wcstol_deflt(wchar_t * w, ULONG deflt)
{
    wchar_t * endp;
    ULONG ul = wcstol(w, &endp, 0);
    return L'\0' != w[0] && L'\0' == *endp ? ul : deflt;
}

PtfsService::PtfsService() : Service(L"" PROGNAME), _Ptfs(), _Host(_Ptfs)
{
}

NTSTATUS PtfsService::OnStart(ULONG argc, PWSTR * argv)
{
#define argtos(v)                       if (arge > ++argp) v = *argp; else goto usage
#define argtol(v)                       if (arge > ++argp) v = wcstol_deflt(*argp, v); else goto usage

    wchar_t ** argp, **arge;
    PWSTR DebugLogFile = 0;
    ULONG DebugFlags = 0;
    PWSTR VolumePrefix = 0;
    PWSTR PassThrough = 0;
    PWSTR MountPoint = 0;
    HANDLE DebugLogHandle = INVALID_HANDLE_VALUE;
    WCHAR PassThroughBuf[MAX_PATH];
    NTSTATUS Result;

    for (argp = argv + 1, arge = argv + argc; arge > argp; argp++)
    {
        if (L'-' != argp[0][0])
            break;
        switch (argp[0][1])
        {
            case L'?':
                goto usage;
            case L'd':
                argtol(DebugFlags);
                break;
            case L'D':
                argtos(DebugLogFile);
                break;
            case L'm':
                argtos(MountPoint);
                break;
            case L'p':
                argtos(PassThrough);
                break;
            case L'u':
                argtos(VolumePrefix);
                break;
            default:
                goto usage;
        }
    }

    if (arge > argp)
        goto usage;

    if (0 == PassThrough && 0 != VolumePrefix)
    {
        PWSTR P;

        P = wcschr(VolumePrefix, L'\\');
        if (0 != P && L'\\' != P[1])
        {
            P = wcschr(P + 1, L'\\');
            if (0 != P &&
                    (
                        (L'A' <= P[1] && P[1] <= L'Z') ||
                        (L'a' <= P[1] && P[1] <= L'z')
                    ) &&
                    L'$' == P[2])
            {
                StringCbPrintfW(PassThroughBuf, sizeof PassThroughBuf, L"%c:%s", P[1], P + 3);
                PassThrough = PassThroughBuf;
            }
        }
    }

    if (0 == PassThrough || 0 == MountPoint)
        goto usage;

    Result = EnableBackupRestorePrivileges();
    if (!NT_SUCCESS(Result))
    {
        warn(L"backup/restore privileges unavailable; continuing without them (0x%08x)", Result);
    }

    if (0 != DebugLogFile)
    {
        if (0 != wcscmp(DebugLogFile, L"-") &&
            FAILED(StringCchCopyW(::DebugLogPath, ARRAYSIZE(::DebugLogPath), DebugLogFile)))
        {
            fail(L"debug log path is too long");
            goto usage;
        }
        Result = FileSystemHost::SetDebugLogFile(DebugLogFile);
        if (!NT_SUCCESS(Result))
        {
            fail(L"cannot open debug log file");
            goto usage;
        }
    }

    Result = _Ptfs.SetPath(PassThrough);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot create file system (0x%08x)", Result);
        return Result;
    }

    _Host.SetPrefix(VolumePrefix);
    Result = _Host.Mount(MountPoint, 0, FALSE, DebugFlags);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot mount file system (0x%08x)", Result);
        return Result;
    }

    MountPoint = _Host.MountPoint();
    info(L"%s%s%s -p %s -m %s",
         L"" PROGNAME,
         0 != VolumePrefix && L'\0' != VolumePrefix[0] ? L" -u " : L"",
         0 != VolumePrefix && L'\0' != VolumePrefix[0] ? VolumePrefix : L"",
         PassThrough,
         MountPoint);

    return STATUS_SUCCESS;

usage:
    static wchar_t usage[] = L""
                             "usage: %s OPTIONS\n"
                             "\n"
                             "options:\n"
                             "    -d DebugFlags       [-1: enable all debug logs]\n"
                             "    -D DebugLogFile     [file path; use - for stderr]\n"
                             "    -u \\Server\\Share    [UNC prefix (single backslash)]\n"
                             "    -p Directory        [directory to expose as pass through file system]\n"
                             "    -m MountPoint       [X:|*|directory]\n";

    fail(usage, L"" PROGNAME);

    return STATUS_UNSUCCESSFUL;

#undef argtos
#undef argtol
}

NTSTATUS PtfsService::OnStop()
{
    _Host.Unmount();
    return STATUS_SUCCESS;
}

int wmain(int argc, wchar_t ** argv)
{
    return PtfsService().Run();
}

