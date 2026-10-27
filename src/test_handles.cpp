// expected to fail on second open

#include <windows.h>
#include <stdio.h>

int main()
{
    HANDLE h1 = CreateFileW(
                    L"X:\\test.txt",
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h1 == INVALID_HANDLE_VALUE)
    {
        printf("First open failed: %lu\n", GetLastError());
        return 1;
    }

    HANDLE h2 = CreateFileW(
                    L"X:\\test.txt",
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h2 == INVALID_HANDLE_VALUE)
    {
        printf("Second open failed: %lu\n", GetLastError());
        CloseHandle(h1);
        return 1;
    }

    printf("Both handles are open.\n");

    /* Write through the first handle. */
    LARGE_INTEGER zero = {};
    SetFilePointerEx(h1, zero, NULL, FILE_BEGIN);

    const char text[] = "Modified through handle 1";
    DWORD written = 0;

    if (!WriteFile(h1, text, sizeof(text) - 1, &written, NULL))
        printf("Write failed: %lu\n", GetLastError());
    else
        printf("Wrote %lu bytes.\n", written);

    printf("Closing first handle. Check whether hashing has occurred.\n");
    CloseHandle(h1);

    printf("First handle closed; second handle remains open.\n");
    printf("Press Enter to close the second handle.\n");
    getchar();

    CloseHandle(h2);

    printf("Both handles closed. Check whether hashing has occurred.\n");
    return 0;
}
