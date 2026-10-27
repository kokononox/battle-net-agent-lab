#include <windows.h>
int main() {
    char value = 0;
    DWORD count = 0;
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), &value, 1, &count, NULL)) return 2;
    return count == 1 && value == '\n' ? 0 : 3;
}
