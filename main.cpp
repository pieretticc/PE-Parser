#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>


int main() {
    std::cout << "Hello, World!" << std::endl;
    std::ifstream file(R"(C:\Windows\System32\PING.EXE)", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open the file!" << std::endl;
        return -1;
    } else {
        std::cout << "File opened successfully!" << std::endl;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    // Check if the PE signature is valid
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid PE file!" << std::endl;
        return -1;
    } else {
        std::cout << "Signature is: " << dosHeader.e_magic << std::endl;
    }
    file.seekg(dosHeader.e_lfanew, std::ios::beg); // Move to NT headers location

    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

    // Check the signature of the PE header
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature!" << std::endl;
        return -1;
    } else {
        std::cout << "Signature of PE Header is: " << ntHeaders.Signature << std::endl;
    }
    IMAGE_FILE_HEADER fileHeader = ntHeaders.FileHeader;
    std::cout << "Number of Sections: " << fileHeader.NumberOfSections << std::endl;
    std::cout << "Timestamp: " << fileHeader.TimeDateStamp << std::endl;

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders.OptionalHeader;
    std::cout << "Address of Entry Point: " << std::hex << optionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "Image Base: " << std::hex << optionalHeader.ImageBase << std::endl;

    std::vector<IMAGE_SECTION_HEADER> sectionHeaders(fileHeader.NumberOfSections);
    for (int i = 0; i < fileHeader.NumberOfSections; ++i) {
        std::cout << "\n" << std::endl;
        file.read(reinterpret_cast<char*>(&sectionHeaders[i]), sizeof(IMAGE_SECTION_HEADER));
        std::cout << "Section #" << i << ": " << std::hex << sectionHeaders[i].VirtualAddress << std::endl;
        std::cout << "Section Name: " << sectionHeaders[i].Name << std::endl;
        std::cout << "Virtual Address: " << std::hex << sectionHeaders[i].VirtualAddress << std::endl;
        std::cout << "Raw Data Size: " << sectionHeaders[i].SizeOfRawData << std::endl;
    }
    std::cout << "\n" << std::endl;
    DWORD importDirectoryRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    std::cout << "Import Table RVA: " << std::hex << importDirectoryRVA << std::endl;


    //now that the PE has been parsed, use create-process api to execute
    LPCSTR exeFilePath = R"(C:\Windows\System32\PING.EXE)";

    // Initialize the STARTUPINFO and PROCESS_INFORMATION structures
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create a new process for the executable
    if (!CreateProcess(
        exeFilePath,   // Path to executable
        "8.8.8.8",          // Command line arguments (NULL if none)
        NULL,          // Process handle not inheritable
        NULL,          // Thread handle not inheritable
        FALSE,         // Set handle inheritance to FALSE
        0,             // No creation flags
        NULL,          // Use parent's environment block
        NULL,          // Use parent's starting directory
        &si,           // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
    ) {
        std::cerr << "CreateProcess failed. Error: " << GetLastError() << std::endl;
        return -1;
    }
    // Wait until the process exits
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::cout << "Process executed successfully!" << std::endl;


    return 0;
}
