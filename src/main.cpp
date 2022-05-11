#include <iostream>
#include <string>
#include <memory>
#include <filesystem>
#include <sstream>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj_core.h>

bool IsElevated() {
  bool elevated = false;
  HANDLE process_token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&process_token)) {
    TOKEN_ELEVATION elevation;
    DWORD cb_size = sizeof(TOKEN_ELEVATION);
    if(GetTokenInformation(process_token, TokenElevation, &elevation, sizeof(elevation), &cb_size)) {
      elevated = elevation.TokenIsElevated;
    }
  }

  if (process_token)
    CloseHandle(process_token);

  return elevated;
}

void CreateConsole() {
  if (!AttachConsole(GetCurrentProcessId()))
    AllocConsole();
  SetConsoleTitle("Copy To Clipboard");
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
  SetConsoleCP(CP_UTF8);
  SetConsoleOutputCP(CP_UTF8);

  freopen("CONOUT$", "w", stdout);
  freopen("CONOUT$", "w", stderr);
  freopen("CONIN$", "r", stdin);
}

void RestartExplorer() {
  std::cout << "Explorer needs to be restarted to apply changes.\n";
  std::cout << "Restart Explorer? (y/n): ";
  std::string input;
  std::getline(std::cin, input);

  if (input == "y" || input == "Y") {
    system("taskkill /f /im explorer.exe && explorer.exe");
  }
}

std::shared_ptr<HKEY> OpenRegistryKey(HKEY key_handle, const std::string& path, REGSAM access) {
  auto key = std::make_shared<HKEY>();
  RegOpenKeyEx(key_handle, path.c_str(), 0, access, key.get());

  return key;
}

std::shared_ptr<HKEY> CreateRegistryKey(HKEY key_handle, const std::string& path, REGSAM access) {
  auto key = std::make_shared<HKEY>();
  RegCreateKeyEx(key_handle, path.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, access, nullptr, key.get(), nullptr);

  return key;
}

LSTATUS SetRegistryValue(HKEY key_handle, const std::string& value_name, DWORD type, const BYTE* value, DWORD value_size) {
  return RegSetValueEx(key_handle, value_name.c_str(), 0, type, value, value_size);
}

LSTATUS SetRegistryKeyValue(HKEY key_handle, LPCSTR sub_key, const std::string& value_name, DWORD type, const BYTE* value, DWORD value_size) {
  return RegSetKeyValue(key_handle, sub_key, value_name.c_str(), type, value, value_size);
}

LSTATUS DeleteRegistryKey(HKEY key_handle, const std::string& path) {
  return RegDeleteKeyEx(key_handle, path.c_str(), KEY_WOW64_64KEY, 0);
}

#define REGISTRY_FILE "*\\shell"
#define REGISTRY_DIRECTORY "Directory\\shell"
#define SUB_KEY "CopyPath"
#define CONTEXT_MENU_NAME (const char*)"Copy path to clipboard"

void InstallRegistry(std::shared_ptr<HKEY> parent, const std::string& name, const std::string& icon, const std::string& command) {
  auto key = parent;

  key = CreateRegistryKey(*key, SUB_KEY, KEY_ALL_ACCESS);

  SetRegistryValue(*key, "", REG_SZ, (BYTE*)CONTEXT_MENU_NAME, strlen(CONTEXT_MENU_NAME) + 1);
  SetRegistryValue(*key, "Icon", REG_SZ, (BYTE*)icon.c_str(), icon.length() + 1);

  SetRegistryKeyValue(*key, "command", "", REG_SZ, (BYTE*)command.c_str(), command.size() + 1);

  RegCloseKey(*key);
}

void Install(const std::string& exe_path) {
  auto program_files = std::make_unique<PWSTR>();
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, NULL, nullptr, program_files.get()))) {

    std::filesystem::path curr_path = exe_path;
    std::filesystem::path install_path = *program_files;
    install_path /= SUB_KEY;

    if (!std::filesystem::is_directory(install_path))
      std::filesystem::create_directories(install_path);

    install_path /= curr_path.filename();

    if (std::filesystem::is_regular_file(install_path))
      std::filesystem::remove(install_path);
    std::filesystem::copy_file(exe_path, install_path);

    auto key = std::shared_ptr<HKEY>();
    std::stringstream command;
    command << '"' << install_path.string() << '"' << R"( "%1")";

    key = OpenRegistryKey(HKEY_CLASSES_ROOT, REGISTRY_FILE, KEY_ALL_ACCESS);
    InstallRegistry(key, curr_path.filename().string(), install_path.string(), command.str());
    RegCloseKey(*key);

    key = OpenRegistryKey(HKEY_CLASSES_ROOT, REGISTRY_DIRECTORY, KEY_ALL_ACCESS);
    InstallRegistry(key, curr_path.filename().string(), install_path.string(), command.str());
    RegCloseKey(*key);

    RestartExplorer();
  } else {
    std::cout << "Failed to install.";
    char c;
    std::cin >> c;
    exit(EXIT_FAILURE);
  }
}

void Uninstall() {
  auto key = std::shared_ptr<HKEY>();

  key = OpenRegistryKey(HKEY_CLASSES_ROOT, REGISTRY_FILE, KEY_ALL_ACCESS);
  RegDeleteTree(*key, SUB_KEY);
  RegCloseKey(*key);

  key = OpenRegistryKey(HKEY_CLASSES_ROOT, REGISTRY_DIRECTORY, KEY_ALL_ACCESS);
  RegDeleteTree(*key, SUB_KEY);
  RegCloseKey(*key);

  RestartExplorer();
}

void InstallOrUninstall(const std::string& exe_path) {
  CreateConsole();

  if (!IsElevated()) {
    std::cout << "To install/uninstall, run the program as administrator...";
    std::string tmp;
    std::getline(std::cin, tmp);
    exit(EXIT_SUCCESS);
  }

  try {
    ask_for_install_or_uninstall:
    std::cout << "Install or uninstall? (i/u): ";

    std::string input;
    std::getline(std::cin, input);
    if (input == "i" || input == "I") {
      Install(exe_path);
    } else if (input == "u" || input == "U") {
      Uninstall();
    } else {
      goto ask_for_install_or_uninstall;
    }
  } catch (std::runtime_error& e) {
    std::cout << e.what() << std::endl;
  } catch (...) {
    std::cout << "Unknown error. While installing/uninstalling" << std::endl;
  }
}

void CopyPath(const std::string& path) {
  if (OpenClipboard(nullptr)) {
    const char* path_cstr = path.c_str();
    size_t path_size = path.size();

    HGLOBAL path_mem = GlobalAlloc(GMEM_MOVEABLE, path_size + 1);
    if (path_mem) {
      memcpy(GlobalLock(path_mem), path_cstr, path_size + 1);
      GlobalUnlock(path_mem);
      EmptyClipboard();

      SetClipboardData(CF_TEXT, path_mem);
    }

    CloseClipboard();
  }
}

int main(int argc, char* argv[]) {
  switch(argc) {
    case 1:
      InstallOrUninstall(argv[0]);
      break;
    case 2:
      CopyPath(argv[1]);
      break;
    default:
      return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, char*, int nShowCmd) {
  return main(__argc, __argv);
}
