; ARP Guard Installer Script
; NSIS (Nullsoft Scriptable Install System) template
; This script will install ARP Guard on Windows systems

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "WinVer.nsh"

; General configuration
Name "ARP Guard"
OutFile "ARPGuard-Setup.exe"
Unicode True

; Default installation directory
InstallDir "$PROGRAMFILES\ARP Guard"
InstallDirRegKey HKLM "Software\ARP Guard" "Install_Dir"

; Request application privileges
RequestExecutionLevel admin

; Variables
Var StartMenuFolder

; Interface settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\modern-wizard.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\modern-header.bmp"
!define MUI_COMPONENTSPAGE_SMALLDESC

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY

; Start Menu Folder Page Configuration
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM" 
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\ARP Guard" 
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Language settings
!insertmacro MUI_LANGUAGE "English"

; Version Information
VIProductVersion "0.3.0.0"
VIAddVersionKey "ProductName" "ARP Guard"
VIAddVersionKey "CompanyName" "ARPGuard Security"
VIAddVersionKey "LegalCopyright" "© 2025 ARPGuard Security"
VIAddVersionKey "FileDescription" "ARP Guard Network Security Tool"
VIAddVersionKey "FileVersion" "0.3.0"
VIAddVersionKey "ProductVersion" "0.3.0"

; Installation Sections
Section "ARP Guard Core (required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"
  
  ; Extract files
  File /r "dist\*.*"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
  ; Write registry keys
  WriteRegStr HKLM "Software\ARP Guard" "Install_Dir" "$INSTDIR"
  
  ; Write registry keys for uninstall
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "DisplayName" "ARP Guard"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "DisplayIcon" "$INSTDIR\app\resources\icon.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "DisplayVersion" "0.3.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "Publisher" "ARPGuard Security"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "URLInfoAbout" "https://arpguard.com"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard" "NoRepair" 1
  
  ; Add to Path
  EnVar::AddValue "PATH" "$INSTDIR\bin"
  
  ; Create Start Menu entries
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
    CreateShortcut "$SMPROGRAMS\$StartMenuFolder\ARP Guard.lnk" "$INSTDIR\bin\arpguard.exe"
    CreateShortcut "$SMPROGRAMS\$StartMenuFolder\Uninstall ARP Guard.lnk" "$INSTDIR\uninstall.exe"
  !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

Section "Python Dependencies" SecPython
  SetOutPath "$INSTDIR\python"
  File /r "python\*.*"
  
  ; Install Python if not present
  DetailPrint "Checking for Python installation..."
  nsExec::ExecToLog '"$INSTDIR\python\check_python.bat"'
  Pop $0
  ${If} $0 != "0"
    DetailPrint "Python not found or version too old. Installing Python..."
    nsExec::ExecToLog '"$INSTDIR\python\install_python.bat"'
  ${Else}
    DetailPrint "Python already installed and meets version requirements."
  ${EndIf}
  
  ; Install required packages
  DetailPrint "Installing Python dependencies..."
  nsExec::ExecToLog '"$INSTDIR\python\install_dependencies.bat"'
SectionEnd

Section "Windows Service" SecService
  DetailPrint "Installing ARP Guard as a Windows service..."
  nsExec::ExecToLog '"$INSTDIR\bin\arpguard.exe" --install-service'
  
  ; Set service to start automatically
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\ARPGuard" "Start" 2
SectionEnd

Section "Desktop Shortcut" SecDesktop
  CreateShortCut "$DESKTOP\ARP Guard.lnk" "$INSTDIR\bin\arpguard.exe"
SectionEnd

; Descriptions
LangString DESC_SecCore ${LANG_ENGLISH} "Core files required for ARP Guard to function."
LangString DESC_SecPython ${LANG_ENGLISH} "Python runtime and dependencies required by ARP Guard."
LangString DESC_SecService ${LANG_ENGLISH} "Install ARP Guard as a Windows service (starts automatically with Windows)."
LangString DESC_SecDesktop ${LANG_ENGLISH} "Create a shortcut on the desktop."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} $(DESC_SecCore)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPython} $(DESC_SecPython)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} $(DESC_SecDesktop)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Silent install options
Function .onInit
  ${If} ${Silent}
    ; Set default values for silent installation
    StrCpy $StartMenuFolder "ARP Guard"
  ${EndIf}
  
  ; Check Windows version
  ${IfNot} ${AtLeastWin7}
    MessageBox MB_OK|MB_ICONSTOP "This application requires Windows 7 or later."
    Abort
  ${EndIf}
FunctionEnd

; Uninstaller Section
Section "Uninstall"
  ; Stop and remove service
  DetailPrint "Stopping and removing ARP Guard service..."
  nsExec::ExecToLog '"$INSTDIR\bin\arpguard.exe" --remove-service'
  
  ; Remove from PATH
  EnVar::DeleteValue "PATH" "$INSTDIR\bin"
  
  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ARP Guard"
  DeleteRegKey HKLM "Software\ARP Guard"
  
  ; Remove Start Menu items
  !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
  Delete "$SMPROGRAMS\$StartMenuFolder\ARP Guard.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall ARP Guard.lnk"
  RMDir "$SMPROGRAMS\$StartMenuFolder"
  
  ; Remove desktop shortcut
  Delete "$DESKTOP\ARP Guard.lnk"
  
  ; Remove files and directories
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR"
SectionEnd 