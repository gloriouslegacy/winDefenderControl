import tkinter as tk
from tkinter import messagebox
import os
import sys
import ctypes
import subprocess

# --- 다크 테마 색상 설정 ---
DARK_BG = "#2B2B2B"       
DARK_FG = "#FFFFFF"       
DARK_BUTTON = "#3C3C3C"   
DARK_BUTTON_HOVER = "#505050" 
ACCENT_ENABLE = "#4CAF50" 
ACCENT_DISABLE = "#F44336" 
ACCENT_OPEN = "#2196F3"    
WARNING_FG = "#FFD700" 
# ---------------------------

# --- 아이콘 경로 설정 함수 ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
# -----------------------------

ICON_FILE = resource_path("icon/winDefender.ico") 

# --- 관리자 권한 확인 및 재실행 ---
def run_as_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, __file__, None, 1
        )
        sys.exit(0)

# --- 기능 함수: 레지스트리 기반 ---

def execute_powershell_command(powershell_command):
    """콘솔 창 없이 PowerShell 명령 실행"""
    # subprocess.Popen을 사용하여 콘솔 창을 숨김(CREATE_NO_WINDOW 플래그 사용)
    # 윈도우 환경에서만 작동, powershell.exe 경로를 직접 지정
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE # 창 숨기기

        subprocess.Popen(
            ["powershell", "-Command", powershell_command],
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except Exception as e:
        messagebox.showerror("Error", f"PowerShell command failed: {e}")

def enable_defender():
    """레지스트리를 수정하여 Windows Defender 실시간 보호 활성화"""
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $false; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 0 -Type DWORD -Force"
    
    execute_powershell_command(powershell_command) # 수정된 함수 사용
    
    messagebox.showinfo(
        "Defender Control", 
        "Windows Defender가 활성화되었습니다.\n\n"
        "변경 사항이 즉시 반영되지 않으면 시스템을 다시 시작해주세요."
    )

def disable_defender():
    """레지스트리를 수정하여 Windows Defender 실시간 보호를 비활성화"""
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $true; New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -Type DWORD -Force"
    
    execute_powershell_command(powershell_command) # 수정된 함수 사용
    
    messagebox.showinfo(
        "Defender Control", 
        "Windows Defender가 비활성화되었습니다.\n\n"
        "변경 사항이 즉시 반영되지 않으면 시스템을 다시 시작해주세요."
    )
    

def open_defender_security_center():
    """Windows 보안 앱을 엽니다."""
    os.system("start windowsdefender://")
    
def app_exit():
    sys.exit()

# --- 버튼 호버 효과 함수 ---
def on_enter(e, button, color):
    button['background'] = color
    
def on_leave(e, button, original_color):
    button['background'] = original_color

# --- 메인 실행 ---
if __name__ == "__main__":
    run_as_admin()

    root = tk.Tk()
    root.title("Windows Defender Control")
    root.geometry("420x280") 
    root.resizable(False, False)

    try:
        root.iconbitmap(ICON_FILE) 
    except tk.TclError:
        print(f"Warning: Could not load icon from {ICON_FILE}")

    root.configure(bg=DARK_BG) 

    # --- 1. 변조 보호 안내 메시지 레이블 추가 ---
    warning_text = (
        "⚠Notice: Enable/Disable (권한) 오류가 발생하면,\n"
        "Windows 보안 → 바이러스 및 위협방지 → 변조 보호(Tamper Protection)\n"
        "비활성화 후 실행해야 합니다."
    )
    
    warning_label = tk.Label(
        root, 
        text=warning_text, 
        font=("Segoe UI", 8), 
        bg=DARK_BG, 
        fg=WARNING_FG, 
        justify=tk.CENTER
    )
    warning_label.pack(pady=(10, 5))
    # -----------------------------------------------

    # 제목 레이블
    title_label = tk.Label(
        root, 
        text="Windows Defender Control", 
        font=("Segoe UI", 13, "bold"), 
        bg=DARK_BG, 
        fg=DARK_FG
    )
    title_label.pack(pady=(5, 15)) # 패딩 조정

    # ------------------ 버튼 생성  ------------------
    btn_enable = tk.Button(
        root, text="Enable", command=enable_defender, width=28, height=1, 
        bg=ACCENT_ENABLE, fg=DARK_FG, font=("Segoe UI", 10, "bold"), bd=0, relief=tk.FLAT
    )
    btn_enable.pack(pady=5)
    btn_enable.bind("<Enter>", lambda e: on_enter(e, btn_enable, "#66BB6A"))
    btn_enable.bind("<Leave>", lambda e: on_leave(e, btn_enable, ACCENT_ENABLE))

    btn_disable = tk.Button(
        root, text="Disable", command=disable_defender, width=28, height=1, 
        bg=ACCENT_DISABLE, fg=DARK_FG, font=("Segoe UI", 10, "bold"), bd=0, relief=tk.FLAT
    )
    btn_disable.pack(pady=5)
    btn_disable.bind("<Enter>", lambda e: on_enter(e, btn_disable, "#E57373"))
    btn_disable.bind("<Leave>", lambda e: on_leave(e, btn_disable, ACCENT_DISABLE))

    btn_open = tk.Button(
        root, text="Open Defender Security Center", command=open_defender_security_center, 
        width=28, height=1, bg=ACCENT_OPEN, fg=DARK_FG, font=("Segoe UI", 10, "bold"), bd=0, relief=tk.FLAT
    )
    btn_open.pack(pady=5)
    btn_open.bind("<Enter>", lambda e: on_enter(e, btn_open, "#42A5F5"))
    btn_open.bind("<Leave>", lambda e: on_leave(e, btn_open, ACCENT_OPEN))

    btn_exit = tk.Button(
        root, text="Exit", command=app_exit, width=14, height=1,
        bg=DARK_BUTTON, fg=DARK_FG, font=("Segoe UI", 10), bd=0, relief=tk.FLAT
    )
    btn_exit.pack(pady=(15, 10))
    btn_exit.bind("<Enter>", lambda e: on_enter(e, btn_exit, DARK_BUTTON_HOVER))
    btn_exit.bind("<Leave>", lambda e: on_leave(e, btn_exit, DARK_BUTTON))
    # -----------------------------------------------------

    root.mainloop()