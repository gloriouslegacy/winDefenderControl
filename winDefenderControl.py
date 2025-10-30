import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import os
import sys
import ctypes
import subprocess
import threading

# --- 다크 테마 색상 설정 ---
DARK_BG = "#1E1E1E"       
DARK_CARD = "#2D2D30"
DARK_FG = "#FFFFFF"       
DARK_BUTTON = "#3C3C3C"   
DARK_BUTTON_HOVER = "#505050" 
ACCENT_ENABLE = "#4CAF50" 
ACCENT_DISABLE = "#F44336" 
ACCENT_OPEN = "#2196F3"    
ACCENT_EXCLUSION = "#FF9800"
WARNING_FG = "#FFD700"
STATUS_ON = "#4CAF50"
STATUS_OFF = "#F44336"
STATUS_UNKNOWN = "#9E9E9E"
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

# --- 상태 확인 함수 ---
def check_defender_status():
    """Windows Defender 실시간 보호 상태 확인"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-Command", "(Get-MpPreference).DisableRealtimeMonitoring"],
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            output = result.stdout.strip().lower()
            if output == "false":
                return "ON"
            elif output == "true":
                return "OFF"
        return "UNKNOWN"
    except:
        return "UNKNOWN"

def check_tamper_protection_status():
    """변조 보호 상태 확인"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-Command", "(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection"],
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            output = result.stdout.strip()
            if output in ["5", "1"]:
                return "ON"
            elif output == "0":
                return "OFF"
        return "UNKNOWN"
    except:
        return "UNKNOWN"

# --- 기능 함수 ---
def execute_powershell_command(powershell_command):
    """콘솔 창 없이 PowerShell 명령 실행"""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-Command", powershell_command],
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0, result.stderr
    except Exception as e:
        return False, str(e)

def enable_defender():
    """실시간 보호 활성화"""
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $false; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -ErrorAction SilentlyContinue"
    success, error = execute_powershell_command(powershell_command)
    
    messagebox.showinfo(
        "Defender Control", 
        "Windows Defender 실시간 보호가 활성화되었습니다.\n\n"
        "상태를 확인하려면 '새로고침' 버튼을 클릭하세요."
    )
    refresh_status()

def disable_defender():
    """실시간 보호 비활성화"""
    # 변조 보호 상태 확인
    tamper_status = check_tamper_protection_status()
    
    if tamper_status == "ON":
        messagebox.showwarning(
            "변조 보호 활성화됨", 
            "⚠️ 실시간 보호 제어를 사용하려면\n"
            "변조 보호를 비활성화(OFF)해야 합니다.\n\n"
            "📍 설정 방법:\n"
            "Windows 보안 → 바이러스 및 위협 방지 설정\n"
            "→ 변조 보호 OFF"
        )
        return
    
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $true; New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -Type DWORD -Force"
    success, error = execute_powershell_command(powershell_command)
    
    messagebox.showinfo(
        "Defender Control", 
        "Windows Defender 실시간 보호가 비활성화되었습니다.\n\n"
        "상태를 확인하려면 '새로고침' 버튼을 클릭하세요."
    )
    refresh_status()

def add_exclusion_folder():
    """제외 폴더 추가"""
    folder_path = filedialog.askdirectory(title="제외할 폴더 선택")
    if folder_path:
        powershell_command = f"Add-MpPreference -ExclusionPath '{folder_path}'"
        success, error = execute_powershell_command(powershell_command)
        
        if success:
            messagebox.showinfo("제외 목록 추가", f"다음 경로가 제외 목록에 추가되었습니다:\n\n{folder_path}")
        else:
            messagebox.showerror("Error", f"제외 목록 추가 실패:\n{error}")

def add_exclusion_file():
    """제외 파일 추가"""
    file_path = filedialog.askopenfilename(title="제외할 파일 선택")
    if file_path:
        powershell_command = f"Add-MpPreference -ExclusionPath '{file_path}'"
        success, error = execute_powershell_command(powershell_command)
        
        if success:
            messagebox.showinfo("제외 목록 추가", f"다음 파일이 제외 목록에 추가되었습니다:\n\n{file_path}")
        else:
            messagebox.showerror("Error", f"제외 목록 추가 실패:\n{error}")

def view_exclusions():
    """현재 제외 목록 보기"""
    powershell_command = "(Get-MpPreference).ExclusionPath"
    
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        result = subprocess.run(
            ["powershell", "-Command", powershell_command],
            startupinfo=startupinfo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.stdout.strip():
            exclusions = result.stdout.strip()
            messagebox.showinfo("현재 제외 목록", f"제외된 경로:\n\n{exclusions}")
        else:
            messagebox.showinfo("현재 제외 목록", "현재 제외 목록이 비어있습니다.")
    except Exception as e:
        messagebox.showerror("Error", f"제외 목록 조회 실패: {e}")

def open_exclusion_settings():
    """Windows 보안의 제외 설정 페이지 열기"""
    messagebox.showinfo(
        "제외 설정 안내", 
        "Windows 보안 설정이 열립니다.\n\n"
        "📍 다음 단계를 따라주세요:\n"
        "1. '바이러스 및 위협 방지' 클릭\n"
        "2. 아래로 스크롤하여\n"
        "3. '제외 추가 또는 제거' 클릭"
    )
    os.system("start windowsdefender://threatsettings/")

def open_defender_security_center():
    """Windows 보안 앱 열기"""
    os.system("start windowsdefender://")

def refresh_status():
    """상태 새로고침 (비동기)"""
    def update():
        status_label.config(text="상태 확인 중...")
        realtime_status = check_defender_status()
        tamper_status = check_tamper_protection_status()
        
        # 실시간 보호 상태 업데이트
        if realtime_status == "ON":
            realtime_indicator.config(bg=STATUS_ON)
            realtime_text.config(text="실시간 보호: ON", fg=STATUS_ON)
        elif realtime_status == "OFF":
            realtime_indicator.config(bg=STATUS_OFF)
            realtime_text.config(text="실시간 보호: OFF", fg=STATUS_OFF)
        else:
            realtime_indicator.config(bg=STATUS_UNKNOWN)
            realtime_text.config(text="실시간 보호: 알 수 없음", fg=STATUS_UNKNOWN)
        
        # 변조 보호 상태 업데이트
        if tamper_status == "ON":
            tamper_indicator.config(bg=STATUS_ON)
            tamper_text.config(text="변조 보호: ON", fg=STATUS_ON)
        elif tamper_status == "OFF":
            tamper_indicator.config(bg=STATUS_OFF)
            tamper_text.config(text="변조 보호: OFF", fg=STATUS_OFF)
        else:
            tamper_indicator.config(bg=STATUS_UNKNOWN)
            tamper_text.config(text="변조 보호: 알 수 없음", fg=STATUS_UNKNOWN)
        
        status_label.config(text="마지막 업데이트: 방금 전")
    
    thread = threading.Thread(target=update, daemon=True)
    thread.start()

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
    root.title("Windows Defender Control - Dashboard")
    root.geometry("500x650") 
    root.resizable(False, False)

    try:
        root.iconbitmap(ICON_FILE) 
    except tk.TclError:
        print(f"Warning: Could not load icon from {ICON_FILE}")

    root.configure(bg=DARK_BG)

    # ============ 상단: 타이틀 ============
    title_frame = tk.Frame(root, bg=DARK_BG)
    title_frame.pack(pady=(15, 10), fill=tk.X)
    
    title_label = tk.Label(
        title_frame, 
        text="🛡️ Windows Defender Control", 
        font=("Segoe UI", 16, "bold"), 
        bg=DARK_BG, 
        fg=DARK_FG
    )
    title_label.pack()

    # ============ 상태 대시보드 카드 ============
    status_card = tk.Frame(root, bg=DARK_CARD, relief=tk.RAISED, bd=1)
    status_card.pack(pady=10, padx=20, fill=tk.BOTH)
    
    status_title = tk.Label(
        status_card, 
        text="📊 현재 상태", 
        font=("Segoe UI", 12, "bold"), 
        bg=DARK_CARD, 
        fg=DARK_FG
    )
    status_title.pack(pady=(10, 5))
    
    # 실시간 보호 상태
    realtime_frame = tk.Frame(status_card, bg=DARK_CARD)
    realtime_frame.pack(pady=5)
    
    realtime_indicator = tk.Label(
        realtime_frame, 
        text="  ", 
        bg=STATUS_UNKNOWN, 
        width=2, 
        relief=tk.RAISED
    )
    realtime_indicator.pack(side=tk.LEFT, padx=(10, 10))
    
    realtime_text = tk.Label(
        realtime_frame, 
        text="실시간 보호: 확인 중...", 
        font=("Segoe UI", 11), 
        bg=DARK_CARD, 
        fg=STATUS_UNKNOWN
    )
    realtime_text.pack(side=tk.LEFT)
    
    # 변조 보호 상태
    tamper_frame = tk.Frame(status_card, bg=DARK_CARD)
    tamper_frame.pack(pady=5)
    
    tamper_indicator = tk.Label(
        tamper_frame, 
        text="  ", 
        bg=STATUS_UNKNOWN, 
        width=2, 
        relief=tk.RAISED
    )
    tamper_indicator.pack(side=tk.LEFT, padx=(10, 10))
    
    tamper_text = tk.Label(
        tamper_frame, 
        text="변조 보호: 확인 중...", 
        font=("Segoe UI", 11), 
        bg=DARK_CARD, 
        fg=STATUS_UNKNOWN
    )
    tamper_text.pack(side=tk.LEFT)
    
    # 새로고침 버튼
    btn_refresh = tk.Button(
        status_card, 
        text="🔄 새로고침", 
        command=refresh_status, 
        width=20, 
        height=1,
        bg="#607D8B", 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_refresh.pack(pady=(5, 10))
    btn_refresh.bind("<Enter>", lambda e: on_enter(e, btn_refresh, "#78909C"))
    btn_refresh.bind("<Leave>", lambda e: on_leave(e, btn_refresh, "#607D8B"))
    
    status_label = tk.Label(
        status_card, 
        text="'새로고침'을 눌러 상태를 확인하세요", 
        font=("Segoe UI", 8), 
        bg=DARK_CARD, 
        fg="#AAAAAA"
    )
    status_label.pack(pady=(0, 10))

    # ============ 제어 카드 ============
    control_card = tk.Frame(root, bg=DARK_CARD, relief=tk.RAISED, bd=1)
    control_card.pack(pady=10, padx=20, fill=tk.BOTH)
    
    control_title = tk.Label(
        control_card, 
        text="⚙️ 실시간 보호 제어", 
        font=("Segoe UI", 12, "bold"), 
        bg=DARK_CARD, 
        fg=DARK_FG
    )
    control_title.pack(pady=(10, 10))
    
    btn_enable = tk.Button(
        control_card, 
        text="✅ Enable (실시간 보호 ON)", 
        command=enable_defender, 
        width=30, 
        height=1, 
        bg=ACCENT_ENABLE, 
        fg=DARK_FG, 
        font=("Segoe UI", 10, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_enable.pack(pady=5)
    btn_enable.bind("<Enter>", lambda e: on_enter(e, btn_enable, "#66BB6A"))
    btn_enable.bind("<Leave>", lambda e: on_leave(e, btn_enable, ACCENT_ENABLE))

    btn_disable = tk.Button(
        control_card, 
        text="❌ Disable (실시간 보호 OFF)", 
        command=disable_defender, 
        width=30, 
        height=1, 
        bg=ACCENT_DISABLE, 
        fg=DARK_FG, 
        font=("Segoe UI", 10, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_disable.pack(pady=(5, 10))
    btn_disable.bind("<Enter>", lambda e: on_enter(e, btn_disable, "#E57373"))
    btn_disable.bind("<Leave>", lambda e: on_leave(e, btn_disable, ACCENT_DISABLE))

    # ============ 제외 목록 관리 카드 ============
    exclusion_card = tk.Frame(root, bg=DARK_CARD, relief=tk.RAISED, bd=1)
    exclusion_card.pack(pady=10, padx=20, fill=tk.BOTH)
    
    exclusion_title = tk.Label(
        exclusion_card, 
        text="📁 제외 목록 관리", 
        font=("Segoe UI", 12, "bold"), 
        bg=DARK_CARD, 
        fg=DARK_FG
    )
    exclusion_title.pack(pady=(10, 10))
    
    btn_add_folder = tk.Button(
        exclusion_card, 
        text="➕ 폴더 제외 추가", 
        command=add_exclusion_folder, 
        width=30, 
        height=1, 
        bg=ACCENT_EXCLUSION, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_add_folder.pack(pady=3)
    btn_add_folder.bind("<Enter>", lambda e: on_enter(e, btn_add_folder, "#FFB74D"))
    btn_add_folder.bind("<Leave>", lambda e: on_leave(e, btn_add_folder, ACCENT_EXCLUSION))

    btn_add_file = tk.Button(
        exclusion_card, 
        text="➕ 파일 제외 추가", 
        command=add_exclusion_file, 
        width=30, 
        height=1, 
        bg=ACCENT_EXCLUSION, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_add_file.pack(pady=3)
    btn_add_file.bind("<Enter>", lambda e: on_enter(e, btn_add_file, "#FFB74D"))
    btn_add_file.bind("<Leave>", lambda e: on_leave(e, btn_add_file, ACCENT_EXCLUSION))

    btn_view_exclusions = tk.Button(
        exclusion_card, 
        text="👁️ 제외 목록 보기", 
        command=view_exclusions, 
        width=30, 
        height=1, 
        bg=ACCENT_EXCLUSION, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_view_exclusions.pack(pady=3)
    btn_view_exclusions.bind("<Enter>", lambda e: on_enter(e, btn_view_exclusions, "#FFB74D"))
    btn_view_exclusions.bind("<Leave>", lambda e: on_leave(e, btn_view_exclusions, ACCENT_EXCLUSION))

    btn_open_exclusion = tk.Button(
        exclusion_card, 
        text="🔧 제외 설정 바로가기", 
        command=open_exclusion_settings, 
        width=30, 
        height=1, 
        bg=ACCENT_EXCLUSION, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_open_exclusion.pack(pady=(3, 10))
    btn_open_exclusion.bind("<Enter>", lambda e: on_enter(e, btn_open_exclusion, "#FFB74D"))
    btn_open_exclusion.bind("<Leave>", lambda e: on_leave(e, btn_open_exclusion, ACCENT_EXCLUSION))

    # ============ 하단 버튼 ============
    bottom_frame = tk.Frame(root, bg=DARK_BG)
    bottom_frame.pack(pady=(10, 15))
    
    btn_open = tk.Button(
        bottom_frame, 
        text="🛡️ Windows 보안 열기", 
        command=open_defender_security_center, 
        width=20, 
        height=1, 
        bg=ACCENT_OPEN, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_open.pack(side=tk.LEFT, padx=5)
    btn_open.bind("<Enter>", lambda e: on_enter(e, btn_open, "#42A5F5"))
    btn_open.bind("<Leave>", lambda e: on_leave(e, btn_open, ACCENT_OPEN))

    btn_exit = tk.Button(
        bottom_frame, 
        text="❌ 종료", 
        command=app_exit, 
        width=20, 
        height=1,
        bg=DARK_BUTTON, 
        fg=DARK_FG, 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT
    )
    btn_exit.pack(side=tk.LEFT, padx=5)
    btn_exit.bind("<Enter>", lambda e: on_enter(e, btn_exit, DARK_BUTTON_HOVER))
    btn_exit.bind("<Leave>", lambda e: on_leave(e, btn_exit, DARK_BUTTON))

    # 초기 상태 확인
    refresh_status()

    root.mainloop()