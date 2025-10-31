import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import os
import sys
import ctypes
import subprocess
import threading

# --- DefenderUI 스타일 색상 설정 ---
DARK_BG = "#1a1d23"  # 메인 배경
DARK_CARD = "#252932"  # 카드 배경
DARK_FG = "#FFFFFF"  # 텍스트
LIGHT_GRAY = "#7f8c8d"  # 회색 텍스트
ACCENT_BLUE = "#3d8bfd"  # 파란색 강조
ACCENT_GREEN = "#2ecc71"  # 녹색 (ON)
ACCENT_RED = "#e74c3c"  # 빨간색 (OFF)
ACCENT_ORANGE = "#f39c12"  # 주황색
BUTTON_HOVER = "#4a9eff"
STATUS_ON = "#2ecc71"
STATUS_OFF = "#e74c3c"
STATUS_UNKNOWN = "#95a5a6"
BORDER_COLOR = "#34383f"
# ---------------------------

# --- 아이콘 경로 설정 ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

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

def show_custom_info(title, message):
    """정보 메시지"""
    msg_window = tk.Toplevel(root)
    msg_window.title(title)
    msg_window.geometry("400x575")
    msg_window.configure(bg=DARK_CARD)
    msg_window.resizable(True, True)
    
    try:
        msg_window.iconbitmap(ICON_FILE)
    except:
        pass
    
    # 텍스트 박스 프레임
    text_frame = tk.Frame(msg_window, bg=DARK_CARD)
    text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(20, 10))
    
    # 스크롤바
    scrollbar = tk.Scrollbar(text_frame, bg=DARK_CARD)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # 텍스트 박스
    text_box = tk.Text(
        text_frame,
        font=("Segoe UI", 10),
        bg=DARK_CARD,
        fg=DARK_FG,
        wrap=tk.WORD,
        yscrollcommand=scrollbar.set,
        relief=tk.FLAT,
        highlightthickness=0,
        padx=10,
        pady=10
    )
    text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=text_box.yview)
    
    # 메시지 삽입
    text_box.insert("1.0", message)
    text_box.config(state=tk.DISABLED)  # 읽기 전용
    
    # 확인 버튼
    ok_button = tk.Button(
        msg_window,
        text="확인",
        command=msg_window.destroy,
        bg=ACCENT_BLUE,
        fg=DARK_FG,
        font=("Segoe UI", 10, "bold"),
        width=15,
        height=1,
        bd=0,
        relief=tk.FLAT,
        cursor="hand2"
    )
    ok_button.pack(pady=(0, 15))
    
    def on_hover(e):
        ok_button['bg'] = BUTTON_HOVER
    def on_leave(e):
        ok_button['bg'] = ACCENT_BLUE
    
    ok_button.bind("<Enter>", on_hover)
    ok_button.bind("<Leave>", on_leave)
    
    msg_window.transient(root)
    msg_window.grab_set()
    msg_window.focus_set()

def show_custom_warning(title, message):
    """경고 메시지"""
    msg_window = tk.Toplevel(root)
    msg_window.title(title)
    msg_window.geometry("450x290")
    msg_window.configure(bg=DARK_CARD)
    msg_window.resizable(True, True)
    
    # 아이콘 설정
    try:
        msg_window.iconbitmap(ICON_FILE)
    except:
        pass
    
    # 경고 아이콘
    warning_label = tk.Label(
        msg_window,
        text="⚠",
        font=("Segoe UI", 30),
        bg=DARK_CARD,
        fg=ACCENT_ORANGE
    )
    warning_label.pack(pady=(20, 10))
    
    # 메시지 레이블
    msg_label = tk.Label(
        msg_window,
        text=message,
        font=("Segoe UI", 10),
        bg=DARK_CARD,
        fg=DARK_FG,
        wraplength=400,
        justify=tk.LEFT
    )
    msg_label.pack(pady=10, padx=20)
    
    # 확인 버튼
    ok_button = tk.Button(
        msg_window,
        text="확인",
        command=msg_window.destroy,
        bg=ACCENT_ORANGE,
        fg=DARK_FG,
        font=("Segoe UI", 10, "bold"),
        width=15,
        height=1,
        bd=0,
        relief=tk.FLAT,
        cursor="hand2"
    )
    ok_button.pack(pady=10)
    
    def on_hover(e):
        ok_button['bg'] = "#f5ab2e"
    def on_leave(e):
        ok_button['bg'] = ACCENT_ORANGE
    
    ok_button.bind("<Enter>", on_hover)
    ok_button.bind("<Leave>", on_leave)
    
    msg_window.transient(root)
    msg_window.grab_set()
    msg_window.focus_set()

def enable_defender():
    """실시간 보호 활성화"""
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $false; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -ErrorAction SilentlyContinue"
    success, error = execute_powershell_command(powershell_command)
    
    show_custom_info(
        "Defender Control", 
        "Windows Defender 실시간 보호가 활성화되었습니다.\n\n상태를 확인하려면 '새로고침' 버튼을 클릭하세요."
    )
    refresh_status()

def disable_defender():
    """실시간 보호 비활성화"""
    tamper_status = check_tamper_protection_status()
    
    if tamper_status == "ON":
        show_custom_warning(
            "변조 보호 활성화됨", 
            "실시간 보호 제어를 사용하려면\n변조 보호를 비활성화(OFF)해야 합니다.\n\n설정 방법:\nWindows 보안 → 바이러스 및 위협 방지 설정 → 변조 보호 OFF"
        )
        return
    
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $true; New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -Type DWORD -Force"
    success, error = execute_powershell_command(powershell_command)
    
    show_custom_info(
        "Defender Control", 
        "Windows Defender 실시간 보호가 비활성화되었습니다.\n\n상태를 확인하려면 '새로고침' 버튼을 클릭하세요."
    )
    refresh_status()

def add_exclusion_folder():
    """제외 폴더 추가"""
    folder_path = filedialog.askdirectory(title="제외할 폴더 선택")
    if folder_path:
        powershell_command = f"Add-MpPreference -ExclusionPath '{folder_path}'"
        success, error = execute_powershell_command(powershell_command)
        
        if success:
            show_custom_info("제외 목록 추가", f"다음 경로가 제외 목록에 추가되었습니다:\n\n{folder_path}")
        else:
            show_custom_warning("오류", f"제외 목록 추가 실패:\n{error}")

def add_exclusion_file():
    """제외 파일 추가"""
    file_path = filedialog.askopenfilename(title="제외할 파일 선택")
    if file_path:
        powershell_command = f"Add-MpPreference -ExclusionPath '{file_path}'"
        success, error = execute_powershell_command(powershell_command)
        
        if success:
            show_custom_info("제외 목록 추가", f"다음 파일이 제외 목록에 추가되었습니다:\n\n{file_path}")
        else:
            show_custom_warning("오류", f"제외 목록 추가 실패:\n{error}")

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
            show_custom_info("현재 제외 목록", f"제외된 경로:\n\n{exclusions}")
        else:
            show_custom_info("현재 제외 목록", "현재 제외 목록이 비어있습니다.")
    except Exception as e:
        show_custom_warning("오류", f"제외 목록 조회 실패: {e}")

def open_exclusion_settings():
    """Windows 보안의 제외 설정 페이지 열기"""
    show_custom_info(
        "제외 설정 안내", 
        "Windows 보안 설정이 열립니다.\n\n다음 단계를 따라주세요:\n1. '바이러스 및 위협 방지' 클릭\n2. 아래로 스크롤하여\n3. '제외 추가 또는 제거' 클릭"
    )
    os.system("start windowsdefender://threatsettings/")

def open_defender_security_center():
    """Windows 보안 앱 열기"""
    os.system("start windowsdefender://")

def refresh_status():
    """상태 새로고침 (비동기)"""
    def update():
        # 새로고침 중 표시
        btn_refresh.config(text="새로고침 중...", state=tk.DISABLED)
        realtime_status_label.config(text="확인 중...", fg=STATUS_UNKNOWN)
        tamper_status_label.config(text="확인 중...", fg=STATUS_UNKNOWN)
        
        realtime_status = check_defender_status()
        tamper_status = check_tamper_protection_status()
        
        # 실시간 보호 상태 업데이트
        if realtime_status == "ON":
            realtime_canvas.itemconfig(realtime_circle, fill=STATUS_ON, outline=STATUS_ON)
            realtime_status_label.config(text="활성화", fg=STATUS_ON)
        elif realtime_status == "OFF":
            realtime_canvas.itemconfig(realtime_circle, fill=STATUS_OFF, outline=STATUS_OFF)
            realtime_status_label.config(text="비활성화", fg=STATUS_OFF)
        else:
            realtime_canvas.itemconfig(realtime_circle, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
            realtime_status_label.config(text="알 수 없음", fg=STATUS_UNKNOWN)
        
        # 변조 보호 상태 업데이트
        if tamper_status == "ON":
            tamper_canvas.itemconfig(tamper_circle, fill=STATUS_ON, outline=STATUS_ON)
            tamper_status_label.config(text="활성화", fg=STATUS_ON)
        elif tamper_status == "OFF":
            tamper_canvas.itemconfig(tamper_circle, fill=STATUS_OFF, outline=STATUS_OFF)
            tamper_status_label.config(text="비활성화", fg=STATUS_OFF)
        else:
            tamper_canvas.itemconfig(tamper_circle, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
            tamper_status_label.config(text="알 수 없음", fg=STATUS_UNKNOWN)
        
        # 새로고침 완료
        btn_refresh.config(text="새로고침", state=tk.NORMAL)
    
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
    root.title("Windows Defender Control")
    root.geometry("400x546") 
    root.resizable(False, False)

    try:
        root.iconbitmap(ICON_FILE) 
    except tk.TclError:
        print(f"Warning: Could not load icon from {ICON_FILE}")

    root.configure(bg=DARK_BG)

    # ============ 상태 섹션 ============
    status_section = tk.Frame(root, bg=DARK_BG)
    status_section.pack(fill=tk.BOTH, padx=15, pady=(15, 10))
    
    status_title = tk.Label(
        status_section, 
        text="상태", 
        font=("Segoe UI", 10, "bold"), 
        bg=DARK_BG, 
        fg=LIGHT_GRAY,
        anchor=tk.W
    )
    status_title.pack(fill=tk.X)
    
    # 상태 카드
    status_card = tk.Frame(status_section, bg=DARK_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
    status_card.pack(fill=tk.BOTH, pady=(5, 0))
    
    # 실시간 보호
    realtime_frame = tk.Frame(status_card, bg=DARK_CARD)
    realtime_frame.pack(fill=tk.X, padx=12, pady=10)
    
    realtime_left = tk.Frame(realtime_frame, bg=DARK_CARD)
    realtime_left.pack(side=tk.LEFT)
    
    realtime_canvas = tk.Canvas(realtime_left, width=16, height=16, bg=DARK_CARD, highlightthickness=0)
    realtime_canvas.pack(side=tk.LEFT, padx=(0, 10))
    realtime_circle = realtime_canvas.create_oval(2, 2, 14, 14, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
    
    realtime_label = tk.Label(
        realtime_left, 
        text="실시간 보호", 
        font=("Segoe UI", 10), 
        bg=DARK_CARD, 
        fg=DARK_FG
    )
    realtime_label.pack(side=tk.LEFT)
    
    realtime_status_label = tk.Label(
        realtime_frame, 
        text="확인 중...", 
        font=("Segoe UI", 9), 
        bg=DARK_CARD, 
        fg=STATUS_UNKNOWN
    )
    realtime_status_label.pack(side=tk.RIGHT)
    
    # 구분선
    tk.Frame(status_card, bg=BORDER_COLOR, height=1).pack(fill=tk.X, padx=12)
    
    # 변조 보호
    tamper_frame = tk.Frame(status_card, bg=DARK_CARD)
    tamper_frame.pack(fill=tk.X, padx=12, pady=10)
    
    tamper_left = tk.Frame(tamper_frame, bg=DARK_CARD)
    tamper_left.pack(side=tk.LEFT)
    
    tamper_canvas = tk.Canvas(tamper_left, width=16, height=16, bg=DARK_CARD, highlightthickness=0)
    tamper_canvas.pack(side=tk.LEFT, padx=(0, 10))
    tamper_circle = tamper_canvas.create_oval(2, 2, 14, 14, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
    
    tamper_label = tk.Label(
        tamper_left, 
        text="변조 보호", 
        font=("Segoe UI", 10), 
        bg=DARK_CARD, 
        fg=DARK_FG
    )
    tamper_label.pack(side=tk.LEFT)
    
    tamper_status_label = tk.Label(
        tamper_frame, 
        text="확인 중...", 
        font=("Segoe UI", 9), 
        bg=DARK_CARD, 
        fg=STATUS_UNKNOWN
    )
    tamper_status_label.pack(side=tk.RIGHT)
    
    # 새로고침 버튼
    btn_refresh = tk.Button(
        status_card, 
        text="새로고침", 
        command=refresh_status, 
        bg=ACCENT_BLUE, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=12,
        height=1
    )
    btn_refresh.pack(pady=10)
    btn_refresh.bind("<Enter>", lambda e: on_enter(e, btn_refresh, BUTTON_HOVER))
    btn_refresh.bind("<Leave>", lambda e: on_leave(e, btn_refresh, ACCENT_BLUE))

    # ============ 제어 섹션 ============
    control_section = tk.Frame(root, bg=DARK_BG)
    control_section.pack(fill=tk.BOTH, padx=15, pady=10)
    
    control_title = tk.Label(
        control_section, 
        text="실시간 보호 제어", 
        font=("Segoe UI", 10, "bold"), 
        bg=DARK_BG, 
        fg=LIGHT_GRAY,
        anchor=tk.W
    )
    control_title.pack(fill=tk.X)
    
    control_card = tk.Frame(control_section, bg=DARK_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
    control_card.pack(fill=tk.BOTH, pady=(5, 0))
    
    btn_enable = tk.Button(
        control_card, 
        text="활성화", 
        command=enable_defender, 
        bg=ACCENT_GREEN, 
        fg=DARK_FG, 
        font=("Segoe UI", 10, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=15,
        height=1
    )
    btn_enable.pack(pady=(12, 5))
    btn_enable.bind("<Enter>", lambda e: on_enter(e, btn_enable, "#27ae60"))
    btn_enable.bind("<Leave>", lambda e: on_leave(e, btn_enable, ACCENT_GREEN))

    btn_disable = tk.Button(
        control_card, 
        text="비활성화", 
        command=disable_defender, 
        bg=ACCENT_RED, 
        fg=DARK_FG, 
        font=("Segoe UI", 10, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=15,
        height=1
    )
    btn_disable.pack(pady=(5, 12))
    btn_disable.bind("<Enter>", lambda e: on_enter(e, btn_disable, "#c0392b"))
    btn_disable.bind("<Leave>", lambda e: on_leave(e, btn_disable, ACCENT_RED))

    # ============ 제외 목록 섹션 ============
    exclusion_section = tk.Frame(root, bg=DARK_BG)
    exclusion_section.pack(fill=tk.BOTH, padx=15, pady=10)
    
    exclusion_title = tk.Label(
        exclusion_section, 
        text="제외 목록 관리", 
        font=("Segoe UI", 10, "bold"), 
        bg=DARK_BG, 
        fg=LIGHT_GRAY,
        anchor=tk.W
    )
    exclusion_title.pack(fill=tk.X)
    
    exclusion_card = tk.Frame(exclusion_section, bg=DARK_CARD, highlightbackground=BORDER_COLOR, highlightthickness=1)
    exclusion_card.pack(fill=tk.BOTH, pady=(5, 0))
    
    btn_add_folder = tk.Button(
        exclusion_card, 
        text="폴더 제외 추가", 
        command=add_exclusion_folder, 
        bg=ACCENT_BLUE, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=1
    )
    btn_add_folder.pack(pady=(10, 4))
    btn_add_folder.bind("<Enter>", lambda e: on_enter(e, btn_add_folder, BUTTON_HOVER))
    btn_add_folder.bind("<Leave>", lambda e: on_leave(e, btn_add_folder, ACCENT_BLUE))

    btn_add_file = tk.Button(
        exclusion_card, 
        text="파일 제외 추가", 
        command=add_exclusion_file, 
        bg=ACCENT_BLUE, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=1
    )
    btn_add_file.pack(pady=4)
    btn_add_file.bind("<Enter>", lambda e: on_enter(e, btn_add_file, BUTTON_HOVER))
    btn_add_file.bind("<Leave>", lambda e: on_leave(e, btn_add_file, ACCENT_BLUE))

    btn_view_exclusions = tk.Button(
        exclusion_card, 
        text="제외 목록 보기", 
        command=view_exclusions, 
        bg=ACCENT_BLUE, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=1
    )
    btn_view_exclusions.pack(pady=4)
    btn_view_exclusions.bind("<Enter>", lambda e: on_enter(e, btn_view_exclusions, BUTTON_HOVER))
    btn_view_exclusions.bind("<Leave>", lambda e: on_leave(e, btn_view_exclusions, ACCENT_BLUE))

    btn_open_exclusion = tk.Button(
        exclusion_card, 
        text="제외 설정 바로가기", 
        command=open_exclusion_settings, 
        bg=ACCENT_BLUE, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=1
    )
    btn_open_exclusion.pack(pady=(4, 10))
    btn_open_exclusion.bind("<Enter>", lambda e: on_enter(e, btn_open_exclusion, BUTTON_HOVER))
    btn_open_exclusion.bind("<Leave>", lambda e: on_leave(e, btn_open_exclusion, ACCENT_BLUE))

    # ============ 하단 버튼 ============
    bottom_frame = tk.Frame(root, bg=DARK_BG)
    bottom_frame.pack(pady=(5, 15))
    
    btn_open = tk.Button(
        bottom_frame, 
        text="Windows 보안", 
        command=open_defender_security_center, 
        bg=ACCENT_BLUE, 
        fg=DARK_FG, 
        font=("Segoe UI", 9, "bold"), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=14,
        height=1
    )
    btn_open.pack(side=tk.LEFT, padx=3)
    btn_open.bind("<Enter>", lambda e: on_enter(e, btn_open, BUTTON_HOVER))
    btn_open.bind("<Leave>", lambda e: on_leave(e, btn_open, ACCENT_BLUE))

    btn_exit = tk.Button(
        bottom_frame, 
        text="종료", 
        command=app_exit, 
        bg="#34383f", 
        fg=DARK_FG, 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=8,
        height=1
    )
    btn_exit.pack(side=tk.LEFT, padx=3)
    btn_exit.bind("<Enter>", lambda e: on_enter(e, btn_exit, "#45494f"))
    btn_exit.bind("<Leave>", lambda e: on_leave(e, btn_exit, "#34383f"))

    # 초기 상태 확인
    refresh_status()

    root.mainloop()