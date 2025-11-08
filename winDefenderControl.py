import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import os
import sys
import ctypes
import subprocess
import threading
import json

# --- Language Configuration ---
LANG_FILE = "defender_lang.json"

def get_language():
    """Get current language setting"""
    try:
        if os.path.exists(LANG_FILE):
            with open(LANG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('language', 'en')
    except:
        pass
    return 'en'

def set_language(lang):
    """Save language setting"""
    try:
        with open(LANG_FILE, 'w', encoding='utf-8') as f:
            json.dump({'language': lang}, f)
    except:
        pass

def toggle_language():
    """Toggle language and restart"""
    current_lang = get_language()
    new_lang = 'ko' if current_lang == 'en' else 'en'
    set_language(new_lang)
    
    # Restart application
    if getattr(sys, 'frozen', False):
        # PyInstaller로 빌드된 경우
        subprocess.Popen([sys.executable] + sys.argv)
    else:
        # 일반 Python 스크립트 실행의 경우
        subprocess.Popen([sys.executable] + sys.argv)
    
    sys.exit(0)

# Get current language
CURRENT_LANG = get_language()

# Language Strings
STRINGS = {
    'en': {
        'title': 'Windows Defender Control',
        'subtitle': 'Windows Security Management Tool',
        'main_title': 'Defender Control',
        'status': 'Status',
        'realtime_protection': 'Real-time Protection',
        'tamper_protection': 'Tamper Protection',
        'enabled': 'Enabled',
        'disabled': 'Disabled',
        'unknown': 'Unknown',
        'checking': 'Checking...',
        'refresh': 'Refresh',
        'refreshing': 'Refreshing...',
        'control_title': 'Real-time Protection Control',
        'enable': 'Enable',
        'disable': 'Disable',
        'exclusion_title': 'Exclusion List Management',
        'add_folder': 'Add Folder Exclusion',
        'add_file': 'Add File Exclusion',
        'view_list': 'View Exclusion List',
        'exclusion_settings': 'Exclusion Settings',
        'windows_security': 'Windows Security',
        'exit': 'Exit',
        'ok': 'OK',
        'language': 'Language',
        'lang_toggle': '한국어',  # Shows Korean when in English mode
        
        # Messages
        'defender_control': 'Defender Control',
        'enabled_msg': 'Windows Defender Real-time Protection has been enabled.\n\nClick the \'Refresh\' button to check the status.',
        'disabled_msg': 'Windows Defender Real-time Protection has been disabled.\n\nClick the \'Refresh\' button to check the status.',
        'tamper_warning_title': 'Tamper Protection Enabled',
        'tamper_warning_msg': 'To control Real-time Protection,\nTamper Protection must be disabled (OFF).\n\nHow to disable:\nWindows Security → Virus & threat protection settings → Tamper Protection OFF',
        'exclusion_added': 'Exclusion Added',
        'exclusion_added_msg': 'The following path has been added to the exclusion list:\n\n',
        'exclusion_added_file_msg': 'The following file has been added to the exclusion list:\n\n',
        'error': 'Error',
        'exclusion_failed': 'Failed to add exclusion:\n',
        'current_exclusions': 'Current Exclusion List',
        'excluded_paths': 'Excluded paths:\n\n',
        'empty_list': 'The exclusion list is currently empty.',
        'exclusion_failed_view': 'Failed to retrieve exclusion list: ',
        'exclusion_guide_title': 'Exclusion Settings Guide',
        'exclusion_guide_msg': 'Windows Security settings will open.\n\nPlease follow these steps:\n1. Click \'Virus & threat protection\'\n2. Scroll down\n3. Click \'Add or remove exclusions\'',
        'select_folder': 'Select Folder to Exclude',
        'select_file': 'Select File to Exclude',
    },
    'ko': {
        'title': 'Windows Defender 제어',
        'subtitle': 'Windows 보안 관리 도구',
        'main_title': 'Defender 제어',
        'status': '상태',
        'realtime_protection': '실시간 보호',
        'tamper_protection': '변조 보호',
        'enabled': '활성화',
        'disabled': '비활성화',
        'unknown': '알 수 없음',
        'checking': '확인 중...',
        'refresh': '새로고침',
        'refreshing': '새로고침 중...',
        'control_title': '실시간 보호 제어',
        'enable': '활성화',
        'disable': '비활성화',
        'exclusion_title': '제외 목록 관리',
        'add_folder': '폴더 제외 추가',
        'add_file': '파일 제외 추가',
        'view_list': '제외 목록 보기',
        'exclusion_settings': '제외 설정 바로가기',
        'windows_security': 'Windows 보안',
        'exit': '종료',
        'ok': '확인',
        'language': '언어',
        'lang_toggle': 'English',  # Shows English when in Korean mode
        
        # Messages
        'defender_control': 'Defender 제어',
        'enabled_msg': 'Windows Defender 실시간 보호가 활성화되었습니다.\n\n상태를 확인하려면 \'새로고침\' 버튼을 클릭하세요.',
        'disabled_msg': 'Windows Defender 실시간 보호가 비활성화되었습니다.\n\n상태를 확인하려면 \'새로고침\' 버튼을 클릭하세요.',
        'tamper_warning_title': '변조 보호 활성화됨',
        'tamper_warning_msg': '실시간 보호 제어를 사용하려면\n변조 보호를 비활성화(OFF)해야 합니다.\n\n설정 방법:\nWindows 보안 → 바이러스 및 위협 방지 설정 → 변조 보호 OFF',
        'exclusion_added': '제외 목록 추가',
        'exclusion_added_msg': '다음 경로가 제외 목록에 추가되었습니다:\n\n',
        'exclusion_added_file_msg': '다음 파일이 제외 목록에 추가되었습니다:\n\n',
        'error': '오류',
        'exclusion_failed': '제외 목록 추가 실패:\n',
        'current_exclusions': '현재 제외 목록',
        'excluded_paths': '제외된 경로:\n\n',
        'empty_list': '현재 제외 목록이 비어있습니다.',
        'exclusion_failed_view': '제외 목록 조회 실패: ',
        'exclusion_guide_title': '제외 설정 안내',
        'exclusion_guide_msg': 'Windows 보안 설정이 열립니다.\n\n다음 단계를 따라주세요:\n1. \'바이러스 및 위협 방지\' 클릭\n2. 아래로 스크롤하여\n3. \'제외 추가 또는 제거\' 클릭',
        'select_folder': '제외할 폴더 선택',
        'select_file': '제외할 파일 선택',
    }
}

def _(key):
    """Get localized string"""
    return STRINGS[CURRENT_LANG].get(key, key)

# --- Windows 11 Style Color Settings ---
WIN11_BG = "#F3F3F3"
WIN11_CARD = "#FFFFFF"
WIN11_TEXT = "#202020"
WIN11_SUBTEXT = "#707070"
WIN11_ACCENT = "#0067C0"
WIN11_ACCENT_HOVER = "#005A9E"
WIN11_SUCCESS = "#107C10"
WIN11_DANGER = "#D13438"
WIN11_WARNING = "#F7630C"
WIN11_GRAY = "#8B8B8B"
WIN11_BORDER = "#E0E0E0"
STATUS_UNKNOWN = "#8B8B8B"

# --- Icon Path Settings ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

ICON_FILE = resource_path("icon/winDefender.ico") 

# --- Check and Request Admin Rights ---
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

# --- Status Check Functions ---
def check_defender_status():
    """Check Windows Defender Real-time Protection Status"""
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
    """Check Tamper Protection Status"""
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

# --- Function Definitions ---
def execute_powershell_command(powershell_command):
    """Execute PowerShell Command Without Console Window"""
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
    """Information Message - Windows 11 Style"""
    msg_window = tk.Toplevel(root)
    msg_window.title(title)
    msg_window.geometry("450x580")
    msg_window.configure(bg=WIN11_BG)
    msg_window.resizable(True, True)
    
    try:
        msg_window.iconbitmap(ICON_FILE)
    except:
        pass
    
    main_container = tk.Frame(msg_window, bg=WIN11_BG)
    main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    title_label = tk.Label(
        main_container,
        text=title,
        font=("Segoe UI", 14, "bold"),
        bg=WIN11_BG,
        fg=WIN11_TEXT
    )
    title_label.pack(pady=(0, 15))
    
    text_card = tk.Frame(main_container, bg=WIN11_CARD,
                        highlightbackground=WIN11_BORDER,
                        highlightthickness=1)
    text_card.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
    
    scrollbar = tk.Scrollbar(text_card)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    text_box = tk.Text(
        text_card,
        font=("Segoe UI", 10),
        bg=WIN11_CARD,
        fg=WIN11_TEXT,
        wrap=tk.WORD,
        yscrollcommand=scrollbar.set,
        relief=tk.FLAT,
        bd=0,
        padx=15,
        pady=15
    )
    text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=text_box.yview)
    
    text_box.insert("1.0", message)
    text_box.config(state=tk.DISABLED)
    
    ok_button = tk.Button(
        main_container,
        text=_('ok'),
        command=msg_window.destroy,
        bg=WIN11_ACCENT,
        fg="white",
        font=("Segoe UI", 10),
        width=20,
        height=1,
        bd=0,
        relief=tk.FLAT,
        cursor="hand2"
    )
    ok_button.pack()
    
    def on_hover(e):
        ok_button['bg'] = WIN11_ACCENT_HOVER
    def on_leave(e):
        ok_button['bg'] = WIN11_ACCENT
    
    ok_button.bind("<Enter>", on_hover)
    ok_button.bind("<Leave>", on_leave)
    
    msg_window.transient(root)
    msg_window.grab_set()
    msg_window.focus_set()

def show_custom_warning(title, message):
    """Warning Message - Windows 11 Style"""
    msg_window = tk.Toplevel(root)
    msg_window.title(title)
    msg_window.geometry("450x371")
    msg_window.configure(bg=WIN11_BG)
    msg_window.resizable(True, True)
    
    try:
        msg_window.iconbitmap(ICON_FILE)
    except:
        pass
    
    main_container = tk.Frame(msg_window, bg=WIN11_BG)
    main_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
    
    warning_label = tk.Label(
        main_container,
        text="⚠",
        font=("Segoe UI", 40),
        bg=WIN11_BG,
        fg=WIN11_WARNING
    )
    warning_label.pack(pady=(0, 15))
    
    title_label = tk.Label(
        main_container,
        text=title,
        font=("Segoe UI", 14, "bold"),
        bg=WIN11_BG,
        fg=WIN11_TEXT
    )
    title_label.pack(pady=(0, 10))
    
    msg_label = tk.Label(
        main_container,
        text=message,
        font=("Segoe UI", 10),
        bg=WIN11_BG,
        fg=WIN11_SUBTEXT,
        wraplength=380,
        justify=tk.CENTER
    )
    msg_label.pack(pady=(0, 25))
    
    ok_button = tk.Button(
        main_container,
        text=_('ok'),
        command=msg_window.destroy,
        bg=WIN11_ACCENT,
        fg="white",
        font=("Segoe UI", 10),
        width=20,
        height=1,
        bd=0,
        relief=tk.FLAT,
        cursor="hand2"
    )
    ok_button.pack()
    
    def on_hover(e):
        ok_button['bg'] = WIN11_ACCENT_HOVER
    def on_leave(e):
        ok_button['bg'] = WIN11_ACCENT
    
    ok_button.bind("<Enter>", on_hover)
    ok_button.bind("<Leave>", on_leave)
    
    msg_window.transient(root)
    msg_window.grab_set()
    msg_window.focus_set()

def enable_defender():
    """Enable Real-time Protection"""
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $false; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -ErrorAction SilentlyContinue"
    success, error = execute_powershell_command(powershell_command)
    
    show_custom_info(
        _('defender_control'), 
        _('enabled_msg')
    )
    refresh_status()

def disable_defender():
    """Disable Real-time Protection"""
    tamper_status = check_tamper_protection_status()
    
    if tamper_status == "ON":
        show_custom_warning(
            _('tamper_warning_title'), 
            _('tamper_warning_msg')
        )
        return
    
    powershell_command = "Set-MpPreference -DisableRealtimeMonitoring $true; New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -Type DWORD -Force"
    success, error = execute_powershell_command(powershell_command)
    
    show_custom_info(
        _('defender_control'), 
        _('disabled_msg')
    )
    refresh_status()

def add_exclusion_folder():
    """Add Exclusion Folder"""
    folder_path = filedialog.askdirectory(title=_('select_folder'))
    if folder_path:
        powershell_command = f"Add-MpPreference -ExclusionPath '{folder_path}'"
        success, error = execute_powershell_command(powershell_command)
        
        if success:
            show_custom_info(_('exclusion_added'), _('exclusion_added_msg') + folder_path)
        else:
            show_custom_warning(_('error'), _('exclusion_failed') + error)

def add_exclusion_file():
    """Add Exclusion File"""
    file_path = filedialog.askopenfilename(title=_('select_file'))
    if file_path:
        powershell_command = f"Add-MpPreference -ExclusionPath '{file_path}'"
        success, error = execute_powershell_command(powershell_command)
        
        if success:
            show_custom_info(_('exclusion_added'), _('exclusion_added_file_msg') + file_path)
        else:
            show_custom_warning(_('error'), _('exclusion_failed') + error)

def view_exclusions():
    """View Current Exclusion List"""
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
            show_custom_info(_('current_exclusions'), _('excluded_paths') + exclusions)
        else:
            show_custom_info(_('current_exclusions'), _('empty_list'))
    except Exception as e:
        show_custom_warning(_('error'), _('exclusion_failed_view') + str(e))

def open_exclusion_settings():
    """Open Windows Security Exclusion Settings Page"""
    show_custom_info(
        _('exclusion_guide_title'), 
        _('exclusion_guide_msg')
    )
    os.system("start windowsdefender://threatsettings/")

def open_defender_security_center():
    """Open Windows Security App"""
    os.system("start windowsdefender://")

def refresh_status():
    """Refresh Status (Asynchronous)"""
    def update():
        btn_refresh.config(text=_('refreshing'), state=tk.DISABLED)
        realtime_status_label.config(text=_('checking'), fg=STATUS_UNKNOWN)
        tamper_status_label.config(text=_('checking'), fg=STATUS_UNKNOWN)
        
        realtime_status = check_defender_status()
        tamper_status = check_tamper_protection_status()
        
        if realtime_status == "ON":
            realtime_canvas.itemconfig(realtime_circle, fill=WIN11_SUCCESS, outline=WIN11_SUCCESS)
            realtime_status_label.config(text=_('enabled'), fg=WIN11_SUCCESS)
        elif realtime_status == "OFF":
            realtime_canvas.itemconfig(realtime_circle, fill=WIN11_DANGER, outline=WIN11_DANGER)
            realtime_status_label.config(text=_('disabled'), fg=WIN11_DANGER)
        else:
            realtime_canvas.itemconfig(realtime_circle, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
            realtime_status_label.config(text=_('unknown'), fg=STATUS_UNKNOWN)
        
        if tamper_status == "ON":
            tamper_canvas.itemconfig(tamper_circle, fill=WIN11_SUCCESS, outline=WIN11_SUCCESS)
            tamper_status_label.config(text=_('enabled'), fg=WIN11_SUCCESS)
        elif tamper_status == "OFF":
            tamper_canvas.itemconfig(tamper_circle, fill=WIN11_DANGER, outline=WIN11_DANGER)
            tamper_status_label.config(text=_('disabled'), fg=WIN11_DANGER)
        else:
            tamper_canvas.itemconfig(tamper_circle, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
            tamper_status_label.config(text=_('unknown'), fg=STATUS_UNKNOWN)
        
        btn_refresh.config(text=_('refresh'), state=tk.NORMAL)
    
    thread = threading.Thread(target=update, daemon=True)
    thread.start()

def app_exit():
    sys.exit()

# --- Button Hover Effect Functions ---
def on_enter(e, button, color):
    button['background'] = color
    
def on_leave(e, button, original_color):
    button['background'] = original_color

def darken_color(hex_color, factor=0.85):
    """Darken Color"""
    hex_color = hex_color.lstrip('#')
    r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    r = max(0, int(r * factor))
    g = max(0, int(g * factor))
    b = max(0, int(b * factor))
    return f'#{r:02x}{g:02x}{b:02x}'

# --- Main Execution ---
if __name__ == "__main__":
    run_as_admin()

    root = tk.Tk()
    root.title(_('title'))
    root.geometry("480x710") 
    root.resizable(False, False)

    try:
        root.iconbitmap(ICON_FILE) 
    except tk.TclError:
        print(f"Warning: Could not load icon from {ICON_FILE}")

    root.configure(bg=WIN11_BG)

    # ============ Title Section ============
    title_section = tk.Frame(root, bg=WIN11_BG)
    title_section.pack(fill=tk.X, padx=25, pady=(25, 5))
    
    # Language toggle button (top right)
    lang_frame = tk.Frame(title_section, bg=WIN11_BG)
    lang_frame.pack(fill=tk.X)
    
    btn_lang = tk.Button(
        lang_frame,
        text=f"🌐 {_('lang_toggle')}",
        command=toggle_language,
        bg=WIN11_CARD,
        fg=WIN11_TEXT,
        font=("Segoe UI", 9),
        bd=0,
        relief=tk.FLAT,
        cursor="hand2",
        highlightbackground=WIN11_BORDER,
        highlightthickness=1,
        padx=10,
        pady=5
    )
    btn_lang.pack(side=tk.RIGHT)
    btn_lang.bind("<Enter>", lambda e: on_enter(e, btn_lang, WIN11_BORDER))
    btn_lang.bind("<Leave>", lambda e: on_leave(e, btn_lang, WIN11_CARD))
    
    main_title = tk.Label(
        title_section,
        text=_('main_title'),
        font=("Segoe UI", 20, "bold"),
        bg=WIN11_BG,
        fg=WIN11_TEXT
    )
    main_title.pack(pady=(10, 0))
    
    subtitle = tk.Label(
        title_section,
        text=_('subtitle'),
        font=("Segoe UI", 10),
        bg=WIN11_BG,
        fg=WIN11_SUBTEXT
    )
    subtitle.pack()

    # ============ Status Section ============
    status_section = tk.Frame(root, bg=WIN11_BG)
    status_section.pack(fill=tk.BOTH, padx=25, pady=(20, 10))
    
    status_title = tk.Label(
        status_section, 
        text=_('status'), 
        font=("Segoe UI", 11, "bold"), 
        bg=WIN11_BG, 
        fg=WIN11_TEXT,
        anchor=tk.W
    )
    status_title.pack(fill=tk.X, pady=(0, 8))
    
    status_card = tk.Frame(status_section, bg=WIN11_CARD, 
                          highlightbackground=WIN11_BORDER, 
                          highlightthickness=1)
    status_card.pack(fill=tk.BOTH)
    
    # Real-time Protection
    realtime_frame = tk.Frame(status_card, bg=WIN11_CARD)
    realtime_frame.pack(fill=tk.X, padx=20, pady=15)
    
    realtime_left = tk.Frame(realtime_frame, bg=WIN11_CARD)
    realtime_left.pack(side=tk.LEFT)
    
    realtime_canvas = tk.Canvas(realtime_left, width=12, height=12, bg=WIN11_CARD, highlightthickness=0)
    realtime_canvas.pack(side=tk.LEFT, padx=(0, 12))
    realtime_circle = realtime_canvas.create_oval(2, 2, 10, 10, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
    
    realtime_label = tk.Label(
        realtime_left, 
        text=_('realtime_protection'), 
        font=("Segoe UI", 11), 
        bg=WIN11_CARD, 
        fg=WIN11_TEXT
    )
    realtime_label.pack(side=tk.LEFT)
    
    realtime_status_label = tk.Label(
        realtime_frame, 
        text=_('checking'), 
        font=("Segoe UI", 10), 
        bg=WIN11_CARD, 
        fg=STATUS_UNKNOWN
    )
    realtime_status_label.pack(side=tk.RIGHT)
    
    tk.Frame(status_card, bg=WIN11_BORDER, height=1).pack(fill=tk.X, padx=20)
    
    # Tamper Protection
    tamper_frame = tk.Frame(status_card, bg=WIN11_CARD)
    tamper_frame.pack(fill=tk.X, padx=20, pady=15)
    
    tamper_left = tk.Frame(tamper_frame, bg=WIN11_CARD)
    tamper_left.pack(side=tk.LEFT)
    
    tamper_canvas = tk.Canvas(tamper_left, width=12, height=12, bg=WIN11_CARD, highlightthickness=0)
    tamper_canvas.pack(side=tk.LEFT, padx=(0, 12))
    tamper_circle = tamper_canvas.create_oval(2, 2, 10, 10, fill=STATUS_UNKNOWN, outline=STATUS_UNKNOWN)
    
    tamper_label = tk.Label(
        tamper_left, 
        text=_('tamper_protection'), 
        font=("Segoe UI", 11), 
        bg=WIN11_CARD, 
        fg=WIN11_TEXT
    )
    tamper_label.pack(side=tk.LEFT)
    
    tamper_status_label = tk.Label(
        tamper_frame, 
        text=_('checking'), 
        font=("Segoe UI", 10), 
        bg=WIN11_CARD, 
        fg=STATUS_UNKNOWN
    )
    tamper_status_label.pack(side=tk.RIGHT)
    
    tk.Frame(status_card, bg=WIN11_BORDER, height=1).pack(fill=tk.X, padx=20)
    
    # Refresh Button
    btn_refresh = tk.Button(
        status_card, 
        text=_('refresh'), 
        command=refresh_status, 
        bg=WIN11_ACCENT, 
        fg="white", 
        font=("Segoe UI", 10), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=15,
        height=1
    )
    btn_refresh.pack(pady=15)
    btn_refresh.bind("<Enter>", lambda e: on_enter(e, btn_refresh, WIN11_ACCENT_HOVER))
    btn_refresh.bind("<Leave>", lambda e: on_leave(e, btn_refresh, WIN11_ACCENT))

    # ============ Control Section ============
    control_section = tk.Frame(root, bg=WIN11_BG)
    control_section.pack(fill=tk.BOTH, padx=25, pady=10)
    
    control_title = tk.Label(
        control_section, 
        text=_('control_title'), 
        font=("Segoe UI", 11, "bold"), 
        bg=WIN11_BG, 
        fg=WIN11_TEXT,
        anchor=tk.W
    )
    control_title.pack(fill=tk.X, pady=(0, 8))
    
    control_card = tk.Frame(control_section, bg=WIN11_CARD, 
                           highlightbackground=WIN11_BORDER, 
                           highlightthickness=1)
    control_card.pack(fill=tk.BOTH)
    
    control_buttons = tk.Frame(control_card, bg=WIN11_CARD)
    control_buttons.pack(padx=20, pady=15)
    
    btn_enable = tk.Button(
        control_buttons, 
        text=_('enable'), 
        command=enable_defender, 
        bg=WIN11_SUCCESS, 
        fg="white", 
        font=("Segoe UI", 10), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=2
    )
    btn_enable.pack(side=tk.LEFT, padx=5)
    btn_enable.bind("<Enter>", lambda e: on_enter(e, btn_enable, darken_color(WIN11_SUCCESS)))
    btn_enable.bind("<Leave>", lambda e: on_leave(e, btn_enable, WIN11_SUCCESS))

    btn_disable = tk.Button(
        control_buttons, 
        text=_('disable'), 
        command=disable_defender, 
        bg=WIN11_DANGER, 
        fg="white", 
        font=("Segoe UI", 10), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=2
    )
    btn_disable.pack(side=tk.LEFT, padx=5)
    btn_disable.bind("<Enter>", lambda e: on_enter(e, btn_disable, darken_color(WIN11_DANGER)))
    btn_disable.bind("<Leave>", lambda e: btn_disable, WIN11_DANGER)

    # ============ Exclusion List Section ============
    exclusion_section = tk.Frame(root, bg=WIN11_BG)
    exclusion_section.pack(fill=tk.BOTH, padx=25, pady=10)
    
    exclusion_title = tk.Label(
        exclusion_section, 
        text=_('exclusion_title'), 
        font=("Segoe UI", 11, "bold"), 
        bg=WIN11_BG, 
        fg=WIN11_TEXT,
        anchor=tk.W
    )
    exclusion_title.pack(fill=tk.X, pady=(0, 8))
    
    exclusion_card = tk.Frame(exclusion_section, bg=WIN11_CARD, 
                             highlightbackground=WIN11_BORDER, 
                             highlightthickness=1)
    exclusion_card.pack(fill=tk.BOTH)
    
    exclusion_grid = tk.Frame(exclusion_card, bg=WIN11_CARD)
    exclusion_grid.pack(padx=20, pady=15)
    
    # First Row
    row1 = tk.Frame(exclusion_grid, bg=WIN11_CARD)
    row1.pack(fill=tk.X, pady=3)
    
    btn_add_folder = tk.Button(
        row1, 
        text=_('add_folder'), 
        command=add_exclusion_folder, 
        bg=WIN11_ACCENT, 
        fg="white", 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=20,
        height=1
    )
    btn_add_folder.pack(side=tk.LEFT, padx=3)
    btn_add_folder.bind("<Enter>", lambda e: on_enter(e, btn_add_folder, WIN11_ACCENT_HOVER))
    btn_add_folder.bind("<Leave>", lambda e: on_leave(e, btn_add_folder, WIN11_ACCENT))

    btn_add_file = tk.Button(
        row1, 
        text=_('add_file'), 
        command=add_exclusion_file, 
        bg=WIN11_ACCENT, 
        fg="white", 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=20,
        height=1
    )
    btn_add_file.pack(side=tk.LEFT, padx=3)
    btn_add_file.bind("<Enter>", lambda e: on_enter(e, btn_add_file, WIN11_ACCENT_HOVER))
    btn_add_file.bind("<Leave>", lambda e: on_leave(e, btn_add_file, WIN11_ACCENT))

    # Second Row
    row2 = tk.Frame(exclusion_grid, bg=WIN11_CARD)
    row2.pack(fill=tk.X, pady=3)

    btn_view_exclusions = tk.Button(
        row2, 
        text=_('view_list'), 
        command=view_exclusions, 
        bg=WIN11_ACCENT, 
        fg="white", 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=20,
        height=1
    )
    btn_view_exclusions.pack(side=tk.LEFT, padx=3)
    btn_view_exclusions.bind("<Enter>", lambda e: on_enter(e, btn_view_exclusions, WIN11_ACCENT_HOVER))
    btn_view_exclusions.bind("<Leave>", lambda e: on_leave(e, btn_view_exclusions, WIN11_ACCENT))

    btn_open_exclusion = tk.Button(
        row2, 
        text=_('exclusion_settings'), 
        command=open_exclusion_settings, 
        bg=WIN11_ACCENT, 
        fg="white", 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=20,
        height=1
    )
    btn_open_exclusion.pack(side=tk.LEFT, padx=3)
    btn_open_exclusion.bind("<Enter>", lambda e: on_enter(e, btn_open_exclusion, WIN11_ACCENT_HOVER))
    btn_open_exclusion.bind("<Leave>", lambda e: on_leave(e, btn_open_exclusion, WIN11_ACCENT))

    # ============ Bottom Buttons ============
    bottom_frame = tk.Frame(root, bg=WIN11_BG)
    bottom_frame.pack(pady=(10, 20))
    
    btn_open = tk.Button(
        bottom_frame, 
        text=_('windows_security'), 
        command=open_defender_security_center, 
        bg=WIN11_ACCENT, 
        fg="white", 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=18,
        height=1
    )
    btn_open.pack(side=tk.LEFT, padx=5)
    btn_open.bind("<Enter>", lambda e: on_enter(e, btn_open, WIN11_ACCENT_HOVER))
    btn_open.bind("<Leave>", lambda e: on_leave(e, btn_open, WIN11_ACCENT))

    btn_exit = tk.Button(
        bottom_frame, 
        text=_('exit'), 
        command=app_exit, 
        bg=WIN11_GRAY, 
        fg="white", 
        font=("Segoe UI", 9), 
        bd=0, 
        relief=tk.FLAT,
        cursor="hand2",
        width=10,
        height=1
    )
    btn_exit.pack(side=tk.LEFT, padx=5)
    btn_exit.bind("<Enter>", lambda e: on_enter(e, btn_exit, darken_color(WIN11_GRAY, 0.8)))
    btn_exit.bind("<Leave>", lambda e: on_leave(e, btn_exit, WIN11_GRAY))

    # Initial Status Check
    refresh_status()

    root.mainloop()