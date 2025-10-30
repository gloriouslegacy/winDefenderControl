import winreg
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def disable_tamper_protection():
    if not is_admin():
        print("관리자 권한이 필요합니다!")
        return False
    
    try:
        # 레지스트리 경로
        key_path = r"SOFTWARE\Microsoft\Windows Defender\Features"
        
        # 레지스트리 키 열기
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                            winreg.KEY_SET_VALUE)
        
        # TamperProtection 값 설정 (0 = 비활성화)
        winreg.SetValueEx(key, "TamperProtection", 0, winreg.REG_DWORD, 0)
        
        winreg.CloseKey(key)
        print("변조 방지가 비활성화되었습니다.")
        return True
        
    except Exception as e:
        print(f"오류 발생: {e}")
        return False

if __name__ == "__main__":
    disable_tamper_protection()