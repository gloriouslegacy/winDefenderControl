import subprocess
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """관리자 권한으로 재실행"""
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

def disable_defender_realtime():
    """실시간 보호 비활성화"""
    try:
        cmd = 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Windows Defender 실시간 보호가 비활성화되었습니다.")
            return True
        else:
            print(f"✗ 오류: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ 예외 발생: {e}")
        return False

def enable_defender_realtime():
    """실시간 보호 활성화"""
    try:
        cmd = 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Windows Defender 실시간 보호가 활성화되었습니다.")
            return True
        else:
            print(f"✗ 오류: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ 예외 발생: {e}")
        return False

def add_exclusion_path(path):
    """특정 경로를 제외 목록에 추가"""
    try:
        cmd = f'powershell -Command "Add-MpPreference -ExclusionPath \'{path}\'"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✓ 경로가 제외 목록에 추가되었습니다: {path}")
            return True
        else:
            print(f"✗ 오류: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ 예외 발생: {e}")
        return False

if __name__ == "__main__":
    run_as_admin()  # 관리자 권한으로 실행
    
    print("=== Windows Defender 테스트 환경 설정 ===\n")
    
    # 방법 1: 실시간 보호 비활성화 (일시적)
    disable_defender_realtime()
    
    # 방법 2: 특정 개발 폴더를 제외 목록에 추가 (권장)
    add_exclusion_path(r"C:\Development")
    add_exclusion_path(r"C:\TestProjects")
    
    print("\n테스트 완료 후 다시 활성화하세요!")