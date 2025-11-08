# Windows Defender Control

Windows Defender의 실시간 보호 및 제외 목록을 관리하는 GUI 도구입니다.

## 주요 기능

### 1. 실시간 보호 제어
- Windows Defender 실시간 보호 활성화/비활성화
- 현재 상태 실시간 확인
- 변조 보호(Tamper Protection) 상태 확인

### 2. 제외 목록 관리
- 폴더 제외 추가
- 파일 제외 추가
- 현재 제외 목록 조회
- Windows 보안 설정 바로가기

### 3. 언어 지원
- 한국어/English 지원
- 사용자별 언어 설정 저장

### 실행 파일 사용
1. 배포된 exe 파일 다운로드
2. 관리자 권한으로 실행
3. UAC 승인 필요 시 "예" 클릭

## 사용 방법

### 상태 확인
1. 프로그램 실행 시 자동으로 현재 상태 확인
2. "새로고침" 버튼으로 상태 업데이트
3. 실시간 보호와 변조 보호 상태를 색상으로 표시
   - 녹색: 활성화
   - 빨간색: 비활성화
   - 회색: 알 수 없음

### 실시간 보호 제어
1. "활성화" 버튼: 실시간 보호 켜기
2. "비활성화" 버튼: 실시간 보호 끄기
3. 변경 후 "새로고침" 버튼으로 상태 확인

**중요:** 변조 보호가 활성화되어 있으면 실시간 보호를 제어할 수 없습니다. Windows 보안 설정에서 변조 보호를 먼저 비활성화해야 합니다.

### 제외 목록 관리

#### 폴더 제외 추가
1. "폴더 제외 추가" 버튼 클릭
2. 제외할 폴더 선택
3. 확인 메시지 확인

#### 파일 제외 추가
1. "파일 제외 추가" 버튼 클릭
2. 제외할 파일 선택
3. 확인 메시지 확인

#### 제외 목록 조회
1. "제외 목록 보기" 버튼 클릭
2. 현재 등록된 제외 경로 확인

#### 제외 설정 직접 편집
1. "제외 설정 바로가기" 버튼 클릭
2. Windows 보안 설정 화면으로 이동
3. "바이러스 및 위협 방지" 클릭
4. "제외 추가 또는 제거" 클릭

### 언어 변경
1. 우측 상단의 언어 버튼 클릭
   - English 모드: "한국어" 표시
   - 한국어 모드: "English" 표시
2. 클릭 시 즉시 언어 전환
3. 설정 자동으로 저장됨

## 설정 파일 위치

언어 설정 파일:
```
%APPDATA%\DefenderControl\defender_lang.json
```

## 변조 보호(Tamper Protection) 비활성화 방법

실시간 보호를 제어하려면 변조 보호를 먼저 비활성화해야 합니다.

1. Windows 보안 열기
   - 프로그램에서 "Windows 보안" 버튼 클릭
   - 또는 Windows 설정 > 개인 정보 및 보안 > Windows 보안
2. "바이러스 및 위협 방지" 클릭
3. "바이러스 및 위협 방지 설정 관리" 클릭
4. "변조 보호"를 OFF로 설정

## 주의사항

### 보안 주의사항
- 실시간 보호를 비활성화하면 컴퓨터가 악성 코드에 취약해집니다
- 신뢰할 수 있는 파일/폴더만 제외 목록에 추가하세요
- 작업 완료 후 실시간 보호를 다시 활성화하는 것을 권장합니다

### 권한 관련
- 이 프로그램은 관리자 권한으로 실행되어야 합니다
- PowerShell 명령을 사용하여 Windows Defender를 제어합니다
- 일부 기업 환경에서는 정책으로 인해 제한될 수 있습니다

### 변조 보호 활성화 시
- 변조 보호가 ON일 경우 프로그램에서 실시간 보호를 제어할 수 없습니다
- 경고 메시지가 표시되며 수동으로 변조 보호를 비활성화해야 합니다

## 기술 정보

### 개발 환경
- Python 3.x
- tkinter (GUI)
- PowerShell (Windows Defender 제어)
- subprocess (명령 실행)

### 사용된 PowerShell 명령어
```powershell
# 실시간 보호 상태 확인
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# 변조 보호 상태 확인
Get-MpComputerStatus | Select-Object IsTamperProtected

# 실시간 보호 활성화
Set-MpPreference -DisableRealtimeMonitoring $false

# 실시간 보호 비활성화
Set-MpPreference -DisableRealtimeMonitoring $true

# 폴더 제외 추가
Add-MpPreference -ExclusionPath "경로"

# 파일 제외 추가
Add-MpPreference -ExclusionPath "파일경로"

# 제외 목록 조회
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

### 빌드 (PyInstaller)
```bash
pyinstaller --onefile --windowed --icon=icon/winDefender.ico --add-data "icon/winDefender.ico;icon" winDefenderControl.py
```

## 문제 해결

### 프로그램이 실행되지 않음
- 관리자 권한으로 실행했는지 확인
- Windows Defender가 활성화되어 있는지 확인
- PowerShell 실행 정책 확인

### 실시간 보호 제어가 작동하지 않음
- 변조 보호가 비활성화되어 있는지 확인
- 그룹 정책으로 제한되어 있는지 확인 (기업 환경)
- Windows 업데이트 상태 확인

### 제외 목록 추가가 실패함
- 경로가 올바른지 확인
- 특수 문자가 포함되어 있는지 확인
- 관리자 권한으로 실행했는지 확인

### 언어 설정이 저장되지 않음
- %APPDATA%\DefenderControl 폴더 접근 권한 확인
- 디스크 공간 확인

## 라이선스

이 프로그램은 개인 및 상업적 용도로 자유롭게 사용할 수 있습니다.

## 면책 조항

이 소프트웨어는 "있는 그대로" 제공되며, 어떠한 명시적 또는 묵시적 보증도 하지 않습니다. 사용자는 자신의 책임 하에 이 프로그램을 사용해야 하며, 개발자는 이 소프트웨어의 사용으로 인해 발생하는 어떠한 손해에 대해서도 책임지지 않습니다.

## 버전 정보

- 현재 버전: 0.2.0
- 마지막 업데이트: 2025
- 지원 OS: Windows 10, Windows 11

## 개발자 노트

### 향후 개선 계획
- 예약 작업 기능 추가
- 실시간 모니터링 로그 기능
- 제외 목록 백업/복원 기능
- 다국어 확장 (중국어, 일본어 등)

### 알려진 제한사항
- 변조 보호는 수동으로만 제어 가능
- 일부 기업 환경에서는 정책으로 인해 제한될 수 있음
- Windows Home 에디션에서는 일부 기능이 제한될 수 있음
