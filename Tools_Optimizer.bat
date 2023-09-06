@ECHO off
goto adminCheck
:adminCheck
	mode con: cols=80 lines=15
    net session >nul 2>&1
    IF %errorLevel% == 0 (
		goto Min_Menu
    ) ELSE (
        ECHO Please Run as administrator
		:notAdmin
			title "not_admin"
			color 9
			timeout 1 >nul
			title not_admin
			color b
			timeout 1 >nul
			goto notAdmin
    )
:Min_Menu
	cls
	TITLE %~n0
	COLOR B
	mode con: cols=80 lines=15
	CLS
	ECHO [1] "Reset Network & Optimiz"
	ECHO [2] "Set DNS"
	ECHO [3] "Stop Services (recommended)"
	ECHO [4] "Stop Services L2"
	ECHO [5] "Stop Services L3"
	ECHO [6] "Fix Windows Update"
	ECHO [7] "WinSxS Cleanup"
	
	SET /A M=o >nul
	SET /p M=type :
	IF %M%==1 GOTO network
	IF %M%==2 GOTO set_dns
	IF %M%==3 GOTO stop_service
	IF %M%==4 GOTO stop_service_not
	IF %M%==5 GOTO stop_service_pc
	IF %M%==6 GOTO update_fix
	IF %M%==7 GOTO WinSxS_Cleanup
	GOTO Min_Menu
:network
	cls
	title "Reset Network & Optimiz"
	color 01
	ipconfig /release
	ipconfig /flushdns
	ipconfig /registerdns
	ipconfig /renew
	netsh interface ipv4 reset
	netsh interface ipv6 reset
	ipconfig /flushdns
	nbtstat –r
	netsh int ip reset
	netsh winsock reset
	netsh winhttp reset proxy
	netsh winsock reset proxy
	netsh int ip reset c:\resetlog.txt
	ipconfig /flushdns
	netsh int tcp set global autotuninglevel=normal
	netsh interface 6to4 set state disabled
	netsh int tcp set global timestamps=disabled
	netsh int tcp set heuristics disabled
	netsh int tcp set global chimney=disabled
	netsh int tcp set global ecncapability=disabled
	netsh int tcp set global nonsackrttresiliency=disabled
	netsh int tcp set security mpp=disabled
	netsh int tcp set security profiles=disabled
	netsh int ip set global icmpredirects=disabled
	netsh int tcp set security mpp=disabled profiles=disabled
	netsh int ip set global multicastforwarding=disabled
	netsh int tcp set supplemental internet congestionprovider=ctcp
	netsh interface teredo set state disabled
	netsh int isatap set state disable
	netsh int ip set global taskoffload=disabled
	netsh int tcp set global dca=enabled
	netsh int tcp set global netdma=enabled
	netsh interface tcp set heuristics disabled
	Netsh int set global congestionprovider=ctcp
	netsh int tcp set global rsc=enabled
	netsh int tcp set global rss=enabled
	ipconfig /flushdns
	ipconfig /registerdns
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f
	powershell Disable-NetAdapterLso -Name "*"
	powershell Enable-NetAdapterChecksumOffload –Name * -TcpIPv4 -UdpIPv4
	powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
	powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"
	cls
	echo Deleting Cache Files
	RMDIR "%systemroot%\SoftwareDistribution\" /S /Q >nul
	RMDIR "%systemroot%\Prefetch\" /S /Q >nul
	RMDIR "%systemroot%\Temp\" /S /Q >nul
	RMDIR "%temp%\" /S /Q >nul
	RMDIR "%LOCALAPPDATA%\Package Cache\" /S /Q >nul
	RMDIR "%LOCALAPPDATA%\D3DSCache\" /S /Q >nul
	RMDIR "%LOCALAPPDATA%\CrashDumps\" /S /Q >nul
	GOTO Logo
:Logo
	cls
	mode con: cols=135 lines=36
	color 06
	echo              .::-------------------.        `-:----------------:::::///////+:`                           .:++/////////+++o-`           
	echo             `-oooooooooooooo++/////-        `:++++++++oooooo+/////+osyhhyhhhho.                          ./ooosyhhhhhyssss:`           
	echo               `..:+yyyyyyyyy+-````            ```.-/osssso+-.`     `.+hhhhyhhhy:`                             `-yddms.``               
	echo                   `/yddddddds-                     -shhho-`          -yddhhhhhdh+.                             `oNNN:                  
	echo                     -ydmmmmmds-                   .+ddho.            -hNmddddddmmy:`                           `oMMM:                  
	echo                      -ydmmmmmds.                 .+dmh+`             :dMNysmmmmmNNd+.                          `+MMM-                  
	echo                       -ydmmmmmds.               .+dmh+`              :dMNs`/mNNNNMMNy-                         `/MMM.                  
	echo                        -ydmmmmmdo.             .+dmh/                :dMNs  -hNMMMMMMd+`                       `/MMM.                  
	echo                         -ymmmmmmdo`           .odmy:                 :dMNs   `sNMMMMMMNs.                      `:MMM`                  
	echo                          :ymmmmmmdo`         .oddy:                  :dMNs     :dMMMMMMMd/                      :MMM`                  
	echo                           :ymmmmmmdo`       .oddy-                   :dMNo      .sNMMMMMMms.                   `:MMM`                  
	echo                            /hmmmmmmd+`     .sdds-                    :dMNo       `/dMMMMMMNh:                  `:MMM`                  
	echo                            `/hmmmmmmd+    .sdds-                     :dMNo         -yNMMMMMMmo`                `:MMM`                  
	echo                             `/hmmmmmmd+  -ydms-                      :dMNo          `+dMMMMMMNh-               `:MMM`                  
	echo                              `/dmmmmmmd/:ydmy-                       :dMNo            :yNMMMMMMm/`             `:MMM`                  
	echo                               `+dmmmmmmddmmy-                        :dMNo             .+mMMMMMMNs.            `/MMM`                  
	echo                                .+dmmmmmmmmy-                         :dMNo              `:hMMMMMMMd:`          `/MMM`                  
	echo                                 .ommmmmmmd:                          :dMNo                .oNMMMMMMNo.         `/MMM`                  
	echo                                  -dmmmmmmy.                          :dMNo                 `:dMMMMMMMh:`       `/MMM`                  
	echo                                  -hmmmmmms`                          :dMNo                   .sNMMMMMMmo.      `/MMM`                  
	echo                                  -hmmmmmmo`                          :dMNo                    `:mMMMMMMNh:     `/MMM`                  
	echo                                  -hmmmmmmo`                          :dMNo                      .yNMMMMMMm+.   `/MMM`                  
	echo                                  -hmmmmmmo`                          :mMNs                       `+mMMMMMMNy:  `/MMM`                  
	echo                                  -hmmmmmmo`                          :mMNs                         -yNMMMMMMmo``/MMM`                  
	echo                                  -hmmmmmmo`                          /mMNy                          `+dMMMMMMNh/oMMM.                  
	echo                                  -hmmmmmms`                          /NMMh                            -yNMMMMMMNmMMM.                  
	echo                                  -dmmmmmmh.                          /NMMd                             `+mMMMMMMMMMM.                  
	echo                                `-smmmmmmmms-.`                      .oMMMm.                              -yNMMMMMMMM-                  
	echo                          ./++osydmmmmmmmmmmdhyso+:`            -//+shNMMMMds+//:`                         `+mMMMMMMM-                  
	echo                          /ydddddddddddddddddddddds-           `ymmmmmmmmmmmmmmmd.                           -smNNMMM:                  
	echo                          `.......................`             `````````````````                              `.-/os.                  
	timeout 2 >nul
	GOTO Min_Menu
:set_dns
	TITLE "Set DNS"
	COLOR B
	GOTO M
	:M
	mode con: cols=80 lines=16
	ipconfig /flushdns >null
	powershell -command "Get-DnsClientServerAddress"|findstr /r "[0-9]\." > %temp%\dns.txt

	SET /p sdns=<%temp%\dns.txt
	SET "sdns=%sdns:*{=%"
	SET "sdns=%sdns:}=%"
	SET "sdns=%sdns: =%"
	SET "sdns=%sdns:	=%"
	SET "dns1=%sdns:,=" & SET "dns2=%"
	SET "name=DNS"
	IF %dns1%==8.8.8.8 (set name=Google)
	IF %dns1%==78.157.42.100 (set name=Electro)
	IF %dns1%==78.157.42.101 (set name=Electro)
	IF %dns1%==185.51.200.2 (set name=Shekan)
	IF %dns1%==178.22.122.100 (set name=Shekan)
	IF %dns1%==94.140.14.14 (set name=AdGuard)
	IF %dns1%==1.1.1.1 (set name=Cloudflare)
	IF %dns1%==10.202.10.10 (set name=Radar.Game)
	IF %dns1%==208.67.220.220 (set name=OpenDNS)
	IF %dns1%==208.67.222.222 (set name=OpenDNS)
	IF %dns1%==77.88.8.8 (set name=YandexDNS)
	IF %dns1%==185.228.168.168 (set name=CleanBrowsing)
	ping %dns1% -n 1|findstr /r "Reply" > %temp%\ping.txt
	SET ping=""
	SET /p ping=<%temp%\ping.txt
	SET "ping=%ping:*time=%"
	SET "ping=%ping: =" & rem "%"
	SET "pi=%ping:~1%"
	SET "pg=%pi:ms=%"
	SETLOCAL ENABLEDELAYEDEXPANSION
	SET "pi=!pi:%pg%=!"
	CLS
	if "%pi%" equ "ms" (echo %name%: %sdns:,= - %		ping%ping%) else (color 04
	ECHO %name%: %sdns:,= - %)
	ECHO:
	ECHO [1] - DHCP DNS (Default)
	ECHO [2] - Electro
	ECHO [3] - Shekan
	ECHO [4] - AdGuard
	ECHO [5] - Google
	ECHO [6] - Cloudflare
	ECHO [7] - Radar.Game
	ECHO [8] - OpenDNS
	ECHO [9] - YandexDNS
	ECHO [10] - CleanBrowsing
	ECHO:
	ECHO [C] Custom DNS
	ECHO [M] Min Menu
	SET /A dn=o >nul
	SET /p dn=type :
	ECHO:
	ECHO:
	IF %dn%==1 GOTO DefaultDNS
	IF %dn%==2 GOTO Electro
	IF %dn%==3 GOTO Shekan
	IF %dn%==4 GOTO AdGuard
	IF %dn%==5 GOTO Google
	IF %dn%==6 GOTO Cloudflare
	IF %dn%==7 GOTO Radar.Game
	IF %dn%==8 GOTO OpenDNS
	IF %dn%==9 GOTO YandexDNS
	IF %dn%==10 GOTO CleanBrowsing
	IF %dn%==C GOTO Custom_DNS
	IF %dn%==M GOTO Min_Menu
	IF %dn%==c GOTO Custom_DNS
	IF %dn%==m GOTO Min_Menu
	GOTO set_dns

	:FL
	COLOR 6
	ECHO Loading....
	ECHO Y88b   d88P 888b    888 
	ECHO  Y88b d88P  8888b   888 
	ECHO   Y88o88P   88888b  888 
	ECHO    Y888P    888Y88b 888 
	ECHO     888     888 Y88b888 
	ECHO     888     888  Y88888 
	ECHO     888     888   Y8888 
	ECHO     888     888    Y888
	ipconfig /flushdns >nul
	ipconfig /registerdns >nul
	COLOR A
	GOTO M

	:DefaultDNS
	CLS
	TITLE "Default DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder () >nul
	GOTO FL
	
	:Custom_DNS
	CLS
	COLOR D
	TITLE "Custom DNS"
	ECHO [M] Min_Menu
	SET /p DNSa=DNS1 :
		IF %DNSa%==m GOTO Min_Menu
		IF %DNSa%==M GOTO Min_Menu
	SET /p DNSb=DNS2 :
		IF %DNSb%==m GOTO Min_Menu
		IF %DNSb%==M GOTO Min_Menu
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("%DNSa%", "%DNSb%") >nul
	GOTO FL

	:Electro
	CLS
	TITLE "Electro DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("78.157.42.101", "78.157.42.100") >nul
	GOTO FL

	:Shekan
	CLS
	TITLE "Shekan"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("178.22.122.100", "185.51.200.2") >nul
	GOTO FL

	:AdGuard
	CLS
	TITLE "AdGuard DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("94.140.14.14", "94.140.15.15") >nul
	GOTO FL

	:Google
	CLS
	TITLE "Google DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("8.8.8.8", "8.8.4.4") >nul
	GOTO FL

	:Cloudflare
	CLS
	TITLE "Cloudflare DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("1.1.1.1", "1.0.0.1") >nul
	GOTO FL

	:Radar.Game
	CLS
	TITLE "Radar.Game"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("10.202.10.10", "10.202.10.11") >nul
	GOTO FL

	:OpenDNS
	CLS
	TITLE "OpenDNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("208.67.222.222", "208.67.220.220") >nul
	GOTO FL

	:YandexDNS
	CLS
	TITLE "Yandex DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("77.88.8.8", "77.88.8.1") >nul
	GOTO FL

	:CleanBrowsing
	CLS
	TITLE "CleanBrowsing DNS"
	wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("185.228.168.168", "185.228.169.168") >nul
	GOTO FL

:stop_service
	cls
	TITLE "Stop Windows Services (recommended)"
	color 3
	echo Stoping Service...
	goto re

:stop_service_not
	cls
	TITLE "Stop Windows Services NoteBook"
	color 3
	echo Stoping Service...
	sc config "CDPSvc" start= disabled >nul
	sc config "DusmSvc" start= disabled >nul
	sc config "DPS" start= disabled >nul
	sc config "TokenBroker" start= disabled >nul
	sc config "WpnService" start= disabled >nul
	sc config "InstallService" start= disabled >nul
	sc config "UsoSvc" start= disabled >nul
	sc config "RasMan" start= disabled >nul
	sc config "wuauserv" start= disabled >nul
	
	sc config "NcbService" start= disabled >nul
	sc config "WlanSvc" start= auto >nul
	sc config "RmSvc" start= auto >nul
	sc config "NlaSvc" start= demand >nul
	sc config "netprofm" start= demand >nul

	sc config "swprv" start= disabled >nul
	sc config "RmSvc" start= demand >nul
	color b
	sc stop "CDPSvc" >nul
	sc stop "DusmSvc" >nul
	sc stop "DPS" >nul
	sc stop "TokenBroker" >nul
	sc stop "WpnService" >nul
	sc stop "InstallService" >nul
	sc stop "UsoSvc" >nul
	sc stop "NcbService" >nul
	sc stop "RasMan" >nul
	sc stop "wuauserv" >nul
	sc stop "uhssvc" >nul
	sc start "WlanSvc" >nul
	sc start "NlaSvc" >nul
	sc start "netprofm" >nul

	sc stop "swprv" >nul
	goto re
:stop_service_pc
	cls
	TITLE "Stop Windows Services pc"
	color 3
	echo Stoping Service...
	sc config "CDPSvc" start= disabled >nul
	sc config "DusmSvc" start= disabled >nul
	sc config "DPS" start= disabled >nul
	sc config "netprofm" start= disabled >nul
	sc config "NlaSvc" start= disabled >nul
	sc config "TokenBroker" start= disabled >nul
	sc config "WpnService" start= disabled >nul
	sc config "WpnUserService_30b5f" start= disabled >nul
	sc config "InstallService" start= disabled >nul
	sc config "UsoSvc" start= disabled >nul
	sc config "NcbService" start= disabled >nul
	sc config "RasMan" start= disabled >nul
	sc config "wuauserv" start= disabled >nul
	sc config "PSEXESVC" start= disabled >nul
	sc config "swprv" start= disabled >nul
	sc config "RmSvc" start= disabled >nul
	sc config "cbdhsvc_212fe" start= disabled >nul
	color b
	sc stop "CDPSvc" >nul
	sc stop "DusmSvc" >nul
	sc stop "DPS" >nul
	sc stop "netprofm" >nul
	sc stop "NlaSvc" >nul
	sc stop "TokenBroker" >nul
	sc stop "WpnService" >nul
	sc stop "WpnUserService_30b5f" >nul
	sc stop "InstallService" >nul
	sc stop "UsoSvc" >nul
	sc stop "NcbService" >nul
	sc stop "RasMan" >nul
	sc stop "wuauserv" >nul
	sc stop "uhssvc" >nul
	sc stop "PSEXESVC" >nul
	sc stop "AppXSvc" >nul
	sc stop "swprv" >nul
	sc stop "cbdhsvc_212fe" >nul
	sc stop "Dhcp" >nul
	GOTO re
:update_fix
	cls
	TITLE "Fix Windows Update"
	dism.exe /Online /Cleanup-image /Restorehealth
	net stop wuauserv
	net stop cryptSvc
	net stop bits
	net stop msiserver
	net stop appidsvc
	del /s /q "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\*.*"
	rmdir %systemroot%\SoftwareDistribution /S /Q
	rmdir %systemroot%\system32\catroot2 /S /Q
	netsh winsock reset
	netsh winsock reset proxy
	net start wuauserv
	net start cryptSvc
	net start bits
	net start msiserver
	net start appidsvc
	GOTO Logo
:WinSxS_Cleanup
	cls
	TITLE "WinSxS Cleanup"
	Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
	schtasks.exe /Run /TN "\Microsoft\Windows\Servicing\StartComponentCleanup"
	Dism.exe /online /Cleanup-Image /StartComponentCleanup
	Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
	Dism.exe /online /Cleanup-Image /SPSuperseded
	sfc /SCANNOW
	GOTO Logo
:re
	sc config "AxInstSV" start= disabled >nul
	sc config "AJRouter" start= disabled >nul
	sc config "ALG" start= disabled >nul
	sc config "AppMgmt" start= disabled >nul
	sc config "tzautoupdate" start= disabled >nul
	sc config "BTAGService" start= disabled >nul
	sc config "bthserv" start= disabled >nul
	sc config "PeerDistSvc" start= disabled >nul
	sc config "CertPropSvc" start= disabled >nul
	sc config "DiagTrack" start= disabled >nul
	sc config "DialogBlockingService" start= disabled >nul
	sc config "MapsBroker" start= disabled >nul
	sc config "Fax" start= disabled >nul
	sc config "lfsvc" start= disabled >nul
	sc config "vmickvpexchange" start= disabled >nul
	sc config "vmicguestinterface" start= disabled >nul
	sc config "vmicshutdown" start= disabled >nul
	sc config "vmicheartbeat" start= disabled >nul
	sc config "vmicvmsession" start= disabled >nul
	sc config "vmicrdv" start= disabled >nul
	sc config "vmictimesync" start= disabled >nul
	sc config "vmicvss" start= disabled >nul
	sc config "iphlpsvc" start= disabled >nul
	sc config "AppVClient" start= disabled >nul
	sc config "MSiSCSI" start= disabled >nul
	sc config "MsKeyboardFilter" start= disabled >nul
	sc config "NetTcpPortSharing" start= disabled >nul
	sc config "CscService" start= disabled >nul
	sc config "ssh-agent" start= disabled >nul
	sc config "PNRPsvc" start= disabled >nul
	sc config "p2psvc" start= disabled >nul
	sc config "p2pimsvc" start= disabled >nul
	sc config "PolicyAgent" start= disabled >nul
	sc config "PhoneSvc" start= disabled >nul
	sc config "Spooler" start= disabled >nul
	sc config "PcaSvc" start= disabled >nul
	sc config "SessionEnv" start= disabled >nul
	sc config "TermService" start= disabled >nul
	sc config "UmRdpService" start= disabled >nul
	sc config "RpcLocator" start= disabled >nul
	sc config "RemoteRegistry" start= disabled >nul
	sc config "RetailDemo" start= disabled >nul
	sc config "RemoteAccess" start= disabled >nul
	sc config "seclogon" start= disabled >nul
	sc config "shpamsvc" start= disabled >nul
	sc config "SCardSvr" start= disabled >nul
	sc config "ScDeviceEnum" start= disabled >nul
	sc config "SCPolicySvc" start= disabled >nul
	sc config "SNMPTRAP" start= disabled >nul
	sc config "SSDPSRV" start= disabled >nul
	sc config "TabletInputService" start= disabled >nul
	sc config "upnphost" start= disabled >nul
	sc config "UevAgentService" start= disabled >nul
	sc config "VSS" start= disabled >nul
	sc config "WebClient" start= disabled >nul
	sc config "WbioSrvc" start= disabled >nul
	sc config "wcncsvc" start= disabled >nul
	sc config "WerSvc" start= disabled >nul
	sc config "wisvc" start= disabled >nul
	sc config "WMPNetworkSvc" start= disabled >nul
	sc config "icssvc" start= disabled >nul
	sc config "WinRM" start= disabled >nul
	sc config "WSearch" start= disabled >nul
	sc config "wlidsvc" start= disabled >nul
	sc config "XboxGipSvc" start= disabled >nul
	sc config "XblAuthManager" start= disabled >nul
	sc config "XblGameSave" start= disabled >nul
	sc config "XboxNetApiSvc" start= disabled >nul
	sc config "cloudidsvc" start= disabled >nul
	sc config "WpcMonSvc" start= disabled >nul
	sc config "AMD Crash Defender Service" start= disabled >nul
	sc config "AMD External Events Utility" start= disabled >nul
	sc config "WiaRpc" start= disabled >nul
	sc config "QWAVE" start= disabled >nul
	sc config "KtmRm" start= disabled >nul
	sc config "TrkWks" start= disabled >nul
	sc config "StorSvc" start= disabled >nul
	sc config "pla" start= disabled >nul
	sc config "fhsvc" start= disabled >nul
	sc config "RasAuto" start= disabled >nul
	sc config "stisvc" start= disabled >nul
	sc config "NvTelemetryContainer" start= disabled >nul
	sc config "PrintNotify" start= disable >nul
	sc stop "AxInstSV" >nul
	sc stop "AJRouter" >nul
	sc stop "ALG" >nul
	sc stop "AppMgmt" >nul
	sc stop "tzautoupdate" >nul
	sc stop "BTAGService" >nul
	sc stop "bthserv" >nul
	sc stop "PeerDistSvc" >nul
	sc stop "CertPropSvc" >nul
	sc stop "DiagTrack" >nul
	sc stop "DialogBlockingService" >nul
	sc stop "MapsBroker" >nul
	sc stop "Fax" >nul
	sc stop "lfsvc" >nul
	sc stop "vmickvpexchange" >nul
	sc stop "vmicguestinterface" >nul
	sc stop "vmicshutdown" >nul
	sc stop "vmicheartbeat" >nul
	sc stop "vmicvmsession" >nul
	sc stop "vmicrdv" >nul
	sc stop "vmictimesync" >nul
	sc stop "vmicvss" >nul
	sc stop "iphlpsvc" >nul
	sc stop "AppVClient" >nul
	sc stop "MSiSCSI" >nul
	sc stop "MsKeyboardFilter" >nul
	sc stop "NetTcpPortSharing" >nul
	sc stop "CscService" >nul
	sc stop "ssh-agent" >nul
	sc stop "PNRPsvc" >nul
	sc stop "p2psvc" >nul
	sc stop "p2pimsvc" >nul
	sc stop "PolicyAgent" >nul
	sc stop "PhoneSvc" >nul
	sc stop "Spooler" >nul
	sc stop "PcaSvc" >nul
	sc stop "SessionEnv" >nul
	sc stop "TermService" >nul
	sc stop "UmRdpService" >nul
	sc stop "RpcLocator" >nul
	sc stop "RemoteRegistry" >nul
	sc stop "RetailDemo" >nul
	sc stop "RemoteAccess" >nul
	sc stop "seclogon" >nul
	sc stop "shpamsvc" >nul
	sc stop "SCardSvr" >nul
	sc stop "ScDeviceEnum" >nul
	sc stop "SCPolicySvc" >nul
	sc stop "SNMPTRAP" >nul
	sc stop "SSDPSRV" >nul
	sc stop "TabletInputService"
	sc stop "upnphost" >nul
	sc stop "UevAgentService" >nul
	sc stop "VSS" >nul
	sc stop "WebClient" >nul
	sc stop "WbioSrvc" >nul
	sc stop "wcncsvc" >nul
	sc stop "WerSvc" >nul
	sc stop "wisvc" >nul
	sc stop "WMPNetworkSvc" >nul
	sc stop "wlidsvc" >nul
	sc stop "W32Time" >nul
	sc stop "Themes" >nul
	sc stop "icssvc" >nul
	sc stop "WinRM" >nul
	sc stop "WSearch" >nul
	sc stop "XboxGipSvc" >nul
	sc stop "XblAuthManager" >nul
	sc stop "XblGameSave" >nul
	sc stop "XboxNetApiSvc" >nul
	sc stop "cloudidsvc" >nul
	sc stop "WpcMonSvc" >nul
	sc stop "WiaRpc" >nul
	sc stop "QWAVE" >nul
	sc stop "KtmRm" >nul
	sc stop "TrkWks" >nul
	sc stop "StorSvc" >nul
	sc stop "pla" >nul
	sc stop "fhsvc" >nul
	sc stop "RasAuto" >nul
	sc stop "stisvc" >nul
	sc stop "embeddedmode" >nul
	sc stop "NvTelemetryContainer" >nul
	sc stop "PrintNotify" >nul
	goto Logo
