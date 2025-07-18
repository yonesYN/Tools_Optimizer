@ECHO off
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && ""%~s0"" %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )
GOTO Main
:Main
	TITLE %~n0 1.9
	COLOR B
	mode con: cols=83 lines=17
	CLS
	ECHO [1] "Reset Network & Optimiz"
	ECHO [2] "Set DNS"
	ECHO [3] "Service Optimization"
	ECHO [4] "Fix Windows Update"
	ECHO [5] "WinSxS Cleanup"
	ECHO:
	SET /A M=o >nul
	SET /p M=type :
	IF %M%==1 GOTO network
	IF %M%==2 GOTO set_dns
	IF %M%==3 GOTO M_service
	IF %M%==4 GOTO update_fix
	IF %M%==5 GOTO WinSxS_Cleanup
	GOTO Main
:network
	TITLE "Network"
	COLOR B
	mode con: cols=83 lines=17
	CLS
	ECHO [1] "Reset Network"
	ECHO [2] "Optimiz Network"
	ECHO:

	SET /A M=o >nul
	SET /p M=type :
	IF %M%==1 GOTO r_net
	IF %M%==2 GOTO opt_net
	GOTO Main
:r_net
	mode con: cols=83 lines=17
	CLS
	ipconfig /release
	ipconfig /flushdns
	ipconfig /renew
	netsh interface ipv4 reset
	netsh interface ipv6 reset
	nbtstat –r
	netsh int ip reset
	netsh winsock reset
	netsh winhttp reset proxy
	netsh winsock reset proxy
	netsh winsock reset catalog
	ipconfig /flushdns
	netsh int ip reset all
	shutdown /r /t 300 /c "It will restart in 5 minutes"
	GOTO Logo
:opt_net
	mode con: cols=83 lines=17
	CLS
	netsh int tcp set global autotuninglevel=normal
	netsh interface 6to4 set state disabled
	netsh int tcp set global timestamps=disabled
	netsh int tcp set heuristics disabled
	netsh int tcp set heuristics wsh=disabled
	netsh int tcp set global chimney=disabled >nul
	netsh int tcp set global ecncapability=disabled
	netsh int tcp set global nonsackrttresiliency=disabled
	netsh int ip set global icmpredirects=disabled
	netsh int tcp set security mpp=disabled profiles=disabled
	netsh int ip set global multicastforwarding=disabled
	netsh int tcp set supplemental internet congestionprovider=ctcp
	netsh int tcp set global maxsynretransmissions=2
	netsh interface teredo set state disabled
	netsh int isatap set state disabled
	netsh int ip set global taskoffload=disabled
	netsh int tcp set global dca=enabled
	netsh int tcp set global netdma=enabled
	netsh int tcp set global rsc=enabled
	netsh int tcp set global rss=enabled
	netsh int ip set global mediasenseeventlog=disabled
::	netsh int ip set global mldlevel=none
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPDelAckTicks" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
	reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "30" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
	reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
	netsh winsock set autotuning on
	powershell -command "Disable-NetAdapterLso -Name *"
	powershell -command "Disable-NetAdapterPowerManagement -Name *"
	powershell -command "Enable-NetAdapterChecksumOffload -Name * "
	powershell -command "Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled"
	powershell -command "Disable-NetAdapterVmq -Name *"
	powershell -command "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
	powershell -command "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"
	CLS
	ECHO Deleting TMP Files
	RMDIR "%systemroot%\Prefetch\" /S /Q >nul
	RMDIR "%systemroot%\Temp\" /S /Q >nul
	RMDIR "%temp%\" /S /Q >nul
	RMDIR "%LOCALAPPDATA%\D3DSCache\" /S /Q >nul
	RMDIR "%LOCALAPPDATA%\CrashDumps\" /S /Q >nul
	GOTO Logo
:Logo
	mode con: cols=83 lines=17
	CLS
	COLOR 06
	ECHO Y88b   d88P 888b    888
	ECHO  Y88b d88P  8888b   888
	ECHO   Y88o88P   88888b  888
	ECHO    Y888P    888Y88b 888
	ECHO     888     888 Y88b888
	ECHO     888     888  Y88888
	ECHO     888     888   Y8888
	ECHO     888     888    Y888
	timeout 2 >nul
	GOTO Main
:set_dns
	TITLE "Set DNS"
	COLOR B
	mode con: cols=83 lines=17
	CLS
	GOTO M
:M
for /f "delims=" %%F in ('powershell -NoProfile -Command "$ap=(Get-NetAdapter | Where Status -eq 'Up' | Sort-Object InterfaceIndex)[0]; $DNS=(Get-DnsClientServerAddress -InterfaceIndex $ap.ifIndex | Where AddressFamily -eq 2).ServerAddresses -join ' - '; Write-Output ($ap.Name + ': ' + $DNS + 'N')"') do (
    set "sdns=%%F"
)
	SET "inter=%sdns:: =" & rem %
	SET "sdns=%sdns:*: =%"
	IF "%sdns%"=="N" (SET "sdns=None"
GOTO D)
	SET "sdns=%sdns:N=%"
	SET "dns1=%sdns: -=" & SET "dns2=%"
	SET "name=DNS"
	IF "%dns1%"=="8.8.8.8" (SET name=Google)
	IF "%dns1%"=="78.157.42.100" (SET name=Electro)
	IF "%dns1%"=="178.22.122.100" (SET name=Shekan)
	IF "%dns1%"=="94.140.14.14" (SET name=AdGuard)
	IF "%dns1%"=="1.1.1.1" (SET name=Cloudflare)
	IF "%dns1%"=="10.202.10.10" (SET name=Radar.Game)
	IF "%dns1%"=="9.9.9.9" (SET name=Quad9)
	IF "%dns1%"=="209.244.0.3" (SET name=Level3)
	IF "%dns1%"=="208.67.220.220" (SET name=OpenDNS)

FOR /F "tokens=* USEBACKQ" %%F IN (`ping %dns1% -n 1 -w 1000`) DO (SET ping=%%F)
	SET "ping=%ping:,="& rem %
	mode con: cols=83 lines=17
	CLS
	IF "%ping:~,1%" == "M" (ECHO %name%: %sdns%		%ping:Minimum =Ping%
GOTO D)
	ECHO [96mDNS: %sdns:,= - %		Ping=[31mTimeout[96m
GOTO D
:D
	IF "%sdns%"=="None" (ECHO [96mDNS: [31mNone[96m)
	ECHO Interface: %inter%
	ECHO:
	ECHO [0] - Default (DHCP)
	ECHO [1] - Electro
	ECHO [2] - Shekan
	ECHO [3] - Radar.Game
	ECHO [4] - Quad9
	ECHO [5] - Level3
	ECHO [6] - Google
	ECHO [7] - Cloudflare
	ECHO [8] - AdGuard
	ECHO [9] - OpenDNS
	ECHO:
	ECHO [C] Custom DNS
	ECHO [M] Main Menu
	SET d=o
	SET /p d=type:
	IF %d%==0 GOTO DHCP
	IF %d%==1 (SET nd='78.157.42.100','78.157.42.101'
	GOTO rdns)
	IF %d%==2 (SET nd='178.22.122.100','185.51.200.2'
	GOTO rdns)
	IF %d%==3 (SET nd='10.202.10.10','10.202.10.11'
	GOTO rdns)
	IF %d%==4 (SET nd='9.9.9.9','149.112.112.112'
	GOTO rdns)
	IF %d%==5 (SET nd='209.244.0.3','209.244.0.4'
	GOTO rdns)
	IF %d%==6 (SET nd='8.8.8.8','8.8.4.4'
	GOTO rdns)
	IF %d%==7 (SET nd='1.1.1.1','1.0.0.1'
	GOTO rdns)
	IF %d%==8 (SET nd='94.140.14.14','94.140.15.15'
	GOTO rdns)
	IF %d%==9 (SET nd='208.67.222.222','208.67.220.220'
	GOTO rdns)
	IF %d%==C GOTO Custom_DNS
	IF %d%==M GOTO Main
	IF %d%==c GOTO Custom_DNS
	IF %d%==m GOTO Main
	GOTO set_dns
:FL
	COLOR 6
	ECHO Y88b   d88P 888b    888
	ECHO  Y88b d88P  8888b   888
	ECHO   Y88o88P   88888b  888
	ECHO    Y888P    888Y88b 888
	ECHO     888     888 Y88b888
	ECHO     888     888  Y88888
	ECHO     888     888   Y8888
	ECHO     888     888    Y888 [92m
	ipconfig /flushdns >nul
	GOTO M
:DHCP
	CLS
	ECHO Loading...
	netsh interface ipv4 set dnsservers name="%inter%" source=dhcp >nul
	GOTO FL
:Custom_DNS
	CLS
	COLOR D
	TITLE "Custom DNS"
	ECHO [M] MainMenu
	SET DNSa=o
	SET DNSb=o

	SET /p DNSa=DNS1:
		IF %DNSa%==m GOTO set_dns
		IF %DNSa%==M GOTO set_dns
		IF %DNSa%==o GOTO set_dns
	SET /p DNSb=DNS2:
		IF %DNSb%==m GOTO set_dns
		IF %DNSb%==M GOTO set_dns
		IF %DNSb%==o GOTO FL2
	powershell -NoProfile -Command "Set-DnsClientServerAddress -InterfaceAlias '%inter%' -ServerAddresses ('%DNSa%', '%DNSb%')"
	GOTO FL
:FL2
	powershell -NoProfile -Command "Set-DnsClientServerAddress -InterfaceAlias '%inter%' -ServerAddresses ('%DNSa%')"
	GOTO FL
:rdns
	CLS
	ECHO Loading...
	powershell -NoProfile -Command "Set-DnsClientServerAddress -InterfaceAlias '%inter%' -ServerAddresses (%nd%)"
	GOTO FL
:M_service
	TITLE Service Optimization
	mode con: cols=83 lines=17
	cls
	ECHO:
	ECHO [1] - Disable Service LVL1
	ECHO [2] - Disable Service LVL2
	ECHO [3] - Disable Service LVL3
	ECHO [4] - Optimiz Service (Recommended)
	ECHO:
	ECHO [M] Main Menu
	SET /A st=o >nul
	SET /p st=type:
	IF %st%==1 GOTO stop_s
	IF %st%==2 GOTO stop_s2
	IF %st%==3 GOTO stop_s3
	IF %st%==4 GOTO d_service
	GOTO Main
:stop_s
	cls
	TITLE "Stop Windows Services (LVL1)"
	color 3
	echo Stoping Service...
	goto re
:stop_s2
	cls
	TITLE "Stop Windows Services(LVL2)"
	color 3
	echo Stoping Service...
	sc config Dhcp start=auto >nul
	sc config WlanSvc start=demand >nul
	sc config NlaSvc start=auto >nul
	sc config netprofm start=demand >nul
	sc config RmSvc start=demand >nul
	sc start Dhcp >nul
GOTO s
:s
	sc config CDPSvc start=disabled >nul
	sc config DPS start=disabled >nul
	sc config TokenBroker start=disabled >nul
	sc config WpnService start=disabled >nul
	sc config InstallService start=disabled >nul
	sc config UsoSvc start=disabled >nul
	sc config RasMan start=disabled >nul
	sc config wuauserv start=disabled >nul
	sc config NcbService start=disabled >nul
	sc config uhssvc start=disabled >nul
	sc config NDU start=disabled >nul
	sc stop CDPSvc >nul
	sc stop DPS >nul
	sc stop TokenBroker >nul
	sc stop WpnService >nul
	sc stop InstallService >nul
	sc stop UsoSvc >nul
	sc stop NcbService >nul
	sc stop RasMan >nul
	sc stop wuauserv >nul
	sc stop uhssvc >nul
	sc stop swprv >nul
	sc stop NDU >nul
	goto re
:stop_s3
	cls
	TITLE "Stop Windows Services(LVL3)"
	color 3
	echo Stoping Service...
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f >nul
	sc config netprofm start=disabled >nul
	sc config NlaSvc start=disabled >nul
	sc config PSEXESVC start=disabled >nul
	sc config swprv start=disabled >nul
	sc config RmSvc start=disabled >nul
	sc config DsmSvc start=disabled >nul
	sc config SENS start=disabled >nul
	sc config smphost start=disabled >nul
	sc config LicenseManager start=disabled >nul
	sc config VSS start=disabled >nul
	sc config Wecsvc start=disabled >nul
	sc config Dhcp start=disabled >nul
	sc config WFDSConMgrSvc start=disabled >nul
	sc config WlanSvc start=disabled >nul
	sc config lmhosts start=disabled >nul
	sc config FrameServer start=disabled >nul
	sc config Netlogon start=disabled >nul
	sc config LanmanWorkstation start=disabled >nul
	sc config LanmanServer start=disabled >nul
	sc config Themes start=disabled >nul
	sc stop netprofm >nul
	sc stop NlaSvc >nul
	sc stop PSEXESVC >nul
	sc stop Dhcp >nul
	sc stop DsmSvc >nul
	sc stop SENS >nul
	sc stop LicenseManager >nul
	sc stop smphost >nul
	sc stop Wecsvc >nul
	sc stop WFDSConMgrSvc >nul
	sc stop WlanSvc >nul
	sc stop RmSvc >nul
	sc stop DoSvc >nul
	sc stop lmhosts >nul
	sc stop Netlogon >nul
	GOTO s
:update_fix
	cls
	TITLE "Fix Windows Update"
	dism.exe /Online /Cleanup-image /Restorehealth
	sfc /SCANNOW
	gpupdate /force
	net stop wuauserv
	net stop cryptSvc
	net stop bits
	net stop msiserver
	net stop appidsvc
	net stop UsoSvc
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
	shutdown /r /t 120 /c "It will restart in 2 minutes"
	GOTO d_service
:WinSxS_Cleanup
	cls
	TITLE "WinSxS Cleanup"
	Dism.exe /online /Cleanup-Image /StartComponentCleanup
	Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
	Dism.exe /online /Cleanup-Image /SPSuperseded
	schtasks.exe /Run /TN "\Microsoft\Windows\Servicing\StartComponentCleanup"
	GOTO Logo
:d_service
sc config AJRouter start=disabled
sc config ALG start=disabled
sc config AppIDSvc start=demand
sc config Appinfo start=demand
sc config AppMgmt start=disabled
sc config AppReadiness start=demand
sc config AppVClient start=disabled
sc config AppXSvc start=demand
sc config AssignedAccessManagerSvc start=disabled
sc config AudioEndpointBuilder start=auto
sc config Audiosrv start=auto
sc config autotimesvc start=demand
sc config AxInstSV start=disabled
sc config BDESVC start=demand
sc config BFE start=auto
sc config BITS start=delayed-auto
sc config BrokerInfrastructure start=auto
sc config BTAGService start=demand
sc config BthAvctpSvc start=demand
sc config bthserv start=demand
sc config camsvc start=demand
sc config CDPSvc start=delayed-auto
sc config CertPropSvc start=disabled
sc config ClipSVC start=demand
sc config cloudidsvc start=demand
sc config COMSysApp start=demand
sc config CoreMessagingRegistrar start=auto
sc config CryptSvc start=auto
sc config CscService start=disabled
sc config DcomLaunch start=auto
sc config dcsvc start=demand
sc config defragsvc start=demand
sc config DeviceAssociationService start=demand
sc config DeviceInstall start=demand
sc config DevQueryBroker start=demand
sc config Dhcp start=auto
sc config diagnosticshub.standardcollector.service start=disabled
sc config diagsvc start=demand
sc config DiagTrack start=disabled
sc config DialogBlockingService start=disabled
sc config DispBrokerDesktopSvc start=delayed-auto
sc config DisplayEnhancementService start=demand
sc config DmEnrollmentSvc start=demand
sc config dmwappushservice start=disabled
sc config Dnscache start=auto
sc config DoSvc start=demand
sc config dot3svc start=demand
sc config DPS start=auto
sc config DsmSvc start=demand
sc config DsSvc start=demand
sc config DusmSvc start=auto
sc config Eaphost start=demand
sc config EFS start=demand
sc config embeddedmode start=demand
sc config EntAppSvc start=demand
sc config EventLog start=auto
sc config EventSystem start=auto
sc config fdPHost start=demand
sc config FDResPub start=demand
sc config fhsvc start=demand
sc config FontCache start=auto
sc config FontCache3.0.0.0 start=demand
sc config FrameServer start=demand
sc config gpsvc start=auto
sc config GraphicsPerfSvc start=demand
sc config hidserv start=demand
sc config HvHost start=demand
sc config icssvc start=disabled
sc config IKEEXT start=demand
sc config InstallService start=demand
sc config iphlpsvc start=disabled
sc config IpxlatCfgSvc start=demand
sc config KeyIso start=demand
sc config KtmRm start=demand
sc config LanmanServer start=auto
sc config LanmanWorkstation start=auto
sc config lfsvc start=disabled
sc config LicenseManager start=demand
sc config lltdsvc start=demand
sc config lmhosts start=demand
sc config LSM start=auto
sc config LxpSvc start=demand
sc config MapsBroker start=disabled
sc config McpManagementService start=demand
sc config mpssvc start=auto
sc config MSDTC start=demand
sc config MSiSCSI start=demand
sc config msiserver start=demand
sc config MsKeyboardFilter start=disabled
sc config NaturalAuthentication start=demand
sc config NcaSvc start=demand
sc config NcbService start=demand
sc config NcdAutoSetup start=demand
sc config Netlogon start=demand
sc config Netman start=demand
sc config netprofm start=demand
sc config NetSetupSvc start=demand
sc config NetTcpPortSharing start=disabled
sc config NgcCtnrSvc start=demand
sc config NgcSvc start=demand
sc config NlaSvc start=auto
sc config nsi start=auto
sc config NVDisplay.ContainerLocalSystem start=auto
sc config p2pimsvc start=disabled
sc config p2psvc start=disabled
sc config PcaSvc start=demand
sc config PeerDistSvc start=disabled
sc config perceptionsimulation start=demand
sc config PerfHost start=demand
sc config PhoneSvc start=disabled
sc config pla start=demand
sc config PlugPlay start=demand
sc config PNRPAutoReg start=demand
sc config PNRPsvc start=disabled
sc config PolicyAgent start=demand
sc config Power start=auto
sc config PrintNotify start=disabled
sc config ProfSvc start=auto
sc config PushToInstall start=demand
sc config QWAVE start=demand
sc config RasAuto start=demand
sc config RasMan start=auto
sc config RemoteAccess start=disabled
sc config RemoteRegistry start=disabled
sc config RetailDemo start=demand
sc config RmSvc start=demand
sc config RpcEptMapper start=auto
sc config RpcLocator start=demand
sc config RpcSs start=auto
sc config SamSs start=auto
sc config SCardSvr start=disabled
sc config ScDeviceEnum start=demand
sc config Schedule start=auto
sc config SCPolicySvc start=disabled
sc config SDRSVC start=demand
sc config seclogon start=demand
sc config SEMgrSvc start=disabled
sc config SENS start=auto
sc config SensorDataService start=demand
sc config SensorService start=demand
sc config SensrSvc start=demand
sc config SessionEnv start=demand
sc config SharedAccess start=demand
sc config SharedRealitySvc start=demand
sc config ShellHWDetection start=auto
sc config shpamsvc start=disabled
sc config smphost start=demand
sc config SmsRouter start=disabled
sc config SNMPTRAP start=disabled
sc config spectrum start=demand
sc config Spooler start=disabled
sc config sppsvc start=delayed-auto
sc config SSDPSRV start=demand
sc config SstpSvc start=demand
sc config StateRepository start=demand
sc config StiSvc start=demand
sc config StorSvc start=demand
sc config svsvc start=demand
sc config swprv start=demand
sc config SysMain start=disabled
sc config SystemEventsBroker start=auto
sc config TabletInputService start=demand
sc config TapiSrv start=demand
sc config TermService start=disabled
sc config Themes start=auto
sc config TieringEngineService start=demand
sc config TimeBrokerSvc start=demand
sc config TokenBroker start=demand
sc config TrkWks start=disabled
sc config TroubleshootingSvc start=demand
sc config TrustedInstaller start=demand
sc config tzautoupdate start=disabled
sc config UevAgentService start=disabled
sc config UmRdpService start=demand
sc config upnphost start=demand
sc config UserManager start=auto
sc config UsoSvc start=demand
sc config VacSvc start=demand
sc config VaultSvc start=demand
sc config vds start=demand
sc config vmicguestinterface start=demand
sc config vmicheartbeat start=demand
sc config vmickvpexchange start=demand
sc config vmicrdv start=demand
sc config vmicshutdown start=demand
sc config vmictimesync start=demand
sc config vmicvmsession start=demand
sc config vmicvss start=demand
sc config VSS start=demand
sc config W32Time start=demand
sc config WaaSMedicSvc start=demand
sc config WalletService start=demand
sc config WarpJITSvc start=demand
sc config wbengine start=demand
sc config WbioSrvc start=disabled
sc config Wcmsvc start=auto
sc config wcncsvc start=demand
sc config WdiServiceHost start=demand
sc config WdiSystemHost start=demand
sc config WebClient start=disabled
sc config Wecsvc start=demand
sc config WEPHOSTSVC start=demand
sc config wercplsupport start=demand
sc config WerSvc start=disabled
sc config WFDSConMgrSvc start=demand
sc config WiaRpc start=demand
sc config WinHttpAutoProxySvc start=demand
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f
sc config Winmgmt start=auto
sc config WinRM start=disabled
sc config wisvc start=disabled
sc config WlanSvc start=demand
sc config wlidsvc start=demand
sc config wlpasvc start=demand
sc config WManSvc start=demand
sc config wmiApSrv start=demand
sc config WpcMonSvc start=disabled
sc config WpnService start=auto
sc config wscsvc start=delayed-auto
sc config WSearch start=disabled
sc config wuauserv start=demand
sc config WwanSvc start=demand
sc config XblAuthManager start=demand
sc config XblGameSave start=demand
sc config XboxGipSvc start=demand
sc config XboxNetApiSvc start=demand
sc config AarSvc start=demand
sc config BcastDVRUserService start=demand
sc config BluetoothUserService start=demand
sc config CaptureService start=demand
sc config cbdhsvc start=demand
sc config CDPUserSvc start=auto
sc config ConsentUxUserSvc start=demand
sc config CredentialEnrollmentManagerUserSvc start=demand
sc config DeviceAssociationBrokerSvc start=demand
sc config DevicePickerUserSvc start=demand
sc config DevicesFlowUserSvc start=demand
sc config MessagingService start=demand
sc config OneSyncSvc start=delayed-auto
sc config PimIndexMaintenanceSvc start=demand
sc config PrintWorkflowUserSvc start=demand
sc config UdkUserSvc start=demand
sc config UnistoreSvc start=demand
sc config UserDataSvc start=demand
sc config WpnUserService start=auto
sc config Fax start=disabled
goto Logo
:re
sc config AxInstSV start=disabled >nul
sc config AJRouter start=disabled >nul
sc config ALG start=disabled >nul
sc config AppMgmt start=disabled >nul
sc config tzautoupdate start=disabled >nul
sc config BTAGService start=disabled >nul
sc config BITS start=disabled >nul
sc config bthserv start=disabled >nul
sc config DusmSvc start=disabled >nul
sc config PeerDistSvc start=disabled >nul
sc config CertPropSvc start=disabled >nul
sc config DiagTrack start=disabled >nul
sc config DialogBlockingService start=disabled >nul
sc config MapsBroker start=disabled >nul
sc config Fax start=disabled >nul
sc config lfsvc start=disabled >nul
sc config vmickvpexchange start=disabled >nul
sc config vmicguestinterface start=disabled >nul
sc config vmicshutdown start=disabled >nul
sc config vmicheartbeat start=disabled >nul
sc config vmicvmsession start=disabled >nul
sc config vmicrdv start=disabled >nul
sc config vmictimesync start=disabled >nul
sc config vmicvss start=disabled >nul
sc config iphlpsvc start=disabled >nul
sc config AppVClient start=disabled >nul
sc config MSiSCSI start=disabled >nul
sc config MsKeyboardFilter start=disabled >nul
sc config NetTcpPortSharing start=disabled >nul
sc config CscService start=disabled >nul
sc config "ssh-agent" start=disabled >nul
sc config PNRPsvc start=disabled >nul
sc config p2psvc start=disabled >nul
sc config p2pimsvc start=disabled >nul
sc config PolicyAgent start=disabled >nul
sc config PhoneSvc start=disabled >nul
sc config Spooler start=disabled >nul
sc config PcaSvc start=disabled >nul
sc config SessionEnv start=disabled >nul
sc config TermService start=disabled >nul
sc config UmRdpService start=disabled >nul
sc config RpcLocator start=disabled >nul
sc config RemoteRegistry start=disabled >nul
sc config RetailDemo start=disabled >nul
sc config diagnosticshub.standardcollector.service start=disabled >nul
sc config RemoteAccess start=disabled >nul
sc config seclogon start=disabled >nul
sc config shpamsvc start=disabled >nul
sc config SCardSvr start=disabled >nul
sc config ScDeviceEnum start=disabled >nul
sc config SCPolicySvc start=disabled >nul
sc config SNMPTRAP start=disabled >nul
sc config SSDPSRV start=disabled >nul
sc config TabletInputService start=disabled >nul
sc config upnphost start=disabled >nul
sc config UevAgentService start=disabled >nul
sc config WebClient start=disabled >nul
sc config WbioSrvc start=disabled >nul
sc config wcncsvc start=disabled >nul
sc config WerSvc start=disabled >nul
sc config wisvc start=disabled >nul
sc config WMPNetworkSvc start=disabled >nul
sc config icssvc start=disabled >nul
sc config WinRM start=disabled >nul
sc config WSearch start=disabled >nul
sc config wlidsvc start=disabled >nul
sc config XboxGipSvc start=disabled >nul
sc config XblAuthManager start=disabled >nul
sc config XblGameSave start=disabled >nul
sc config XboxNetApiSvc start=disabled >nul
sc config cloudidsvc start=disabled >nul
sc config WpcMonSvc start=disabled >nul
sc config "NvTelemetryContainer" start=disabled >nul
sc config WiaRpc start=disabled >nul
sc config QWAVE start=disabled >nul
sc config KtmRm start=disabled >nul
sc config TrkWks start=disabled >nul
sc config StorSvc start=disabled >nul
sc config pla start=disabled >nul
sc config fhsvc start=disabled >nul
sc config RasAuto start=disabled >nul
sc config stisvc start=disabled >nul
sc config PrintNotify start=disabled >nul
sc config dmwappushservice start=disabled >nul
sc config SmsRouter start=disabled >nul
sc config HomeGroupListener start=disabled >nul
sc config HomeGroupProvider start=disabled >nul
sc config SharedAccess start=disabled >nul
sc config wscsvc start=disabled >nul
sc config VaultSvc start=demand >nul
sc config HvHost start=disabled >nul
sc config BthAvctpSvc start=disabled >nul
sc config TapiSrv start=disabled >nul
sc config SEMgrSvc start=disabled >nul
sc stop AxInstSV >nul
sc stop AJRouter >nul
sc stop ALG >nul
sc stop AppMgmt >nul
sc stop tzautoupdate >nul
sc stop BTAGService >nul
sc stop BITS >nul
sc stop bthserv >nul
sc stop DusmSvc >nul
sc stop PeerDistSvc >nul
sc stop CertPropSvc >nul
sc stop DiagTrack >nul
sc stop DialogBlockingService >nul
sc stop MapsBroker >nul
sc stop Fax >nul
sc stop lfsvc >nul
sc stop vmickvpexchange >nul
sc stop vmicguestinterface >nul
sc stop vmicshutdown >nul
sc stop vmicheartbeat >nul
sc stop vmicvmsession >nul
sc stop vmicrdv >nul
sc stop vmictimesync >nul
sc stop vmicvss >nul
sc stop iphlpsvc >nul
sc stop AppVClient >nul
sc stop MSiSCSI >nul
sc stop MsKeyboardFilter >nul
sc stop NetTcpPortSharing >nul
sc stop CscService >nul
sc stop "ssh-agent" >nul
sc stop PNRPsvc >nul
sc stop p2psvc >nul
sc stop p2pimsvc >nul
sc stop PolicyAgent >nul
sc stop PhoneSvc >nul
sc stop Spooler >nul
sc stop PcaSvc >nul
sc stop SessionEnv >nul
sc stop TermService >nul
sc stop UmRdpService >nul
sc stop RpcLocator >nul
sc stop RemoteRegistry >nul
sc stop RetailDemo >nul
sc stop RemoteAccess >nul
sc stop seclogon >nul
sc stop shpamsvc >nul
sc stop SCardSvr >nul
sc stop ScDeviceEnum >nul
sc stop SCPolicySvc >nul
sc stop SNMPTRAP >nul
sc stop SSDPSRV >nul
sc stop TabletInputService >nul
sc stop upnphost >nul
sc stop UevAgentService >nul
sc stop VSS >nul
sc stop WebClient >nul
sc stop WbioSrvc >nul
sc stop wcncsvc >nul
sc stop WerSvc >nul
sc stop wisvc >nul
sc stop WMPNetworkSvc >nul
sc stop wlidsvc >nul
sc stop W32Time >nul
sc stop Themes >nul
sc stop icssvc >nul
sc stop WinRM >nul
sc stop WSearch >nul
sc stop XboxGipSvc >nul
sc stop XblAuthManager >nul
sc stop XblGameSave >nul
sc stop XboxNetApiSvc >nul
sc stop cloudidsvc >nul
sc stop WpcMonSvc >nul
sc stop WiaRpc >nul
sc stop QWAVE >nul
sc stop KtmRm >nul
sc stop TrkWks >nul
sc stop StorSvc >nul
sc stop pla >nul
sc stop fhsvc >nul
sc stop RasAuto >nul
sc stop stisvc >nul
sc stop embeddedmode >nul
sc stop "NvTelemetryContainer" >nul
sc stop PrintNotify >nul
sc stop dmwappushservice >nul
sc stop diagnosticshub.standardcollector.service >nul
sc stop BthAvctpSvc >nul
sc stop SmsRouter >nul
sc stop sppsvc >nul
sc stop AppXSvc >nul
sc stop TapiSrv >nul
sc stop SEMgrSvc >nul
goto Logo
