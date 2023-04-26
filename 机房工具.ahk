;-----------------管理员权限运行----------------
full_command_line := DllCall("GetCommandLine", "str")

if not (A_IsAdmin or RegExMatch(full_command_line, " /restart(?!\S)"))
{
    try
    {
        if A_IsCompiled
            Run '*RunAs "' A_ScriptFullPath '" /restart'
        else
            Run '*RunAs "' A_AhkPath '" /restart "' A_ScriptFullPath '"'
    }
    ExitApp
}
;------------------权限检测--------------------
if (A_IsAdmin)
    User_State := "管理员：是"
else
    User_State := "管理员：否"
a := RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
if (a = 1)
{
    Run_permit := "运行状态：普通用户"
}
else
{
    Run_permit := "运行状态：管理员"
}
权限情况 := User_State "   /   " Run_permit
;------------------授权查询-------------------
content := FileExist("C:\ProgramData\FLEXnet")
if (content = "")
    授权情况 := "授权文件：无"
else
    授权情况 := "授权文件：有"
;------------------防火墙检测------------------
FirewallState := RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall")
if (FirewallState = 1)
{
    防火墙状态 := "防火墙:开"
}
Else
{
    防火墙状态 := "防火墙:关"
}
;------------------IP地址获取------------------
addresses := SysGetIPAddresses()
for address in addresses
    if address != ""
        IP := address
;------------------更新状态读取--------------
try {
    更新状态 := RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "UseWUServer")
} catch Error as err {
    更新按钮 := "禁止更新"
} else {
    更新按钮 := "恢复更新"
}

;------------------INI读取------------------
RoomNum := IniRead("config.ini", "Room", "RoomNum")
Row := IniRead("config.ini", "Room", "Row")
Start := IniRead("config.ini", "Room", "Start")
offset := IniRead("config.ini", "Room", "offset")
adapter := IniRead("config.ini", "Room", "adapter")
;-----------------机房IP设置------------------
机房 := "机房：" RoomNum
if (RoomNum = "201")
{
    IP_Three := "192.168.24."
}
else if (RoomNum = "308")
{
    IP_Three := "192.168.33."
}
else if (RoomNum = "216")
{
    IP_Three := "192.168.26."
}
else if (RoomNum = "311")
{
    IP_Three := "192.168.12."
}
else if (RoomNum = "316")
{
    IP_Three := "192.168.11."
}
else if (RoomNum = "206")
{
    IP_Three := "192.168.25."
}
else if (RoomNum = "209")
{
    IP_Three := "192.168.29."
}
else if (RoomNum = "204")
{
    IP_Three := "192.168.23."
}

if (Row = "A")
{
    IP_Four := Start + (offset * 0) + 100
    IP_Config := IP_Three IP_Four
}
if (Row = "B")
{
    IP_Four := Start + (offset * 1) + 100
    IP_Config := IP_Three IP_Four
}
if (Row = "C")
{
    IP_Four := Start + (offset * 2) + 100
    IP_Config := IP_Three IP_Four
}
if (Row = "D")
{
    IP_Four := Start + (offset * 3) + 100
    IP_Config := IP_Three IP_Four
}
if (Row = "E")
{
    IP_Four := Start + (offset * 4) + 100
    IP_Config := IP_Three IP_Four
}
计算机名称 := RoomNum Row Start

;------------------基础网络配置------------------
mask := "255.255.255.0" ;子网掩码
gateway := IP_Three "1" ;默认网关
dns := "114.114.114.114" ;DNS

;------------------检测以太网卡是否被禁用------------------
ConnectedToTheInternet(flag := 0x40) {
    Return DllCall("Wininet.dll\InternetGetConnectedState", "Str", flag, "Int", 0)
}
; adapter := "以太网" ; Adapter Name
if ConnectedToTheInternet()
    网络状态 := "网络：已连接"
else
    网络状态 := "网络：未连接"
;------------------------------------
MyGui := Gui()
MyGui.Title := 机房
myGui.SetFont("s12", "Segoe UI")
COM名字 := MyGui.Add("Text", "w290 h50 + 0x200 + Center + 0x1000 ", A_ComputerName)
IP地址 := MyGui.Add("Text", "w290 h50 + 0x200 + Center + 0x1000 xs Section", IP)
; MyGui.Add("Text", "w135 h50 + 0x200 + Center + 0x1000 ys", IP)
C_Config := MyGui.Add("Text", "w290 w290 h50 + 0x200 + Center + 0x1000 Section xs", "Config:  " 计算机名称 "   /   " IP_Config)
myGui.SetFont("s9", "Segoe UI")
Row_A := MyGui.Add("Button", "w46 Section y+25", "A")
Row_A.OnEvent("Click", A组)
Row_B := MyGui.Add("Button", "w46 ys", "B")
Row_B.OnEvent("Click", B组)
Row_C := MyGui.Add("Button", "w46 ys", "C")
Row_C.OnEvent("Click", C组)
Row_D := MyGui.Add("Button", "w46 ys", "D")
Row_D.OnEvent("Click", D组)
Row_E := MyGui.Add("Button", "w46 ys", "E")
Row_E.OnEvent("Click", E组)
手改 := MyGui.Add("Button", "w138 h32 Section xs", "手动修改")
手改.OnEvent("Click", 手动修改)
自改 := MyGui.Add("Button", "w138 h32 ys", "自动修改")
自改.OnEvent("Click", 自动修改)
独改IP := MyGui.Add("Button", "w138 h32 Section xs", "单独改 IP")
独改IP.OnEvent("Click", 单改IP)
睡眠 := MyGui.Add("Button", "w138 h32 ys", "防止睡眠")
睡眠.OnEvent("Click", 防止睡眠)
更新 := MyGui.Add("Button", "w138 h32 Section xs", 更新按钮)
更新.OnEvent("Click", 禁止更新)
网络 := MyGui.Add("Button", "w138 h32 ys", 网络状态)
网络.OnEvent("Click", 一键网络)
防火 := MyGui.Add("Button", "w138 h32 Section xs", 防火墙状态)
防火.OnEvent("Click", 防火墙)
删权 := MyGui.Add("Button", "w138 h32 ys", 授权情况)
删权.OnEvent("Click", 删除授权)
提权 := MyGui.Add("Button", "w290 h32 Section xs", 权限情况)
提权.OnEvent("Click", 提升权限)
底栏 := MyGui.Add("StatusBar", , "      本工具由郑信商学院夏岩老师编写。")
MyGui.Show

手动修改(*)
{
    IB_CONTENT := "IP   :   " IP_Three "x"
    IB_TITLE := RoomNum "修改"
    IB := InputBox(IB_CONTENT, IB_TITLE, "w100 h120", "请输入第四位IP")
    IIP := IP_Three IB.Value
    CMD改IP及DNS(adapter, IIP, mask, gateway, dns)
    IP地址.Opt ("c0xFF0000")
    IP地址.Text := IIP " ( 已修改 ) "
    IB := InputBox(IB_CONTENT, IB_TITLE, "w100 h120", "请输入排+号")
    CCOM名字 := RoomNum IB.Value
    注册表改计算机名称(CCOM名字)
    COM名字.Opt ("c0xFF0000")
    COM名字.Text := CCOM名字 " ( 已修改 ) "
    底栏.Text := "手动修改IP电脑名称功能已生效！！！"
}

A组(*)
{
    IniWrite("A", "config.ini", "Room", "Row")
    IniWrite("1", "config.ini", "Room", "Start")
    Row := IniRead("config.ini", "Room", "Row")
    Start := IniRead("config.ini", "Room", "Start")
    IP_Four := Start + (offset * 0) + 100
    C_Config.Opt ("c0xFF0000")
    C_Config.Text := "Config:  " RoomNum Row Start "   /   " IP_Three IP_Four
}

B组(*)
{
    IniWrite("B", "config.ini", "Room", "Row")
    IniWrite("1", "config.ini", "Room", "Start")
    Row := IniRead("config.ini", "Room", "Row")
    Start := IniRead("config.ini", "Room", "Start")
    IP_Four := Start + (offset * 1) + 100
    C_Config.Opt ("c0xFF0000")
    C_Config.Text := "Config:  " RoomNum Row Start "   /   " IP_Three IP_Four
}

C组(*)
{
    IniWrite("C", "config.ini", "Room", "Row")
    IniWrite("1", "config.ini", "Room", "Start")
    Row := IniRead("config.ini", "Room", "Row")
    Start := IniRead("config.ini", "Room", "Start")
    IP_Four := Start + (offset * 2) + 100
    C_Config.Opt ("c0xFF0000")
    C_Config.Text := "Config:  " RoomNum Row Start "   /   " IP_Three IP_Four
}

D组(*)
{
    IniWrite("D", "config.ini", "Room", "Row")
    IniWrite("1", "config.ini", "Room", "Start")
    Row := IniRead("config.ini", "Room", "Row")
    Start := IniRead("config.ini", "Room", "Start")
    IP_Four := Start + (offset * 3) + 100
    C_Config.Opt ("c0xFF0000")
    C_Config.Text := "Config:  " RoomNum Row Start "   /   " IP_Three IP_Four
}

E组(*)
{
    IniWrite("E", "config.ini", "Room", "Row")
    IniWrite("1", "config.ini", "Room", "Start")
    Row := IniRead("config.ini", "Room", "Row")
    Start := IniRead("config.ini", "Room", "Start")
    IP_Four := Start + (offset * 4) + 100
    C_Config.Opt ("c0xFF0000")
    C_Config.Text := "Config:  " RoomNum Row Start "   /   " IP_Three IP_Four
}

自动修改(*)
{
    Row := IniRead("config.ini", "Room", "Row")
    Start := IniRead("config.ini", "Room", "Start")

    if (Row = "A")
    {
        IP_Four := Start + (offset * 0) + 100
        IP_Config := IP_Three IP_Four
    }
    if (Row = "B")
    {
        IP_Four := Start + (offset * 1) + 100
        IP_Config := IP_Three IP_Four
    }
    if (Row = "C")
    {
        IP_Four := Start + (offset * 2) + 100
        IP_Config := IP_Three IP_Four
    }
    if (Row = "D")
    {
        IP_Four := Start + (offset * 3) + 100
        IP_Config := IP_Three IP_Four
    }
    if (Row = "E")
    {
        IP_Four := Start + (offset * 4) + 100
        IP_Config := IP_Three IP_Four
    }
    计算机名称 := RoomNum Row Start
    CMD改IP及DNS(adapter, IP_Config, mask, gateway, dns)
    注册表改计算机名称(计算机名称)
    IP地址.Opt ("c0xFF0000")
    IP地址.Text := IP_Config " ( 已修改 ) "
    COM名字.Opt ("c0xFF0000")
    COM名字.Text := 计算机名称 " ( 已修改 ) "
    Starts := Start + 1
    IniWrite(Starts, "config.ini", "Room", "Start")
    底栏.Text := "自动修改IP电脑名称功能已生效！！！"
}

单改IP(*)
{
    IB_CONTENT := "IP   :   xxx.xxx.xxx.xxx"
    IB_TITLE := RoomNum "修改"
    IB := InputBox(IB_CONTENT, IB_TITLE, "w100 h120", "请输入IP")
    IIP := IB.Value
    CMD改IP及DNS(adapter, IIP, mask, gateway, dns)
    IP地址.Opt ("c0xFF0000")
    IP地址.Text := IIP " ( 已修改 ) "
    底栏.Text := "单独改IP功能已生效！！！"
}

防止睡眠(*)
{
    Run(A_ComSpec " /c powercfg -change -standby-timeout-dc 0", , "hide")
    Run(A_ComSpec " /c powercfg -change -standby-timeout-ac 0", , "hide")
    Run(A_ComSpec " /c powercfg -change -disk-timeout-dc 0", , "hide")
    Run(A_ComSpec " /c powercfg -change -disk-timeout-ac 0", , "hide")
    Run(A_ComSpec " /c powercfg -change -monitor-timeout-ac 0", , "hide")
    Run(A_ComSpec " /c powercfg -change -monitor-timeout-dc 0", , "hide")
    底栏.Text := "      睡眠已禁用，电脑将不会自动进入休眠！！！"
}

禁止更新(*)
{
    if (更新.Text = "恢复更新")
    {
        RegDeleteKey("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")
        更新.Text := "禁止更新"
    }
    else
    {
        RegWrite("127.0.0.1", "REG_SZ", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "UpdateServiceUrlAlternate")
        RegWrite("127.0.0.1", "REG_SZ", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer")
        RegWrite("127.0.0.1", "REG_SZ", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUStatusServer")
        RegWrite("0", "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AutoInstallMinorUpdates")
        RegWrite("1", "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAUAsDefaultShutdownOption")
        RegWrite("1", "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAUShutdownOption")
        RegWrite("1", "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate")
        RegWrite("1", "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "UseWUServer")
        更新.Text := "恢复更新"
    }
}

一键网络(*)
{
    if (网络.Text = "网络：已连接")
    {
        RunWait("netsh interface set interface `"" adapter "`" admin=disabled", , "hide")
        网络.Text := "网络：未连接"
    }
    else
    {
        RunWait("netsh interface set interface `"" adapter "`" admin=enable", , "hide")
        网络.Text := "网络：已连接"
    }
}

防火墙(*)
{
    if (防火.Text = "防火墙:开")
    {
        Run(A_ComSpec " /c netsh advfirewall set allprofiles state off", , "hide")
        防火.Text := "防火墙:关"
    }
    else
    {
        Run(A_ComSpec " /c netsh advfirewall set allprofiles state on", , "hide")
        防火.Text := "防火墙:开"
    }

}

删除授权(*)
{
    if (删权.Text = "授权文件：无")
    {
        底栏.Text := "      AUTOCAD和REVit等软件的无授权！！！"
    }
    else
    {
        FileDelete("C:\ProgramData\FLEXnet\*")
        底栏.Text := "      AUTOCAD和REVit等软件的授权已删除！！！"
        删权.Text := "授权文件：无"
    }

}

提升权限(*)
{
    if (提权.Text = "管理员：是   /   运行状态：管理员")
    {
        RunWait(A_ComSpec " /c net localgroup administrators " A_UserName " /add", , "Hide")
        RegWrite(1, "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        底栏.Text := "      账户权限已提升,软件并不以管理员方式运行！"
        提权.Text := "管理员：是   /   运行状态：普通用户"
    }
    else
    {
        RunWait(A_ComSpec " /c net localgroup administrators " A_UserName " /add", , "Hide")
        RegWrite(0, "REG_DWORD", "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        底栏.Text := "      账户权限已提升,软件以管理员权限运行！"
        提权.Text := "管理员：是   /   运行状态：管理员"
    }
}

注册表改计算机名称(计算机名称)
{
    RegWrite(计算机名称, "REG_SZ", "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName")
    RegWrite(计算机名称, "REG_SZ", "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ComputerName\ActiveComputerName", "ComputerName")
    RegWrite(计算机名称, "REG_SZ", "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters", "Hostname")
    RegWrite(计算机名称, "REG_SZ", "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters", "NV Hostname")
    RegWrite(计算机名称, "REG_SZ", "HKEY_LOCAL_MACHINE\System\CurrentControlSet001\Control\ComputerName\ComputerName", "ComputerName")
    RegWrite(计算机名称, "REG_SZ", "HKEY_LOCAL_MACHINE\System\CurrentControlSet001\Control\ComputerName\ActiveComputerName", "ComputerName")
}

CMD改IP及DNS(adapter, IP_Config, mask, gateway, dns)
{
    RunWait("netsh interface ip set address name=" adapter " source=static addr=" IP_Config " mask=" mask " gateway=" gateway " gwmetric=10", , "Hide")
    RunWait("netsh interface ip set dns name=" adapter " source=static addr=" dns, "", "Hide")
}