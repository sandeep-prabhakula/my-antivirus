import "pe"
import "hash"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Rules that are included in several other files.
*/

private rule is__elf {
	meta:
		author = "@mmorenog,@yararules"
	strings:
		$header = { 7F 45 4C 46 }
	condition:
		$header at 0
}


rule is__Mirai_gen7 {
        meta:
                description = "Generic detection for MiraiX version 7"
                reference = "http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html"
                author = "unixfreaxjp"
                org = "MalwareMustDie"
                date = "2018-01-05"

        strings:
                $st01 = "/bin/busybox rm" fullword nocase wide ascii
                $st02 = "/bin/busybox echo" fullword nocase wide ascii
                $st03 = "/bin/busybox wget" fullword nocase wide ascii
                $st04 = "/bin/busybox tftp" fullword nocase wide ascii
                $st05 = "/bin/busybox cp" fullword nocase wide ascii
                $st06 = "/bin/busybox chmod" fullword nocase wide ascii
                $st07 = "/bin/busybox cat" fullword nocase wide ascii

        condition:
                5 of them
}

rule LIGHTDART_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "ret.log" wide ascii
        $s2 = "Microsoft Internet Explorer 6.0" wide ascii
        $s3 = "szURL Fail" wide ascii
        $s4 = "szURL Successfully" wide ascii
        $s5 = "%s&sdate=%04ld-%02ld-%02ld" wide ascii

    condition:
        all of them
}

rule AURIGA_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "superhard corp." wide ascii
        $s2 = "microsoft corp." wide ascii
        $s3 = "[Insert]" wide ascii
        $s4 = "[Delete]" wide ascii
        $s5 = "[End]" wide ascii
        $s6 = "!(*@)(!@KEY" wide ascii
        $s7 = "!(*@)(!@SID=" wide ascii

    condition:
        all of them
}

rule AURIGA_driver_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Services\\riodrv32" wide ascii
        $s2 = "riodrv32.sys" wide ascii
        $s3 = "svchost.exe" wide ascii
        $s4 = "wuauserv.dll" wide ascii
        $s5 = "arp.exe" wide ascii
        $pdb = "projects\\auriga" wide ascii

    condition:
        all of ($s*) or $pdb
}

rule BANGAT_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "superhard corp." wide ascii
        $s2 = "microsoft corp." wide ascii
        $s3 = "[Insert]" wide ascii
        $s4 = "[Delete]" wide ascii
        $s5 = "[End]" wide ascii
        $s6 = "!(*@)(!@KEY" wide ascii
        $s7 = "!(*@)(!@SID=" wide ascii
        $s8 = "end      binary output" wide ascii
        $s9 = "XriteProcessMemory" wide ascii
        $s10 = "IE:Password-Protected sites" wide ascii
        $s11 = "pstorec.dll" wide ascii

    condition:
        all of them
}

rule BISCUIT_GREENCAT_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "zxdosml" wide ascii
        $s2 = "get user name error!" wide ascii
        $s3 = "get computer name error!" wide ascii
        $s4 = "----client system info----" wide ascii
        $s5 = "stfile" wide ascii
        $s6 = "cmd success!" wide ascii

    condition:
        all of them
}

rule BOUNCER_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
        $s2 = "IDR_DATA%d" wide ascii
        $s3 = "asdfqwe123cxz" wide ascii
        $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii

    condition:
        ($s1 and $s2) or ($s3 and $s4)
}

rule BOUNCER_DLL_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "new_connection_to_bounce():" wide ascii
        $s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

    condition:
        all of them
}

rule CALENDAR_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
       
    strings:
        $s1 = "content" wide ascii
        $s2 = "title" wide ascii
        $s3 = "entry" wide ascii
        $s4 = "feed" wide ascii
        $s5 = "DownRun success" wide ascii
        $s6 = "%s@gmail.com" wide ascii
        $s7 = "<!--%s-->" wide ascii
        $b8 = "W4qKihsb+So=" wide ascii
        $b9 = "PoqKigY7ggH+VcnqnTcmhFCo9w==" wide ascii
        $b10 = "8oqKiqb5880/uJLzAsY=" wide ascii

    condition:
        all of ($s*) or all of ($b*)
}

rule COMBOS_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Mozilla4.0 (compatible; MSIE 7.0; Win32)" wide ascii
        $s2 = "Mozilla5.1 (compatible; MSIE 8.0; Win32)" wide ascii
        $s3 = "Delay" wide ascii
        $s4 = "Getfile" wide ascii
        $s5 = "Putfile" wide ascii
        $s6 = "---[ Virtual Shell]---" wide ascii
        $s7 = "Not Comming From Our Server %s." wide ascii

    condition:
        all of them
}

rule DAIRY_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Mozilla/4.0 (compatible; MSIE 7.0;)" wide ascii
        $s2 = "KilFail" wide ascii
        $s3 = "KilSucc" wide ascii
        $s4 = "pkkill" wide ascii
        $s5 = "pklist" wide ascii

    condition:
        all of them
}

rule GLOOXMAIL_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Kill process success!" wide ascii
        $s2 = "Kill process failed!" wide ascii
        $s3 = "Sleep success!" wide ascii
        $s4 = "based on gloox" wide ascii
        $pdb = "glooxtest.pdb" wide ascii

    condition:
        all of ($s*) or $pdb
}

rule GOGGLES_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Kill process success!" wide ascii
        $s2 = "Kill process failed!" wide ascii
        $s3 = "Sleep success!" wide ascii
        $s4 = "based on gloox" wide ascii
        $pdb = "glooxtest.pdb" wide ascii

    condition:
        all of ($s*) or $pdb
}

rule HACKSFASE1_APT1
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = {cb 39 82 49 42 be 1f 3a}

    condition:
        all of them
}

rule HACKSFASE2_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Send to Server failed." wide ascii
        $s2 = "HandShake with the server failed. Error:" wide ascii
        $s3 = "Decryption Failed. Context Expired." wide ascii

    condition:
        all of them
}

rule KURTON_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Mozilla/4.0 (compatible; MSIE8.0; Windows NT 5.1)" wide ascii
        $s2 = "!(*@)(!@PORT!(*@)(!@URL" wide ascii
        $s3 = "MyTmpFile.Dat" wide ascii
        $s4 = "SvcHost.DLL.log" wide ascii

    condition:
        all of them
}

rule LONGRUN_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" wide ascii
        $s2 = "%s\\%c%c%c%c%c%c%c" wide ascii
        $s3 = "wait:" wide ascii
        $s4 = "Dcryption Error! Invalid Character" wide ascii

    condition:
        all of them
}

rule MACROMAIL_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "svcMsn.dll" wide ascii
        $s2 = "RundllInstall" wide ascii
        $s3 = "Config service %s ok." wide ascii
        $s4 = "svchost.exe" wide ascii

    condition:
        all of them
}

rule MANITSME_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Install an Service hosted by SVCHOST." wide ascii
        $s2 = "The Dll file that to be released." wide ascii
        $s3 = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
        $s4 = "svchost.exe" wide ascii
        $e1 = "Man,it's me" wide ascii
        $e2 = "Oh,shit" wide ascii
        $e3 = "Hallelujah" wide ascii
        $e4 = "nRet == SOCKET_ERROR" wide ascii
        $pdb1 = "rouji\\release\\Install.pdb" wide ascii
        $pdb2 = "rouji\\SvcMain.pdb" wide ascii

    condition:
        (all of ($s*)) or (all of ($e*)) or $pdb1 or $pdb2
}

rule MINIASP_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "miniasp" wide ascii
        $s2 = "wakeup=" wide ascii
        $s3 = "download ok!" wide ascii
        $s4 = "command is null!" wide ascii
        $s5 = "device_input.asp?device_t=" wide ascii

    condition:
        all of them
}

rule NEWSREELS_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" wide ascii
        $s2 = "name=%s&userid=%04d&other=%c%s" wide ascii
        $s3 = "download ok!" wide ascii
        $s4 = "command is null!" wide ascii
        $s5 = "noclient" wide ascii
        $s6 = "wait" wide ascii
        $s7 = "active" wide ascii
        $s8 = "hello" wide ascii

    condition:
        all of them
}

rule SEASALT_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
      
    strings:
        $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.00; Windows 98) KSMM" wide ascii
        $s2 = "upfileok" wide ascii
        $s3 = "download ok!" wide ascii
        $s4 = "upfileer" wide ascii
        $s5 = "fxftest" wide ascii

    condition:
        all of them
}

rule STARSYPOUND_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "*(SY)# cmd" wide ascii
        $s2 = "send = %d" wide ascii
        $s3 = "cmd.exe" wide ascii
        $s4 = "*(SY)#" wide ascii

    condition:
        all of them
}

rule SWORD_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
       
    strings:
        $s1 = "@***@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>>>" wide ascii
        $s2 = "sleep:" wide ascii
        $s3 = "down:" wide ascii
        $s4 = "*========== Bye Bye ! ==========*" wide ascii

    condition:
        all of them
}

rule thequickbrow_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "thequickbrownfxjmpsvalzydg" wide ascii

    condition:
        all of them
}

rule TABMSGSQL_APT1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "letusgohtppmmv2.0.0.1" wide ascii
        $s2 = "Mozilla/4.0 (compatible; )" wide ascii
        $s3 = "filestoc" wide ascii
        $s4 = "filectos" wide ascii
        $s5 = "reshell" wide ascii

    condition:
        all of them
}

rule CCREWBACK1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "postvalue" wide ascii
        $b = "postdata" wide ascii
        $c = "postfile" wide ascii
        $d = "hostname" wide ascii
        $e = "clientkey" wide ascii
        $f = "start Cmd Failure!" wide ascii
        $g = "sleep:" wide ascii
        $h = "downloadcopy:" wide ascii
        $i = "download:" wide ascii
        $j = "geturl:" wide ascii
        $k = "1.234.1.68" wide ascii

    condition:
        4 of ($a,$b,$c,$d,$e) or $f or 3 of ($g,$h,$i,$j) or $k
}

rule TrojanCookies_CCREW
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
     strings:
        $a = "sleep:" wide ascii
        $b = "content=" wide ascii
        $c = "reqpath=" wide ascii
        $d = "savepath=" wide ascii
        $e = "command=" wide ascii

    condition:
        4 of ($a,$b,$c,$d,$e)
}

rule GEN_CCREW1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "W!r@o#n$g" wide ascii
        $b = "KerNel32.dll" wide ascii

    condition:
        any of them
}

rule Elise
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
       
    strings:
        $a = "SetElise.pdb" wide ascii

    condition:
        $a
}

rule EclipseSunCloudRAT
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "Eclipse_A" wide ascii
        $b = "\\PJTS\\" wide ascii
        $c = "Eclipse_Client_B.pdb" wide ascii
        $d = "XiaoME" wide ascii
        $e = "SunCloud-Code" wide ascii
        $f = "/uc_server/data/forum.asp" wide ascii

    condition:
        any of them
}

rule MoonProject
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
       
    strings:
        $a = "Serverfile is smaller than Clientfile" wide ascii
        $b = "\\M tools\\" wide ascii
        $c = "MoonDLL" wide ascii
        $d = "\\M tools\\" wide ascii

  condition:
        any of them
}

rule ccrewDownloader1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = {DD B5 61 F0 20 47 20 57 D6 65 9C CB 31 1B 65 42}

    condition:
        any of them
}

rule ccrewDownloader2
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "3gZFQOBtY3sifNOl" wide ascii
        $b = "docbWUWsc2gRMv9HN7TFnvnKcrWUUFdAEem9DkqRALoD" wide ascii
        $c = "6QVSOZHQPCMc2A8HXdsfuNZcmUnIqWrOIjrjwOeagILnnScxadKEr1H2MZNwSnaJ" wide ascii

    condition:
        any of them
}

rule ccrewMiniasp
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        

  strings:
        $a = "MiniAsp.pdb" wide ascii
        $b = "device_t=" wide ascii

  condition:
        any of them
}

rule ccrewSSLBack2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = {39 82 49 42 BE 1F 3A}

    condition:
        any of them
}

rule ccrewSSLBack3
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "SLYHKAAY" wide ascii

  condition:
        any of them
}

rule ccrewSSLBack1
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "!@#%$^#@!" wide ascii
        $b = "64.91.80.6" wide ascii

  condition:
        any of them
}

rule ccrewDownloader3
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "ejlcmbv" wide ascii
        $b = "bhxjuisv" wide ascii
        $c = "yqzgrh" wide ascii
        $d = "uqusofrp" wide ascii
        $e = "Ljpltmivvdcbb" wide ascii
        $f = "frfogjviirr" wide ascii
        $g = "ximhttoskop" wide ascii

    condition:
        4 of them
}

rule ccrewQAZ
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "!QAZ@WSX" wide ascii

  condition:
        $a
}

rule metaxcd
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "<meta xcd=" wide ascii

    condition:
        $a
}

rule MiniASP
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $KEY = { 71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A }
        $PDB = "MiniAsp.pdb" nocase wide ascii

    condition:
        any of them
}

rule DownloaderPossibleCCrew
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $a = "%s?%.6u" wide ascii
        $b = "szFileUrl=%s" wide ascii
        $c = "status=%u" wide ascii
        $d = "down file success" wide ascii
        $e = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" wide ascii

  condition:
        all of them
}

rule APT1_MAPIGET
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "%s\\Attachment.dat" wide ascii
        $s2 = "MyOutlook" wide ascii
        $s3 = "mail.txt" wide ascii
        $s4 = "Recv Time:" wide ascii
        $s5 = "Subject:" wide ascii

    condition:
       all of them
}

rule APT1_LIGHTBOLT
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $str1 = "bits.exe" wide ascii
        $str2 = "PDFBROW" wide ascii
        $str3 = "Browser.exe" wide ascii
        $str4 = "Protect!" wide ascii

    condition:
        2 of them
}

rule APT1_GETMAIL
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $stra1 = "pls give the FULL path" wide ascii
        $stra2 = "mapi32.dll" wide ascii
        $stra3 = "doCompress" wide ascii
        $strb1 = "getmail.dll" wide ascii
        $strb2 = "doCompress" wide ascii
        $strb3 = "love" wide ascii

    condition:
        all of ($stra*) or all of ($strb*)
}

rule APT1_GDOCUPLOAD
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $str1 = "name=\"GALX\"" wide ascii
        $str2 = "User-Agent: Shockwave Flash" wide ascii
        $str3 = "add cookie failed..." wide ascii
        $str4 = ",speed=%f" wide ascii

    condition:
        3 of them
}

rule APT1_WEBC2_Y21K
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "Y29ubmVjdA" wide ascii // connect
        $2 = "c2xlZXA" wide ascii // sleep
        $3 = "cXVpdA" wide ascii // quit
        $4 = "Y21k" wide ascii // cmd
        $5 = "dW5zdXBwb3J0" wide ascii // unsupport

    condition:
        4 of them
}

rule APT1_WEBC2_YAHOO
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $http1 = "HTTP/1.0" wide ascii
        $http2 = "Content-Type:" wide ascii
        $uagent = "IPHONE8.5(host:%s,ip:%s)" wide ascii

    condition:
        all of them
}

rule APT1_WEBC2_UGX
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $persis = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide ascii
        $exe = "DefWatch.exe" wide ascii
        $html = "index1.html" wide ascii
        $cmd1 = "!@#tiuq#@!" wide ascii
        $cmd2 = "!@#dmc#@!" wide ascii
        $cmd3 = "!@#troppusnu#@!" wide ascii

    condition:
        3 of them
}

rule APT1_WEBC2_TOCK
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "InprocServer32" wide ascii
        $2 = "HKEY_PERFORMANCE_DATA" wide ascii
        $3 = "<!---[<if IE 5>]id=" wide ascii

    condition:
        all of them
}

rule APT1_WEBC2_TABLE
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $msg1 = "Fail To Execute The Command" wide ascii
        $msg2 = "Execute The Command Successfully" wide ascii
        /*
    	$gif1 = /\w+\.gif/
    	*/
        $gif2 = "GIF89" wide ascii

    condition:
        3 of them
}

rule APT1_WEBC2_RAVE
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "iniet.exe" wide ascii
        $2 = "cmd.exe" wide ascii
        $3 = "SYSTEM\\CurrentControlSet\\Services\\DEVFS" wide ascii
        $4 = "Device File System" wide ascii

    condition:
        3 of them
}

rule APT1_WEBC2_QBP
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "2010QBP" wide ascii
        $2 = "adobe_sl.exe" wide ascii
        $3 = "URLDownloadToCacheFile" wide ascii
        $4 = "dnsapi.dll" wide ascii
        $5 = "urlmon.dll" wide ascii

    condition:
        4 of them
}

rule APT1_WEBC2_HEAD
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "Ready!" wide ascii
        $2 = "connect ok" wide ascii
        $3 = "WinHTTP 1.0" wide ascii
        $4 = "<head>" wide ascii

    condition:
        all of them
}

rule APT1_WEBC2_GREENCAT
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "reader_sl.exe" wide ascii
        $2 = "MS80547.bat" wide ascii
        $3 = "ADR32" wide ascii
        $4 = "ControlService failed!" wide ascii

    condition:
        3 of them
}

rule APT1_WEBC2_DIV
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "3DC76854-C328-43D7-9E07-24BF894F8EF5" wide ascii
        $2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $3 = "Hello from MFC!" wide ascii
        $4 = "Microsoft Internet Explorer" wide ascii

    condition:
        3 of them
}

rule APT1_WEBC2_CSON
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $httpa1 = "/Default.aspx?INDEX=" wide ascii
        $httpa2 = "/Default.aspx?ID=" wide ascii
        $httpb1 = "Win32" wide ascii
        $httpb2 = "Accept: text*/*" wide ascii
        $exe1 = "xcmd.exe" wide ascii
        $exe2 = "Google.exe" wide ascii

    condition:
        1 of ($exe*) and 1 of ($httpa*) and all of ($httpb*)
}

rule APT1_WEBC2_CLOVER
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $msg1 = "BUILD ERROR!" wide ascii
        $msg2 = "SUCCESS!" wide ascii
        $msg3 = "wild scan" wide ascii
        $msg4 = "Code too clever" wide ascii
        $msg5 = "insufficient lookahead" wide ascii
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT 5.1; SV1)" wide ascii
        $ua2 = "Mozilla/5.0 (Windows; Windows NT 5.1; en-US; rv:1.8.0.12) Firefox/1.5.0.12" wide ascii

    condition:
        2 of ($msg*) and 1 of ($ua*)
}

rule APT1_WEBC2_BOLID
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
      
    strings:
        $vm = "VMProtect" wide ascii
        $http = "http://[c2_location]/[page].html" wide ascii

    condition:
        all of them
}

rule APT1_WEBC2_ADSPACE
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "<!---HEADER ADSPACE style=" wide ascii
        $2 = "ERSVC.DLL" wide ascii

    condition:
        all of them
}

rule APT1_WEBC2_AUSOV
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "ntshrui.dll" wide ascii
        $2 = "%SystemRoot%\\System32\\" wide ascii
        $3 = "<!--DOCHTML" wide ascii
        $4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" wide ascii
        $5 = "Ausov" wide ascii

    condition:
        4 of them
}

rule APT1_WARP
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $err1 = "exception..." wide ascii
        $err2 = "failed..." wide ascii
        $err3 = "opened..." wide ascii
        $exe1 = "cmd.exe" wide ascii
        $exe2 = "ISUN32.EXE" wide ascii

    condition:
        2 of ($err*) and all of ($exe*)
}

rule APT1_TARSIP_ECLIPSE
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "\\pipe\\ssnp" wide ascii
        $2 = "toobu.ini" wide ascii
        $3 = "Serverfile is not bigger than Clientfile" wide ascii
        $4 = "URL download success" wide ascii

    condition:
        3 of them
}

rule APT1_TARSIP_MOON
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $s1 = "\\XiaoME\\SunCloud-Code\\moon" wide ascii
        $s2 = "URL download success!" wide ascii
        $s3 = "Kugoosoft" wide ascii
        $msg1 = "Modify file failed!! So strange!" wide ascii
        $msg2 = "Create cmd process failed!" wide ascii
        $msg3 = "The command has not been implemented!" wide ascii
        $msg4 = "Runas success!" wide ascii
        $onec1 = "onec.php" wide ascii
        $onec2 = "/bin/onec" wide ascii

    condition:
        1 of ($s*) and 1 of ($msg*) and 1 of ($onec*)
}

/*
rule APT1_payloads
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii

    condition:
        1 of them
}
*/

rule APT1_RARSilent_EXE_PDF
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $winrar1 = "WINRAR.SFX" wide ascii
        $str2 = "Steup=" wide ascii

    condition:
        all of them
}

rule APT1_aspnetreport
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $url = "aspnet_client/report.asp" wide ascii
        $param = "name=%s&Gender=%c&Random=%04d&SessionKey=%s" wide ascii
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii

    condition:
        $url and $param and 1 of ($pay*)
}

rule APT1_Revird_svc
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $dll1 = "nwwwks.dll" wide ascii
        $dll2 = "rdisk.dll" wide ascii
        $dll3 = "skeys.dll" wide ascii
        $dll4 = "SvcHost.DLL.log" wide ascii
        $svc1 = "InstallService" wide ascii
        $svc2 = "RundllInstallA" wide ascii
        $svc3 = "RundllUninstallA" wide ascii
        $svc4 = "ServiceMain" wide ascii
        $svc5 = "UninstallService" wide ascii

    condition:
        1 of ($dll*) and 2 of ($svc*)
}

rule APT1_dbg_mess
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $dbg1 = "Down file ok!" wide ascii
        $dbg2 = "Send file ok!" wide ascii
        $dbg3 = "Command Error!" wide ascii
        $dbg4 = "Pls choose target first!" wide ascii
        $dbg5 = "Alert!" wide ascii
        $dbg6 = "Pls press enter to make sure!" wide ascii
        $dbg7 = "Are you sure to " wide ascii
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii

    condition:
        4 of ($dbg*) and 1 of ($pay*)
}

rule APT1_known_malicious_RARSilent
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "Analysis And Outlook.doc" wide ascii
        $str2 = "North Korean launch.pdf" wide ascii
        $str3 = "Dollar General.doc" wide ascii
        $str4 = "Dow Corning Corp.pdf" wide ascii

    condition:
        1 of them and APT1_RARSilent_EXE_PDF
}

/* US CERT Rule */

rule Dropper_DeploysMalwareViaSideLoading {
meta:
        description = "Detect a dropper used to deploy an implant via side loading. This dropper has specifically been observed deploying REDLEAVES & PlugX"
        author = "USG"
        true_positive = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481: drops REDLEAVES. 6392e0701a77ea25354b1f40f5b867a35c0142abde785a66b83c9c8d2c14c0c3: drops plugx. "
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
        $UniqueString = {2e 6c 6e 6b [0-14] 61 76 70 75 69 2e 65 78 65} // ".lnk" near "avpui.exe"
        $PsuedoRandomStringGenerator = {b9 1a [0-6] f7 f9 46 80 c2 41 88 54 35 8b 83 fe 64} // Unique function that generates a 100 character pseudo random string.

condition:
        any of them
}

rule REDLEAVES_DroppedFile_ImplantLoader_Starburn {
meta:
        description = "Detect the DLL responsible for loading and deobfuscating the DAT file containing shellcode and core REDLEAVES RAT"
        author = "USG"
        true_positive = "7f8a867a8302fe58039a6db254d335ae" // StarBurn.dll
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
strings:
        $XOR_Loop = {32 0c 3a 83 c2 02 88 0e 83 fa 08 [4-14] 32 0c 3a 83 c2 02 88 0e 83 fa 10} // Deobfuscation loop
condition:
        any of them
}

rule REDLEAVES_DroppedFile_ObfuscatedShellcodeAndRAT_handkerchief {
meta:
        description = "Detect obfuscated .dat file containing shellcode and core REDLEAVES RAT"
        author = "USG"
        true_positive = "fb0c714cd2ebdcc6f33817abe7813c36" // handkerchief.dat
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
        $RedleavesStringObfu = {73 64 65 5e 60 74 75 74 6c 6f 60 6d 5e 6d 64 60 77 64 72 5e 65 6d 6d 6c 60 68 6f 2f 65 6d 6d} // This is 'red_autumnal_leaves_dllmain.dll' XOR'd with 0x01
condition:
        any of them
}

rule REDLEAVES_CoreImplant_UniqueStrings {
meta:
        description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
        author = "USG"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
        $unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
        $unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
        $unique7 = "\\NamePipe_MoreWindows" wide ascii
condition:
        any of them
}

rule PLUGX_RedLeaves
{
meta:
        author = "US-CERT Code Analysis Team"
        date = "03042017"
        incident = "10118538"
        date = "2017/04/03"
        MD5_1 = "598FF82EA4FB52717ACAFB227C83D474"
        MD5_2 = "7D10708A518B26CC8C3CBFBAA224E032"
        MD5_3 = "AF406D35C77B1E0DF17F839E36BCE630"
        MD5_4 = "6EB9E889B091A5647F6095DCD4DE7C83"
        MD5_5 = "566291B277534B63EAFC938CDAAB8A399E41AF7D"
        info = "Detects specific RedLeaves and PlugX binaries"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
        $s0 = { 80343057403D2FD0010072F433C08BFF80343024403D2FD0010072F4 }
        $s1 = "C:/Users/user/Desktop/my_OK_2014/bit9/runsna/Release/runsna.pdb" fullword ascii
        $s2 = "d:/work/plug4.0(shellcode)" fullword ascii
        $s3 = "/shellcode/shellcode/XSetting.h" fullword ascii
        $s4 = { 42AFF4276A45AA58474D4C4BE03D5B395566BEBCBDEDE9972872C5C4C5498228 }
        $s5 = { 8AD32AD002D180C23830140E413BCB7CEF6A006A006A00566A006A00 }
        $s6 = { EB055F8BC7EB05E8F6FFFFFF558BEC81ECC8040000535657 }
        $s7 = { 8A043233C932043983C10288043283F90A7CF242890D18AA00103BD37CE2891514AA00106A006A006A0056 }
        $s8 = { 293537675A402A333557B05E04D09CB05EB3ADA4A4A40ED0B7DAB7935F5B5B08 }
        $s9 = "RedLeavesCMDSimulatorMutex"
condition:
        $s0 or $s1 or $s2 and $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9
}

/* Cylance Rule */

rule Ham_backdoor
{
meta:
        author = "Cylance Spear Team"
        reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
strings:
        $a = {8D 14 3E 8B 7D FC 8A 0C 11 32 0C 38 40 8B 7D 10 88 0A 8B 4D 08 3B C3}
        $b = {8D 0C 1F 8B 5D F8 8A 04 08 32 04 1E 46 8B 5D 10 88 01 8B 45 08 3B F2}
condition:
        $a or $b
}

rule Tofu_Backdoor
{
meta:
        author = "Cylance Spear Team"
        reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
strings:
	$a = "Cookies: Sym1.0"
	$b = "\\\\.\\pipe\\1[12345678]"
	$c = {66 0F FC C1 0F 11 40 D0 0F 10 40 D0 66 0F EF C2 0F 11 40 D0 0F 10 40 E0}
condition:
	$a or $b or $c
}



rule clean_apt15_patchedcmd{
	meta:
		author = "Ahmed Zaki"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
	strings:
	    $ = "eisableCMD" wide
	    $ = "%WINDOWS_COPYRIGHT%" wide
	    $ = "Cmd.Exe" wide
	    $ = "Windows Command Processor" wide
	condition:
        	all of them
}

rule malware_apt15_royalcli_1{
	meta:
    description = "Generic strings found in the Royal CLI tool"
    reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		author = "David Cannings"
		sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"

	strings:
	    $ = "%s~clitemp%08x.tmp" fullword
	    $ = "qg.tmp" fullword
	    $ = "%s /c %s>%s" fullword
	    $ = "hkcmd.exe" fullword
	    $ = "%snewcmd.exe" fullword
	    $ = "%shkcmd.exe" fullword
	    $ = "%s~clitemp%08x.ini" fullword
	    $ = "myRObject" fullword
	    $ = "myWObject" fullword
	    $ = "10 %d %x\x0D\x0A"
	    $ = "4 %s  %d\x0D\x0A"
	    $ = "6 %s  %d\x0D\x0A"
	    $ = "1 %s  %d\x0D\x0A"
	    $ = "3 %s  %d\x0D\x0A"
	    $ = "5 %s  %d\x0D\x0A"
	    $ = "2 %s  %d 0 %d\x0D\x0A"
	    $ = "2 %s  %d 1 %d\x0D\x0A"
	    $ = "%s file not exist" fullword

	condition:
	    5 of them
}

rule malware_apt15_royalcli_2{
	meta:
    author = "Nikolaos Pantazopoulos"
    description = "APT15 RoyalCli backdoor"
    reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$string1 = "%shkcmd.exe" fullword
		$string2 = "myRObject" fullword
		$string3 = "%snewcmd.exe" fullword
		$string4 = "%s~clitemp%08x.tmp" fullword
		$string5 = "hkcmd.exe" fullword
		$string6 = "myWObject" fullword
	condition:
		uint16(0) == 0x5A4D and 2 of them
}

rule malware_apt15_bs2005{
	meta:
		author	=	"Ahmed Zaki"
		md5	=	"ed21ce2beee56f0a0b1c5a62a80c128b"
		description	=	"APT15 bs2005"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
   	strings:
		$ = "%s&%s&%s&%s"  wide ascii
		$ = "%s\\%s"  wide ascii
		$ = "WarOnPostRedirect"  wide ascii fullword
		$ = "WarnonZoneCrossing"  wide ascii fullword
		$ = "^^^^^" wide ascii fullword
			/*
				"%s" /C "%s > "%s\tmp.txt" 2>&1 "     
			*/
		$ =  /"?%s\s*"?\s*\/C\s*"?%s\s*>\s*\\?"?%s\\(\w+\.\w+)?"\s*2>&1\s*"?/ 
		$ ="IEharden" wide ascii fullword
		$ ="DEPOff" wide ascii fullword
		$ ="ShownVerifyBalloon" wide ascii fullword
		$ ="IEHardenIENoWarn" wide ascii fullword
   	condition:
		(uint16(0) == 0x5A4D and 5 of them) or 
		( uint16(0) == 0x5A4D and 3 of them and 
		( pe.imports("advapi32.dll", "CryptDecrypt") and pe.imports("advapi32.dll", "CryptEncrypt") and
		pe.imports("ole32.dll", "CoCreateInstance")))}

rule malware_apt15_royaldll{
	meta:
		author = "David Cannings"
		description = "DLL implant, originally rights.dll and runs as a service"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"          
	strings:
	    /*
	      56                push    esi
	      B8 A7 C6 67 4E    mov     eax, 4E67C6A7h
	      83 C1 02          add     ecx, 2
	      BA 04 00 00 00    mov     edx, 4
	      57                push    edi
	      90                nop
	    */
	    // JSHash implementation (Justin Sobel's hash algorithm)
		$opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }

	    /*
	      0F B6 1C 03       movzx   ebx, byte ptr [ebx+eax]
	      8B 55 08          mov     edx, [ebp+arg_0]
	      30 1C 17          xor     [edi+edx], bl
	      47                inc     edi
	      3B 7D 0C          cmp     edi, [ebp+arg_4]
	      72 A4             jb      short loc_10003F31
	    */
	    // Encode loop, used to "encrypt" data before DNS request
		$opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }

	    /*
	      68 88 13 00 00    push    5000 # Also seen 3000, included below
	      FF D6             call    esi ; Sleep
	      4F                dec     edi
	      75 F6             jnz     short loc_10001554
	    */
	    // Sleep loop
		$opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }

	    // Generic strings
	    $ = "Nwsapagent" fullword
	    $ = "\"%s\">>\"%s\"\\s.txt"
	    $ = "myWObject" fullword
	    $ = "del c:\\windows\\temp\\r.exe /f /q"
	    $ = "del c:\\windows\\temp\\r.ini /f /q"
	condition:
		3 of them
}

rule malware_apt15_royaldll_2	{
	meta:
		author	=	"Ahmed Zaki"
		sha256	=	"bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
		description	=	"DNS backdoor used by APT15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		    $= "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide ascii 
		    $= "netsvcs" wide ascii fullword
		    $= "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide ascii fullword
		    $= "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
		    $= "myWObject" wide ascii 
	condition:
		uint16(0) == 0x5A4D and all of them
		and pe.exports("ServiceMain")
		and filesize > 50KB and filesize < 600KB
}

rule malware_apt15_exchange_tool {
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$s1= "subjectname" fullword
		$s2= "sendername" fullword
		$s3= "WebCredentials" fullword
		$s4= "ExchangeVersion"	fullword
		$s5= "ExchangeCredentials"	fullword
		$s6= "slfilename"	fullword
		$s7= "EnumMail"	fullword
		$s8= "EnumFolder"	fullword
		$s9= "set_Credentials"	fullword
		$s10 = "/de" wide
		$s11 = "/sn" wide
		$s12 = "/sbn" wide
		$s13 = "/list" wide
		$s14 = "/enum" wide
		$s15 = "/save" wide
		$s16 = "/ao" wide
		$s17 = "/sl" wide
		$s18 = "/v or /t is null" wide
		$s19 = "2007" wide
		$s20 = "2010" wide
		$s21 = "2010sp1" wide
		$s22 = "2010sp2" wide
		$s23 = "2013" wide
		$s24 = "2013sp1" wide
	condition:
		uint16(0) == 0x5A4D and 15 of ($s*)
}

rule malware_apt15_generic {
	meta:
		author = "David Cannings"
		description = "Find generic data potentially relating to AP15 tools"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
	    // Appears to be from copy/paste code
		$str01 = "myWObject" fullword
		$str02 = "myRObject" fullword

	    /*
	      6A 02             push    2               ; dwCreationDisposition
	      6A 00             push    0               ; lpSecurityAttributes
	      6A 00             push    0               ; dwShareMode
	      68 00 00 00 C0    push    0C0000000h      ; dwDesiredAccess
	      50                push    eax             ; lpFileName
	      FF 15 44 F0 00 10 call    ds:CreateFileA
	    */
	    // Arguments for CreateFileA
		$opcodes01 = { 6A (02|03) 6A 00 6A 00 68 00 00 00 C0 50 FF 15 }
  	condition:
		2 of them
}

rule APT17_Sample_FXSST_DLL 
{
    
    meta:
        description = "Detects Samples related to APT17 activity - file FXSST.DLL"
        author = "Florian Roth"
        reference = "https://goo.gl/ZiJyQv"
        date = "2015-05-14"
        hash = "52f1add5ad28dc30f68afda5d41b354533d8bce3"
        
    strings:
        $x1 = "Microsoft? Windows? Operating System" fullword wide
        $x2 = "fxsst.dll" fullword ascii
        $y1 = "DllRegisterServer" fullword ascii
        $y2 = ".cSV" fullword ascii
        $s1 = "GetLastActivePopup"
        $s2 = "Sleep"
        $s3 = "GetModuleFileName"
        $s4 = "VirtualProtect"
        $s5 = "HeapAlloc"
        $s6 = "GetProcessHeap"
        $s7 = "GetCommandLine"
   
   condition:
        uint16(0) == 0x5a4d and filesize < 800KB and ( 1 of ($x*) or all of ($y*) ) and all of ($s*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-29
   Identifier: GRIZZLY STEPPE
*/

rule GRIZZLY_STEPPE_Malware_1
{

   meta:
      description = "Auto-generated rule - file HRDG022184_certclint.dll"
      author = "Florian Roth"
      reference = "https://goo.gl/WVflzO"
      date = "2016-12-29"
      hash1 = "9f918fb741e951a10e68ce6874b839aef5a26d60486db31e509f8dcaa13acec5"

   strings:
      $s1 = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb" fullword ascii
      $s2 = "Repeat last find command)Replace specific text with different text" fullword wide
      $s3 = "l\\Processor(0)\\% Processor Time" fullword wide
      $s6 = "Self Process" fullword wide
      $s7 = "Default Process" fullword wide
      $s8 = "Star Polk.exe" fullword wide

   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 4 of them )
}

rule GRIZZLY_STEPPE_Malware_2
{

   meta:
      description = "Auto-generated rule - file 9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
      author = "Florian Roth"
      reference = "https://goo.gl/WVflzO"
      date = "2016-12-29"
      hash1 = "9acba7e5f972cdd722541a23ff314ea81ac35d5c0c758eb708fb6e2cc4f598a0"
      hash2 = "55058d3427ce932d8efcbe54dccf97c9a8d1e85c767814e34f4b2b6a6b305641"
      
   strings:
      $x1 = "GoogleCrashReport.dll" fullword ascii
      $s1 = "CrashErrors" fullword ascii
      $s2 = "CrashSend" fullword ascii
      $s3 = "CrashAddData" fullword ascii
      $s4 = "CrashCleanup" fullword ascii
      $s5 = "CrashInit" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $x1 ) or ( all of them )
}

rule PAS_TOOL_PHP_WEB_KIT_mod 
{
   
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
      author = "US CERT - modified by Florian Roth due to performance reasons"
      date = "2016/12/29"
   
   strings:
      $php = "<?php"
      $base64decode1 = "='base'.("
      $strreplace = "str_replace(\"\\n\", ''"
      $md5 = ".substr(md5(strrev("
      $gzinflate = "gzinflate"
      $cookie = "_COOKIE"
      $isset = "isset"
   
   condition:
      $php at 0 and (filesize > 10KB and filesize < 30KB) and #cookie == 2 and #isset == 3 and all of them
}

rule WebShell_PHP_Web_Kit_v3
{

   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      author = "Florian Roth"
      date = "2016/01/01"

   strings:
      $php = "<?php $"
      $php2 = "@assert(base64_decode($_REQUEST["
      $s1 = "(str_replace(\"\\n\", '', '"
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii

   condition:
      ( $php at 0 or $php2 ) and filesize > 8KB and filesize < 100KB and all of ($s*)
}

rule WebShell_PHP_Web_Kit_v4
{

   meta:
      description = "Detects PAS Tool PHP Web Kit"
      reference = "https://github.com/wordfence/grizzly"
      author = "Florian Roth"
      date = "2016/01/01"

   strings:
      $php = "<?php $"
      $s1 = "(StR_ReplAcE(\"\\n\",'',"
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii

   condition:
      $php at 0 and filesize > 8KB and filesize < 100KB and 2 of ($s*)
}


rule APT3102Code
{

    meta:
        description = "3102 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }

    condition:
        any of them
}

rule APT3102Strings
{
    
    meta:
        description = "3102 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"

    strings:
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"

    condition:
       any of them
}

rule APT9002Code 
{
    
    meta:
        description = "9002 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }

    condition:
        any of them
}

rule APT9002Strings
{
    
    meta:
        description = "9002 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"

    condition:
       any of them
}

rule APT9002 
{
    
    meta:
        description = "9002"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        APT9002Code or APT9002Strings
}

rule FE_APT_9002
{
    
    meta:
        Author      = "FireEye Labs"
        Date        = "2013/11/10"
        Description = "Strings inside"
        Reference   = "Useful link"
        
    strings:
        $mz = { 4d 5a }
        $a = "rat_UnInstall" wide ascii

    condition:
        ($mz at 0) and $a
}



rule apt_backspace
{

    meta:
        description = "Detects APT backspace"
        author = "Bit Byte Bitten"
        date = "2015-05-14"
        hash = "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"
        
    strings:
        $s1 = "!! Use Splice Socket !!"
        $s2 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
        $s3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"

    condition:
        uint16(0) == 0x5a4d and all of them
}


rule APT_bestia
{
meta:
    author = "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
    date = "2014-03-19"
    description = "Bestia.3.02.012.07 malware used in APT attacks on Polish government"
    references = "http://zaufanatrzeciastrona.pl/post/ukierunkowany-atak-na-pracownikow-polskich-samorzadow/" /* PL */
    hash0 = "9bb03bb5af40d1202378f95a6485fba8"
    hash1 = "7d9a806e0da0b869b10870dd6c7692c5"
    maltype = "apt"
    filetype = "exe"
strings:
    /* generated with https://github.com/Xen0ph0n/YaraGenerator */
    $string0 = "u4(UeK"
    $string1 = "nMiq/'p"
    $string2 = "_9pJMf"
    $string3 = "ICMP.DLL"
    $string4 = "EG}QAp"
    $string5 = "tsjWj:U"
    $string6 = "FileVersion" wide
    $string7 = "O2nQpp"
    $string8 = "2}W8we"
    $string9 = "ILqkC:l"
    $string10 = "f1yzMk"
    $string11 = "AutoIt v3 Script: 3, 3, 8, 1" wide
    $string12 = "wj<1uH"
    $string13 = "6fL-uD"
    $string14 = "B9Iavo<"
    $string15 = "rUS)sO"
    $string16 = "FJH{_/f"
    $string17 = "3e 03V"
condition:
    17 of them
}

rule BlackEnergy_BE_2 
{
   
   meta:
      description = "Detects BlackEnergy 2 Malware"
      author = "Florian Roth"
      reference = "http://goo.gl/DThzLz"
      date = "2015/02/19"
      hash = "983cfcf3aaaeff1ad82eb70f77088ad6ccedee77"
   
   strings:
      $s0 = "<description> Windows system utility service  </description>" fullword ascii
      $s1 = "WindowsSysUtility - Unicode" fullword wide
      $s2 = "msiexec.exe" fullword wide
      $s3 = "WinHelpW" fullword ascii
      $s4 = "ReadProcessMemory" fullword ascii
   
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and all of ($s*)
}

rule BlackEnergy_VBS_Agent 
{

    meta:
        description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs"
        author = "Florian Roth"
        reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
        date = "2016-01-03"
        hash = "b90f268b5e7f70af1687d9825c09df15908ad3a6978b328dc88f96143a64af0f"
    
    strings:
        $s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
        $s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
        $s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
   
    condition:
        filesize < 1KB and 2 of them
}

rule DropBear_SSH_Server
 {

    meta:
        description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
        author = "Florian Roth"
        reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
        date = "2016-01-03"
        score = 50
        hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
    
    strings:
        $s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
        $s2 = "Badly formatted command= authorized_keys option" fullword ascii
        $s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
        $s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
        $s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule BlackEnergy_BackdoorPass_DropBear_SSH 
{
    
    meta:
        description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
        author = "Florian Roth"
        reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
        date = "2016-01-03"
        hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
    
    strings:
        $s1 = "passDs5Bu9Te7" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and $s1
}

rule BlackEnergy_KillDisk_1 
{

    meta:
        description = "Detects KillDisk malware from BlackEnergy"
        author = "Florian Roth"
        reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
        date = "2016-01-03"
        score = 80
        super_rule = 1
        hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
        hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
        hash3 = "c7536ab90621311b526aefd56003ef8e1166168f038307ae960346ce8f75203d"
        hash4 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"

    strings:
        $s0 = "system32\\cmd.exe" fullword ascii
        $s1 = "system32\\icacls.exe" fullword wide
        $s2 = "/c del /F /S /Q %c:\\*.*" fullword ascii
        $s3 = "shutdown /r /t %d" fullword ascii
        $s4 = "/C /Q /grant " fullword wide
        $s5 = "%08X.tmp" fullword ascii
        $s6 = "/c format %c: /Y /X /FS:NTFS" fullword ascii
        $s7 = "/c format %c: /Y /Q" fullword ascii
        $s8 = "taskhost.exe" fullword wide /* Goodware String - occured 1 times */
        $s9 = "shutdown.exe" fullword wide /* Goodware String - occured 1 times */
 
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 8 of them
}

rule BlackEnergy_KillDisk_2 
{

    meta:
        description = "Detects KillDisk malware from BlackEnergy"
        author = "Florian Roth"
        reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
        date = "2016-01-03"
        score = 80
        super_rule = 1
        hash1 = "11b7b8a7965b52ebb213b023b6772dd2c76c66893fc96a18a9a33c8cf125af80"
        hash2 = "5d2b1abc7c35de73375dd54a4ec5f0b060ca80a1831dac46ad411b4fe4eac4c6"
        hash3 = "f52869474834be5a6b5df7f8f0c46cbc7e9b22fa5cb30bee0f363ec6eb056b95"

    strings:
        $s0 = "%c:\\~tmp%08X.tmp" fullword ascii
        $s1 = "%s%08X.tmp" fullword ascii
        $s2 = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" fullword wide
        $s3 = "%ls_%ls_%ls_%d.~tmp" fullword wide

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 3 of them
}

rule BlackEnergy_Driver_USBMDM 
{

    meta:
        description = "Auto-generated rule - from files 7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094, b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a, edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
        author = "Florian Roth"
        reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
        date = "2016-01-04"
        super_rule = 1
        hash1 = "7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094"
        hash2 = "b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a"
        hash3 = "edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
        hash4 = "ac13b819379855af80ea3499e7fb645f1c96a4a6709792613917df4276c583fc"
        hash5 = "7a393b3eadfc8938cbecf84ca630e56e37d8b3d23e084a12ea5a7955642db291"
        hash6 = "405013e66b6f137f915738e5623228f36c74e362873310c5f2634ca2fda6fbc5"
        hash7 = "244dd8018177ea5a92c70a7be94334fa457c1aab8a1c1ea51580d7da500c3ad5"
        hash8 = "edcd1722fdc2c924382903b7e4580f9b77603110e497393c9947d45d311234bf"
    
    strings:
        $s1 = "USB MDM Driver" fullword wide
        $s2 = "KdDebuggerNotPresent" fullword ascii /* Goodware String - occured 50 times */
        $s3 = "KdDebuggerEnabled" fullword ascii /* Goodware String - occured 69 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule BlackEnergy_Driver_AMDIDE 
{

    meta:
        description = "Auto-generated rule - from files 32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614, 3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2, 90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c, 97be6b2cec90f655ef11ed9feef5b9ef057fd8db7dd11712ddb3702ed7c7bda1"
        author = "Florian Roth"
        reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
        date = "2016-01-04"
        super_rule = 1
        hash1 = "32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614"
        hash2 = "3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2"
        hash3 = "90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c"
        hash4 = "97be6b2cec90f655ef11ed9feef5b9ef057fd8db7dd11712ddb3702ed7c7bda1"
        hash5 = "5111de45210751c8e40441f16760bf59856ba798ba99e3c9532a104752bf7bcc"
        hash6 = "cbc4b0aaa30b967a6e29df452c5d7c2a16577cede54d6d705ca1f095bd6d4988"
        hash7 = "1ce0dfe1a6663756a32c69f7494ad082d293d32fe656d7908fb445283ab5fa68"
   
    strings:
        $s1 = " AMD IDE driver" fullword wide
        $s2 = "SessionEnv" fullword wide
        $s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
        $s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
    
    condition:
        uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule Emdivi_SFX
 {

    meta:
        description = "Detects Emdivi malware in SFX Archive"
        author = "Florian Roth @Cyber0ps"
        reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
        date = "2015-08-20"
        score = 70
        hash1 = "7a3c81b2b3c14b9cd913692347019887b607c54152b348d6d3ccd3ecfd406196"
        hash2 = "8c3df4e4549db3ce57fc1f7b1b2dfeedb7ba079f654861ca0b608cbfa1df0f6b"
    
    strings:
        $x1 = "Setup=unsecess.exe" fullword ascii
        $x2 = "Setup=leassnp.exe" fullword ascii
        $s1 = "&Enter password for the encrypted file:" fullword wide
        $s2 = ";The comment below contains SFX script commands" fullword ascii
        $s3 = "Path=%temp%" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 740KB and (1 of ($x*) and all of ($s*))
}

rule Emdivi_Gen1 
{

    meta:
        description = "Detects Emdivi Malware"
        author = "Florian Roth @Cyber0ps"
        reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
        date = "2015-08-20"
        score = 80
        super_rule = 1
        hash1 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
        hash2 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
        hash3 = "6a331c4e654dd8ddaa2c69d260aa5f4f76f243df8b5019d62d4db5ae5c965662"
        hash4 = "90d07ea2bb80ed52b007f57d0d9a79430cd50174825c43d5746a16ee4f94ea86"
    
    strings:
        $x1 = "wmic nteventlog where filename=\"SecEvent\" call cleareventlog" fullword wide
        $s0 = "del %Temp%\\*.exe %Temp%\\*.dll %Temp%\\*.bat %Temp%\\*.ps1 %Temp%\\*.cmd /f /q" fullword wide
        $x3 = "userControl-v80.exe" fullword ascii
        $s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword wide
        $s2 = "http://www.msftncsi.com" fullword wide
        $s3 = "net use | find /i \"c$\"" fullword wide
        $s4 = " /del /y & " fullword wide
        $s5 = "\\auto.cfg" fullword wide
        $s6 = "/ncsi.txt" fullword wide
        $s7 = "Dcmd /c" fullword wide
        $s8 = "/PROXY" fullword wide
    
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule Emdivi_Gen2 
{

    meta:
        description = "Detects Emdivi Malware"
        author = "Florian Roth @Cyber0ps"
        reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
        date = "2015-08-20"
        super_rule = 1
        score = 80
        hash1 = "9a351885bf5f6fec466f30021088504d96e9db10309622ed198184294717add1"
        hash2 = "a5be7cb1f37030c9f9211c71e0fbe01dae19ff0e6560c5aab393621f18a7d012"
        hash3 = "9183abb9b639699cd2ad28d375febe1f34c14679b7638d1a79edb49d920524a4"
    
    strings:
        $s1 = "%TEMP%\\IELogs\\" fullword ascii
        $s2 = "MSPUB.EXE" fullword ascii
        $s3 = "%temp%\\" fullword ascii
        $s4 = "\\NOTEPAD.EXE" fullword ascii
        $s5 = "%4d-%02d-%02d %02d:%02d:%02d " fullword ascii
        $s6 = "INTERNET_OPEN_TYPE_PRECONFIG" fullword ascii
        $s7 = "%4d%02d%02d%02d%02d%02d" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 1300KB and 6 of them
}

rule Emdivi_Gen3 
{

    meta:
        description = "Detects Emdivi Malware"
        author = "Florian Roth @Cyber0ps"
        reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
        date = "2015-08-20"
        super_rule = 1
        score = 80
        hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
        hash2 = "a94bf485cebeda8e4b74bbe2c0a0567903a13c36b9bf60fab484a9b55207fe0d"
  
    strings:
        $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword ascii
        $s2 = "\\Mozilla\\Firefox\\Profiles\\" fullword ascii
        $s4 = "\\auto.cfg" fullword ascii
        $s5 = "/ncsi.txt" fullword ascii
        $s6 = "/en-us/default.aspx" fullword ascii
        $s7 = "cmd /c" fullword ascii
        $s9 = "APPDATA" fullword ascii /* Goodware String - occured 25 times */
   
    condition:
        uint16(0) == 0x5a4d and filesize < 850KB and (( $x1 and 1 of ($s*)) or ( 4 of ($s*)))
}

rule Emdivi_Gen4
 {

    meta:
        description = "Detects Emdivi Malware"
        author = "Florian Roth @Cyber0ps"
        reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
        date = "2015-08-20"
        super_rule = 1
        score = 80
        hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
        hash2 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
        hash3 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
        hash4 = "6a331c4e654dd8ddaa2c69d260aa5f4f76f243df8b5019d62d4db5ae5c965662"
        hash5 = "90d07ea2bb80ed52b007f57d0d9a79430cd50174825c43d5746a16ee4f94ea86"
        hash6 = "a94bf485cebeda8e4b74bbe2c0a0567903a13c36b9bf60fab484a9b55207fe0d"
  
    strings:
        $s1 = ".http_port\", " fullword wide
        $s2 = "UserAgent: " fullword ascii
        $s3 = "AUTH FAILED" fullword ascii
        $s4 = "INVALID FILE PATH" fullword ascii
        $s5 = ".autoconfig_url\", \"" fullword wide
        $s6 = "FAILED TO WRITE FILE" fullword ascii
        $s7 = ".proxy" fullword wide
        $s8 = "AuthType: " fullword ascii
        $s9 = ".no_proxies_on\", \"" fullword wide
  
    condition:
        uint16(0) == 0x5a4d and filesize < 853KB and all of them
}



rule apt_c16_win_memory_pcclient
{

  meta:
    author = "@dragonthreatlab"
    md5 = "ec532bbe9d0882d403473102e9724557"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

  condition:
    all of them
}

rule apt_c16_win_disk_pcclient
{

  meta:
    author = "@dragonthreatlab"
    md5 = "55f84d88d84c221437cd23cdbc541d2e"
    description = "Encoded version of pcclient found on disk"
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}

  condition:
    $header at 0
}

rule apt_c16_win32_dropper
{

  meta:
    author = "@dragonthreatlab"
    md5 = "ad17eff26994df824be36db246c8fb6a"
    description = "APT malware used to drop PcClient RAT"
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}

  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_swisyn
{

  meta:
    author = "@dragonthreatlab"
    md5 = "a6a18c846e5179259eba9de238f67e41"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_wateringhole
{

  meta:
    author = "@dragonthreatlab"
    description = "Detects code from APT wateringhole"
    date = "2015/01/11"
    reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"

  condition:
    any of ($str*)
}

rule apt_c16_win64_dropper
{

    meta:
        author = "@dragonthreatlab"
        date = "2015/01/11"
        description = "APT malware used to drop PcClient RAT"
        reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

    strings:
        $mz = { 4D 5A }
        $str1 = "clbcaiq.dll" ascii
        $str2 = "profapi_104" ascii
        $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
        $str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

    condition:
        $mz at 0 and all of ($str*)
}


rule Carbanak_0915_1
{

    meta:
        description = "Carbanak Malware"
        author = "Florian Roth"
        reference = "https://www.csis.dk/en/csis/blog/4710/"
        date = "2015-09-03"
        score = 70

    strings:
        $s1 = "evict1.pdb" fullword ascii
        $s2 = "http://testing.corp 0" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule Carbanak_0915_2
{

    meta:
        description = "Carbanak Malware"
        author = "Florian Roth"
        reference = "https://www.csis.dk/en/csis/blog/4710/"
        date = "2015-09-03"
        score = 70

    strings:
        $x1 = "8Rkzy.exe" fullword wide
        $s1 = "Export Template" fullword wide
        $s2 = "Session folder with name '%s' already exists." fullword ascii
        $s3 = "Show Unconnected Endpoints (Ctrl+U)" fullword ascii
        $s4 = "Close All Documents" fullword wide
        $s5 = "Add &Resource" fullword ascii
        $s6 = "PROCEXPLORER" fullword wide /* Goodware String - occured 1 times */
        $s7 = "AssocQueryKeyA" fullword ascii /* Goodware String - occured 4 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and ( $x1 or all of ($s*) )
}

rule Carbanak_0915_3
{

    meta:
        description = "Carbanak Malware"
        author = "Florian Roth"
        reference = "https://www.csis.dk/en/csis/blog/4710/"
        date = "2015-09-03"
        score = 70

    strings:
        $s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
        $s2 = "SHInvokePrinterCommandA" fullword ascii
        $s3 = "Ycwxnkaj" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and all of them
}


rule Careto_SGH 
{

    meta:
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto SGH component signature"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
        date = "2014/02/11"

    strings:
        $m1 = "PGPsdkDriver" ascii wide fullword
        $m2 = "jpeg1x32" ascii wide fullword
        $m3 = "SkypeIE6Plugin" ascii wide fullword
        $m4 = "CDllUninstall" ascii wide fullword

    condition:
        2 of them
}

rule Careto_OSX_SBD 
{

    meta:
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto OSX component signature"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
        date = "2014/02/11"

    strings:
        /* XORed "/dev/null strdup() setuid(geteuid())" */
        $1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}

    condition:
        all of them
}

rule Careto_CnC 
{

    meta:
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto CnC communication signature"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
        date = "2014/02/11"

    strings:
        $1 = "cgi-bin/commcgi.cgi" ascii wide
        $2 = "Group" ascii wide
        $3 = "Install" ascii wide
        $4 = "Bn" ascii wide

    condition:
        all of them
}

rule Careto_CnC_domains 
{

    meta:
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto known command and control domains"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
        date = "2014/02/11"

    strings:
        $1 = "linkconf.net" ascii wide nocase
        $2 = "redirserver.net" ascii wide nocase
        $3 = "swupdt.com" ascii wide nocase

    condition:
        any of them
}


rule Casper_Backdoor_x86
{

    meta:
        description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/05"
        hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
        score = 80

    strings:
        $s1 = "\"svchost.exe\"" fullword wide
        $s2 = "firefox.exe" fullword ascii
        $s3 = "\"Host Process for Windows Services\"" fullword wide
        $x1 = "\\Users\\*" fullword ascii
        $x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x3 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x4 = "\\Documents and Settings\\*" fullword ascii
        $y1 = "%s; %S=%S" fullword wide
        $y2 = "%s; %s=%s" fullword ascii
        $y3 = "Cookie: %s=%s" fullword ascii
        $y4 = "http://%S:%d" fullword wide
        $z1 = "http://google.com/" fullword ascii
        $z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
        $z3 = "Operating System\"" fullword wide

    condition:
        ( all of ($s*) ) or ( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}

rule Casper_EXE_Dropper
{

    meta:
        description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/05"
        hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
        score = 80

    strings:
        $s0 = "<Command>" fullword ascii
        $s1 = "</Command>" fullword ascii
        $s2 = "\" /d \"" fullword ascii
        $s4 = "'%s' %s" fullword ascii
        $s5 = "nKERNEL32.DLL" fullword wide
        $s6 = "@ReturnValue" fullword wide
        $s7 = "ID: 0x%x" fullword ascii
        $s8 = "Name: %S" fullword ascii

    condition:
        7 of them
}

rule Casper_Included_Strings
{

    meta:
        description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/06"
        score = 50

    strings:
        $a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
        $a1 = "& SYSTEMINFO) ELSE EXIT"
        $mz = { 4d 5a }
        $c1 = "domcommon.exe" wide fullword                         // File Name
        $c2 = "jpic.gov.sy" fullword                                // C2 Server
        $c3 = "aiomgr.exe" wide fullword                            // File Name
        $c4 = "perfaudio.dat" fullword                              // Temp File Name
        $c5 = "Casper_DLL.dll" fullword                             // Name
        $c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 }   // Decryption Key
        $c7 = "{4216567A-4512-9825-7745F856}" fullword              // Mutex

    condition:
        all of ($a*) or ( $mz at 0 ) and ( 1 of ($c*) )
}

rule Casper_SystemInformation_Output
{

    meta:
        description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
        author = "Florian Roth"
        reference = "http://goo.gl/VRJNLo"
        date = "2015/03/06"
        score = 70

    strings:
        $a0 = "***** SYSTEM INFORMATION ******"
        $a1 = "***** SECURITY INFORMATION ******"
        $a2 = "Antivirus: "
        $a3 = "Firewall: "
        $a4 = "***** EXECUTION CONTEXT ******"
        $a5 = "Identity: "
        $a6 = "<CONFIG TIMESTAMP="

    condition:
        all of them
}

rule CheshireCat_Sample2
{

    meta:
        description = "Auto-generated rule - file dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
        author = "Florian Roth"
        reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
        date = "2015-08-08"
        score = 70
        hash = "dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"

    strings:
        $s0 = "mpgvwr32.dll" fullword ascii
        $s1 = "Unexpected failure of wait! (%d)" fullword ascii
        $s2 = "\"%s\" /e%d /p%s" fullword ascii
        $s4 = "error in params!" fullword ascii
        $s5 = "sscanf" fullword ascii
        $s6 = "<>Param : 0x%x" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 4 of ($s*)
}

/* Generic Rules ----------------------------------------------------------- */
/* Gen1 is more exact than Gen2 - until now I had no FPs with Gen2 */

rule CheshireCat_Gen1
{

    meta:
        description = "Auto-generated rule - file ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
        author = "Florian Roth"
        reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
        date = "2015-08-08"
        super_rule = 1
        score = 90
        hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
        hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
        hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
        hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"

    strings:
        $x1 = "CAPESPN.DLL" fullword wide
        $x2 = "WINF.DLL" fullword wide
        $x3 = "NCFG.DLL" fullword wide
        $x4 = "msgrthlp.dll" fullword wide
        $x5 = "Local\\{c0d9770c-9841-430d-b6e3-575dac8a8ebf}" fullword ascii
        $x6 = "Local\\{1ef9f94a-5664-48a6-b6e8-c3748db459b4}" fullword ascii
        $a1 = "Interface\\%s\\info" fullword ascii
        $a2 = "Interface\\%s\\info\\%s" fullword ascii
        $a3 = "CLSID\\%s\\info\\%s" fullword ascii
        $a4 = "CLSID\\%s\\info" fullword ascii
        $b1 = "Windows Shell Icon Handler" fullword wide
        $b2 = "Microsoft Shell Icon Handler" fullword wide
        $s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
        $s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
        $s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
        $s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
        $s5 = "%sMutex" fullword ascii
        $s6 = "\\ShellIconCache" fullword ascii
        $s7 = "+6Service Pack " fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 350KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*) and 1 of ($x*)
}

rule CheshireCat_Gen2
{

    meta:
        description = "Auto-generated rule - from files 32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a, 63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
        author = "Florian Roth"
        reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
        date = "2015-08-08"
        super_rule = 1
        score = 70
        hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
        hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
        hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
        hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"

    strings:
        $a1 = "Interface\\%s\\info" fullword ascii
        $a2 = "Interface\\%s\\info\\%s" fullword ascii
        $a3 = "CLSID\\%s\\info\\%s" fullword ascii
        $a4 = "CLSID\\%s\\info" fullword ascii
        $b1 = "Windows Shell Icon Handler" fullword wide
        $b2 = "Microsoft Shell Icon Handler" fullword wide
        $s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
        $s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
        $s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
        $s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
        $s5 = "%sMutex" fullword ascii
        $s6 = "\\ShellIconCache" fullword ascii
        $s7 = "+6Service Pack " fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*)
}


rule CloudDuke_Malware
{

    meta:
        description = "Detects CloudDuke Malware"
        author = "Florian Roth"
        reference = "https://www.f-secure.com/weblog/archives/00002822.html"
        date = "2015-07-22"
        score = 60
        hash1 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
        hash2 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
        hash3 = "1d4ac97d43fab1d464017abb5d57a6b4601f99eaa93b01443427ef25ae5127f7"
        hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
        hash5 = "1d4ac97d43fab1d464017abb5d57a6b4601f99eaa93b01443427ef25ae5127f7"
        hash6 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
        hash7 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
        hash8 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
        hash9 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
        hash10 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
        hash11 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
        hash12 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"
        hash13 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
        hash14 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
        hash15 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"

    strings:
        $s1 = "ProcDataWrap" fullword ascii
        $s2 = "imagehlp.dll" fullword ascii
        $s3 = "dnlibsh" fullword ascii
        $s4 = "%ws_out%ws" fullword wide
        $s5 = "Akernel32.dll" fullword wide
        $op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b } /* Opcode */
        $op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f } /* Opcode */
        $op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 } /* Opcode */

    condition:
        uint16(0) == 0x5a4d and filesize < 720KB and 4 of ($s*) and 1 of ($op*)
}

rule SFXRAR_Acrotray
{

    meta:
        description = "Most likely a malicious file acrotray in SFX RAR / CloudDuke APT 5442.1.exe, 5442.2.exe"
        author = "Florian Roth"
        reference = "https://www.f-secure.com/weblog/archives/00002822.html"
        date = "2015-07-22"
        super_rule = 1
        score = 70
        hash1 = "51e713c7247f978f5836133dd0b8f9fb229e6594763adda59951556e1df5ee57"
        hash2 = "5d695ff02202808805da942e484caa7c1dc68e6d9c3d77dc383cfa0617e61e48"
        hash3 = "56531cc133e7a760b238aadc5b7a622cd11c835a3e6b78079d825d417fb02198"

    strings:
        $s1 = "winrarsfxmappingfile.tmp" fullword wide /* PEStudio Blacklist: strings */
        $s2 = "GETPASSWORD1" fullword wide /* PEStudio Blacklist: strings */
        $s3 = "acrotray.exe" fullword ascii
        $s4 = "CryptUnprotectMemory failed" fullword wide /* PEStudio Blacklist: strings */

    condition:
        uint16(0) == 0x5a4d and filesize < 2449KB and all of them
}

rule Cobalt_functions
{

    meta:

        author="@j0sm1"
        url="https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/"
        description="Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"

    strings:

        $h1={58 A4 53 E5} // VirtualAllocEx
        $h2={4C 77 26 07} // LoadLibraryEx
        $h3={6A C9 9C C9} // DNSQuery_UTF8
        $h4={44 F0 35 E0} // Sleep
        $h5={F4 00 8E CC} // lstrlen

    condition:
        2 of ( $h* )
}

rule Codoso_PlugX_3
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "74e1e83ac69e45a3bee78ac2fac00f9e897f281ea75ed179737e9b6fe39971e3"

    strings:
        $s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
        $s2 = "mcs.exe" fullword ascii
        $s3 = "McAltLib.dll" fullword ascii
        $s4 = "WinRAR self-extracting archive" fullword wide

    condition:
        uint16(0) == 0x5a4d and filesize < 1200KB and all of them
}

rule Codoso_PlugX_2
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "b9510e4484fa7e3034228337768176fce822162ad819539c6ca3631deac043eb"

    strings:
        $s1 = "%TEMP%\\HID" fullword wide
        $s2 = "%s\\hid.dll" fullword wide
        $s3 = "%s\\SOUNDMAN.exe" fullword wide
        $s4 = "\"%s\\SOUNDMAN.exe\" %d %d" fullword wide
        $s5 = "%s\\HID.dllx" fullword wide

    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them ) or all of them
}

rule Codoso_CustomTCP_4
{

    meta:
        description = "Detects Codoso APT CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash1 = "ea67d76e9d2e9ce3a8e5f80ff9be8f17b2cd5b1212153fdf36833497d9c060c0"
        hash2 = "130abb54112dd47284fdb169ff276f61f2b69d80ac0a9eac52200506f147b5f8"
        hash3 = "3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa"
        hash4 = "02cf5c244aebaca6195f45029c1e37b22495609be7bdfcfcd79b0c91eac44a13"

    strings:
        $x1 = "varus_service_x86.dll" fullword ascii
        $s1 = "/s %s /p %d /st %d /rt %d" fullword ascii
        $s2 = "net start %%1" fullword ascii
        $s3 = "ping 127.1 > nul" fullword ascii
        $s4 = "McInitMISPAlertEx" fullword ascii
        $s5 = "sc start %%1" fullword ascii
        $s6 = "net stop %%1" fullword ascii
        $s7 = "WorkerRun" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and 5 of them ) or ( $x1 and 2 of ($s*) )
}

rule Codoso_CustomTCP_3
{

    meta:
        description = "Detects Codoso APT CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "d66106ec2e743dae1d71b60a602ca713b93077f56a47045f4fc9143aa3957090"

    strings:
        $s1 = "DnsApi.dll" fullword ascii
        $s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
        $s3 = "CONNECT %s:%d hTTP/1.1" ascii
        $s4 = "CONNECT %s:%d HTTp/1.1" ascii
        $s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
        $s6 = "iphlpapi.dll" ascii
        $s7 = "%systemroot%\\Web\\" ascii
        $s8 = "Proxy-Authorization: Negotiate %s" ascii
        $s9 = "CLSID\\{%s}\\InprocServer32" ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 500KB and 5 of them ) or 7 of them
}

rule Codoso_CustomTCP_2
{

    meta:
        description = "Detects Codoso APT CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"

    strings:
        $s1 = "varus_service_x86.dll" fullword ascii
        $s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
        $s3 = "net start %%1" fullword ascii
        $s4 = "ping 127.1 > nul" fullword ascii
        $s5 = "McInitMISPAlertEx" fullword ascii
        $s6 = "sc start %%1" fullword ascii
        $s7 = "B_WKNDNSK^" fullword ascii
        $s8 = "net stop %%1" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 406KB and all of them
}

rule Codoso_PGV_PVID_6
{

    meta:
        description = "Detects Codoso APT PGV_PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "4b16f6e8414d4192d0286b273b254fa1bd633f5d3d07ceebd03dfdfc32d0f17f"

    strings:
        $s0 = "rundll32 \"%s\",%s" fullword ascii
        $s1 = "/c ping 127.%d & del \"%s\"" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}

rule Codoso_Gh0st_3
{

    meta:
        description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"

    strings:
        $x1 = "RunMeByDLL32" fullword ascii
        $s1 = "svchost.dll" fullword wide
        $s2 = "server.dll" fullword ascii
        $s3 = "Copyright ? 2008" fullword wide
        $s4 = "testsupdate33" fullword ascii
        $s5 = "Device Protect Application" fullword wide
        $s6 = "MSVCP60.DLL" fullword ascii /* Goodware String - occured 1 times */
        $s7 = "mail-news.eicp.net" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 195KB and $x1 or 4 of them
}

rule Codoso_Gh0st_2
{

    meta:
        description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"

    strings:
        $s0 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
        $s1 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
        $s13 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
        $s14 = "%s -r debug 1" fullword ascii
        $s15 = "\\\\.\\keymmdrv1" fullword ascii
        $s17 = "RunMeByDLL32" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}

rule Codoso_CustomTCP
{

    meta:
        description = "Codoso CustomTCP Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"

    strings:
        $s4 = "wnyglw" fullword ascii
        $s5 = "WorkerRun" fullword ascii
        $s7 = "boazdcd" fullword ascii
        $s8 = "wayflw" fullword ascii
        $s9 = "CODETABL" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 405KB and all of them
}

/* Super Rules ------------------------------------------------------------- */

rule Codoso_PGV_PVID_5
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $s1 = "/c del %s >> NUL" fullword ascii
        $s2 = "%s%s.manifest" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Codoso_Gh0st_1
{

    meta:
        description = "Detects Codoso APT Gh0st Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "5402c785037614d09ad41e41e11093635455b53afd55aa054a09a84274725841"
        hash2 = "7dc7cec2c3f7e56499175691f64060ebd955813002d4db780e68a8f6e7d0a8f8"
        hash3 = "d7004910a87c90ade7e5ff6169f2b866ece667d2feebed6f0ec856fb838d2297"

    strings:
        $x1 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
        $x2 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
        $x3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
        $x4 = "\\\\.\\keymmdrv1" fullword ascii
        $s1 = "spideragent.exe" fullword ascii
        $s2 = "AVGIDSAgent.exe" fullword ascii
        $s3 = "kavsvc.exe" fullword ascii
        $s4 = "mspaint.exe" fullword ascii
        $s5 = "kav.exe" fullword ascii
        $s6 = "avp.exe" fullword ascii
        $s7 = "NAV.exe" fullword ascii
        $c1 = "Elevation:Administrator!new:" wide
        $c2 = "Global\\RUNDLL32EXITEVENT_NAME{12845-8654-543}" fullword ascii
        $c3 = "\\sysprep\\sysprep.exe" fullword wide
        $c4 = "\\sysprep\\CRYPTBASE.dll" fullword wide
        $c5 = "Global\\TERMINATEEVENT_NAME{12845-8654-542}" fullword ascii
        $c6 = "ConsentPromptBehaviorAdmin" fullword ascii
        $c7 = "\\sysprep" fullword wide
        $c8 = "Global\\UN{5FFC0C8B-8BE5-49d5-B9F2-BCDC8976EE10}" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and ( 4 of ($s*) or 4 of ($c*) ) or 1 of ($x*) or 6 of ($c*)
}

rule Codoso_PGV_PVID_4
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash2 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
        hash3 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
        hash4 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
        hash5 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $x1 = "dropper, Version 1.0" fullword wide
        $x2 = "dropper" fullword wide
        $x3 = "DROPPER" fullword wide
        $x4 = "About dropper" fullword wide
        $s1 = "Microsoft Windows Manager Utility" fullword wide
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\" fullword ascii /* Goodware String - occured 9 times */
        $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify" fullword ascii /* Goodware String - occured 10 times */
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii /* Goodware String - occured 46 times */
        $s5 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"></supportedOS>" fullword ascii /* Goodware String - occured 65 times */
    condition:
        uint16(0) == 0x5a4d and filesize < 900KB and 1 of ($x*) and 2 of ($s*)
}

rule Codoso_PlugX_1
{

    meta:
        description = "Detects Codoso APT PlugX Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "0b8cbc9b4761ab35acce2aa12ba2c0a283afd596b565705514fd802c8b1e144b"
        hash2 = "448711bd3f689ceebb736d25253233ac244d48cb766834b8f974c2e9d4b462e8"
        hash3 = "fd22547497ce52049083092429eeff0599d0b11fe61186e91c91e1f76b518fe2"

    strings:
        $s1 = "GETPASSWORD1" fullword ascii
        $s2 = "NvSmartMax.dll" fullword ascii
        $s3 = "LICENSEDLG" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule Codoso_PGV_PVID_3
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "126fbdcfed1dfb31865d4b18db2fb963f49df838bf66922fea0c37e06666aee1"
        hash2 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash3 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
        hash4 = "b2950f2e09f5356e985c38b284ea52175d21feee12e582d674c0da2233b1feb1"
        hash5 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
        hash6 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $x1 = "Copyright (C) Microsoft Corporation.  All rights reserved.(C) 2012" fullword wide

    condition:
        $x1
}

rule Codoso_PGV_PVID_2
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
        hash2 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
        hash3 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

    strings:
        $s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
        $s1 = "regsvr32.exe /s \"%s\"" fullword ascii
        $s2 = "Help and Support" fullword ascii
        $s3 = "netsvcs" fullword ascii
        $s9 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" fullword ascii /* Goodware String - occured 4 times */
        $s10 = "winlogon" fullword ascii /* Goodware String - occured 4 times */
        $s11 = "System\\CurrentControlSet\\Services" fullword ascii /* Goodware String - occured 11 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Codoso_PGV_PVID_1
{

    meta:
        description = "Detects Codoso APT PGV PVID Malware"
        author = "Florian Roth"
        reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
        date = "2016-01-30"
        super_rule = 1
        hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
        hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
        hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
        hash4 = "ce91ea20aa2e6af79508dd0a40ab0981f463b4d2714de55e66d228c579578266"
        hash5 = "e770a298ae819bba1c70d0c9a2e02e4680d3cdba22d558d21caaa74e3970adf1"

    strings:
        $x1 = "Cookie: pgv_pvid=" ascii
        $x2 = "DRIVERS\\ipinip.sys" fullword wide
        $s1 = "TsWorkSpaces.dll" fullword ascii
        $s2 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
        $s3 = "/selfservice/microsites/search.php?%016I64d" fullword ascii
        $s4 = "/solutions/company-size/smb/index.htm?%016I64d" fullword ascii
        $s5 = "Microsoft Chart ActiveX Control" fullword wide
        $s6 = "MSChartCtrl.ocx" fullword wide
        $s7 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
        $s8 = "WUServiceMain" fullword ascii /* Goodware String - occured 2 times */
    condition:
        ( uint16(0) == 0x5a4d and ( 1 of ($x*) or 3 of them ) ) or 5 of them
}


rule dragos_crashoverride_exporting_dlls {
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Export"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
	condition:
		pe.exports("Crash") & pe.characteristics
}

rule dragos_crashoverride_suspcious {
	meta:
		description = "CRASHOVERRIDE v1 Wiper"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
	strings:
		$s0 = "SYS_BASCON.COM" fullword nocase wide
		$s1 = ".pcmp" fullword nocase wide
		$s2 = ".pcmi" fullword nocase wide
		$s3 = ".pcmt" fullword nocase wide
		$s4 = ".cin" fullword nocase wide
	condition:
		pe.exports("Crash") and any of ($s*)
}

rule dragos_crashoverride_name_search {
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Strings and Export"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
	strings:
		$s0 = "101.dll" fullword nocase wide
		$s1 = "Crash101.dll" fullword nocase wide
		$s2 = "104.dll" fullword nocase wide
		$s3 = "Crash104.dll" fullword nocase wide
		$s4 = "61850.dll" fullword nocase wide
		$s5 = "Crash61850.dll" fullword nocase wide
		$s6 = "OPCClientDemo.dll" fullword nocase wide
		$s7 = "OPC" fullword nocase wide
		$s8 = "CrashOPCClientDemo.dll" fullword nocase wide
		$s9 = "D2MultiCommService.exe" fullword nocase wide
		$s10 = "CrashD2MultiCommService.exe" fullword nocase wide
		$s11 = "61850.exe" fullword nocase wide
		$s12 = "OPC.exe" fullword nocase wide
		$s13 = "haslo.exe" fullword nocase wide
		$s14 = "haslo.dat" fullword nocase wide
	condition:
		any of ($s*) and pe.exports("Crash")
}

rule dragos_crashoverride_hashes {
	meta:
		description = "CRASHOVERRIDE Malware Hashes"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
    condition:
        filesize < 1MB and
        hash.sha1(0, filesize) == "f6c21f8189ced6ae150f9ef2e82a3a57843b587d" or  
        hash.sha1(0, filesize) == "cccce62996d578b984984426a024d9b250237533" or 
        hash.sha1(0, filesize) == "8e39eca1e48240c01ee570631ae8f0c9a9637187" or 
        hash.sha1(0, filesize) == "2cb8230281b86fa944d3043ae906016c8b5984d9" or 
        hash.sha1(0, filesize) == "79ca89711cdaedb16b0ccccfdcfbd6aa7e57120a" or  
        hash.sha1(0, filesize) == "94488f214b165512d2fc0438a581f5c9e3bd4d4c" or
        hash.sha1(0, filesize) == "5a5fafbc3fec8d36fd57b075ebf34119ba3bff04" or
        hash.sha1(0, filesize) == "b92149f046f00bb69de329b8457d32c24726ee00" or
        hash.sha1(0, filesize) == "b335163e6eb854df5e08e85026b2c3518891eda8"
}

rule dragos_crashoverride_moduleStrings { 
	meta:
		description = "IEC-104 Interaction Module Program Strings"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
	strings:      
		$s1 = "IEC-104 client: ip=%s; port=%s; ASDU=%u" nocase wide ascii 
		$s2 = " MSTR ->> SLV" nocase wide ascii 
		$s3 = " MSTR <<- SLV" nocase wide ascii 
		$s4 = "Unknown APDU format !!!" nocase wide ascii 
		$s5 = "iec104.log" nocase wide ascii 
	condition:
		any of ($s*)
}

rule dragos_crashoverride_configReader {
    meta:
    description = "CRASHOVERRIDE v1 Config File Parsing"
    author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
    strings:
        $s0 = { 68 e8 ?? ?? ?? 6a 00 e8 a3 ?? ?? ?? 8b f8 83 c4 ?8 }
        $s1 = { 8a 10 3a 11 75 ?? 84 d2 74 12 }
        $s2 = { 33 c0 eb ?? 1b c0 83 c8 ?? }
        $s3 = { 85 c0 75 ?? 8d 95 ?? ?? ?? ?? 8b cf ?? ?? }
    condition:
        all of them
}

rule dragos_crashoverride_weirdMutex {
    meta:
        description = "Blank mutex creation assoicated with CRASHOVERRIDE"
        author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
    strings:
        $s1 = { 81 ec 08 02 00 00 57 33 ff 57 57 57 ff 15 ?? ?? 40 00 a3 ?? ?? ?? 00 85 c0 }
        $s2 = { 8d 85 ?? ?? ?? ff 50 57 57 6a 2e 57 ff 15 ?? ?? ?? 00 68 ?? ?? 40 00}
    condition:
        all of them
}

rule dragos_crashoverride_serviceStomper {
    meta:
        description = "Identify service hollowing and persistence setting"
        author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
    strings:
        $s0 = { 33 c9 51 51 51 51 51 51 ?? ?? ?? }
        $s1 = { 6a ff 6a ff 6a ff 50 ff 15 24 ?? 40 00 ff ?? ?? ff 15 20 ?? 40 00 }
    condition:
        all of them
}

rule dragos_crashoverride_wiperModuleRegistry {
    meta:
        description = "Registry Wiper functionality assoicated with CRASHOVERRIDE"
        author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
    strings:
        $s0 = { 8d 85 a0 ?? ?? ?? 46 50 8d 85 a0 ?? ?? ?? 68 68 0d ?? ?? 50 }
        $s1 = { 6a 02 68 78 0b ?? ?? 6a 02 50 68 b4 0d ?? ?? ff b5 98 ?? ?? ?? ff 15 04 ?? ?? ?? }
        $s2 = { 68 00 02 00 00 8d 85 a0 ?? ?? ?? 50 56 ff b5 9c ?? ?? ?? ff 15 00 ?? ?? ?? 85 c0 }
    condition:
        all of them
}

rule dragos_crashoverride_wiperFileManipulation {
    meta:
		description = "File manipulation actions associated with CRASHOVERRIDE wiper"
        author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
    strings:
        $s0 = { 6a 00 68 80 00 00 00 6a 03 6a 00 6a 02 8b f9 68 00 00 00 40 57 ff 15 1c ?? ?? ?? 8b d8 }
        $s2 = { 6a 00 50 57 56 53 ff 15 4c ?? ?? ?? 56 }
    condition:
        all of them
}
rule Anthem_DeepPanda_sl_txt_packed
{

    meta:
        description = "Anthem Hack Deep Panda - ScanLine sl-txt-packed"
        author = "Florian Roth"
        date = "2015/02/08"
        hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"

    strings:
        $s0 = "Command line port scanner" fullword wide
        $s1 = "sl.exe" fullword wide
        $s2 = "CPports.txt" fullword ascii
        $s3 = ",GET / HTTP/.}" fullword ascii
        $s4 = "Foundstone Inc." fullword wide
        $s9 = " 2002 Foundstone Inc." fullword wide
        $s15 = ", Inc. 2002" fullword ascii
        $s20 = "ICMP Time" fullword ascii

    condition:
        all of them
}

rule Anthem_DeepPanda_lot1
{

    meta:
        description = "Anthem Hack Deep Panda - lot1.tmp-pwdump"
        author = "Florian Roth"
        date = "2015/02/08"
        hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"

    strings:
        $s0 = "Unable to open target process: %d, pid %d" fullword ascii
        $s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
        $s2 = "Target: Failed to load SAM functions." fullword ascii
        $s5 = "Error writing the test file %s, skipping this share" fullword ascii
        $s6 = "Failed to create service (%s/%s), error %d" fullword ascii
        $s8 = "Service start failed: %d (%s/%s)" fullword ascii
        $s12 = "PwDump.exe" fullword ascii
        $s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
        $s14 = ":\\\\.\\pipe\\%s" fullword ascii
        $s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
        $s16 = "dump logon session" fullword ascii
        $s17 = "Timed out waiting to get our pipe back" fullword ascii
        $s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
        $s20 = "%s\\%s.exe" fullword ascii

    condition:
        10 of them
}

rule Anthem_DeepPanda_htran_exe
{

    meta:
        description = "Anthem Hack Deep Panda - htran-exe"
        author = "Florian Roth"
        date = "2015/02/08"
        hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"

    strings:
        $s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
        $s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
        $s2 = "e:\\VS 2008 Project\\htran\\Release\\htran.pdb" fullword ascii
        $s3 = "[SERVER]connection to %s:%d error" fullword ascii
        $s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s5 = "[-] ERROR: Must supply logfile name." fullword ascii
        $s6 = "[-] There is a error...Create a new connection." fullword ascii
        $s7 = "[+] Accept a Client on port %d from %s" fullword ascii
        $s8 = "======================== htran V%s =======================" fullword ascii
        $s9 = "[-] Socket Listen error." fullword ascii
        $s10 = "[-] ERROR: open logfile" fullword ascii
        $s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s12 = "[+] Make a Connection to %s:%d ......" fullword ascii
        $s14 = "Recv %5d bytes from %s:%d" fullword ascii
        $s15 = "[+] OK! I Closed The Two Socket." fullword ascii
        $s16 = "[+] Waiting another Client on port:%d...." fullword ascii
        $s17 = "[+] Accept a Client on port %d from %s ......" fullword ascii
        $s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii

    condition:
        10 of them
}

rule Anthem_DeepPanda_Trojan_Kakfum
{

    meta:
        description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
        author = "Florian Roth"
        date = "2015/02/08"
        hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
        hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"

    strings:
        $s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
        $s1 = "%s\\sqlsrv32.dll" fullword ascii
        $s2 = "%s\\sqlsrv64.dll" fullword ascii
        $s3 = "%s\\%d.tmp" fullword ascii
        $s4 = "ServiceMaix" fullword ascii
        $s15 = "sqlserver" fullword ascii

    condition:
        all of them
}

rule APT_DeputyDog_Fexel
{

meta:
    author = "ThreatConnect Intelligence Research Team"

strings:
    $180 = "180.150.228.102" wide ascii
    $0808cmd = {25 30 38 78 30 38 78 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 [2-6] 43 00 61 00 6E 00 27 00 74 00 20 00 6F 00 70 00 65 00 6E 00 20 00 73 00 68 00 65 00 6C 00 6C 00 21}
    $cUp = "Upload failed! [Remote error code:" nocase wide ascii
    $DGGYDSYRL = {00 44 47 47 59 44 53 59 52 4C 00}
    $GDGSYDLYR = "GDGSYDLYR_%" wide ascii

condition:
    any of them
}

rule APT_DeputyDog
{

    meta:
        Author      = "FireEye Labs"
        Date        = "2013/09/21"
        Description = "detects string seen in samples used in 2013-3893 0day attacks"
        Reference   = "https://www.fireeye.com/blog/threat-research/2013/09/operation-deputydog-zero-day-cve-2013-3893-attack-against-japanese-targets.html"

    strings:
        $mz = {4d 5a}
        $a = "DGGYDSYRL"

    condition:
        ($mz at 0) and $a
}

rule apt_nix_elf_derusbi
{

    meta:
        Author = "@seifreed"

    strings:
        $ = "LxMain"
        $ = "execve"
        $ = "kill"
        $ = "cp -a %s %s"
        $ = "%s &"
        $ = "dbus-daemon"
        $ = "--noprofile"
        $ = "--norc"
        $ = "TERM=vt100"
        $ = "/proc/%u/cmdline"
        $ = "loadso"
        $ = "/proc/self/exe"
        $ = "Proxy-Connection: Keep-Alive"
        $ = "Connection: Keep-Alive"
        $ = "CONNECT %s"
        $ = "HOST: %s:%d"
        $ = "User-Agent: Mozilla/4.0"
        $ = "Proxy-Authorization: Basic %s"
        $ = "Server: Apache"
        $ = "Proxy-Authenticate"
        $ = "gettimeofday"
        $ = "pthread_create"
        $ = "pthread_join"
        $ = "pthread_mutex_init"
        $ = "pthread_mutex_destroy"
        $ = "pthread_mutex_lock"
        $ = "getsockopt"
        $ = "socket"
        $ = "setsockopt"
        $ = "select"
        $ = "bind"
        $ = "shutdown"
        $ = "listen"
        $ = "opendir"
        $ = "readdir"
        $ = "closedir"
        $ = "rename"

    condition:
        (uint32(0) == 0x4464c457f) and (all of them)
}

rule apt_nix_elf_derusbi_kernelModule
{

    meta:
        Author = "@seifreed"

    strings:
        $ = "__this_module"
        $ = "init_module"
        $ = "unhide_pid"
        $ = "is_hidden_pid"
        $ = "clear_hidden_pid"
        $ = "hide_pid"
        $ = "license"
        $ = "description"
        $ = "srcversion="
        $ = "depends="
        $ = "vermagic="
        $ = "current_task"
        $ = "sock_release"
        $ = "module_layout"
        $ = "init_uts_ns"
        $ = "init_net"
        $ = "init_task"
        $ = "filp_open"
        $ = "__netlink_kernel_create"
        $ = "kfree_skb"

    condition:
        (uint32(0) == 0x4464c457f) and (all of them)
}

rule apt_nix_elf_Derusbi_Linux_SharedMemCreation
{

    meta:
        Author = "@seifreed"

    strings:
        $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

    condition:
        (uint32(0) == 0x464C457F) and (any of them)
}

rule apt_nix_elf_Derusbi_Linux_Strings
{

    meta:
        Author = "@seifreed"

    strings:
        $a1 = "loadso" wide ascii fullword
        $a2 = "\nuname -a\n\n" wide ascii
        $a3 = "/dev/shm/.x11.id" wide ascii
        $a4 = "LxMain64" wide ascii nocase
        $a5 = "# \\u@\\h:\\w \\$ " wide ascii
        $b1 = "0123456789abcdefghijklmnopqrstuvwxyz" wide
        $b2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" wide
        $b3 = "ret %d" wide fullword
        $b4 = "uname -a\n\n" wide ascii
        $b5 = "/proc/%u/cmdline" wide ascii
        $b6 = "/proc/self/exe" wide ascii
        $b7 = "cp -a %s %s" wide ascii
        $c1 = "/dev/pts/4" wide ascii fullword
        $c2 = "/tmp/1408.log" wide ascii fullword

    condition:
        uint32(0) == 0x464C457F and ((1 of ($a*) and 4 of ($b*)) or (1 of ($a*) and 1 of ($c*)) or 2 of ($a*) or all of ($b*))
}

rule apt_win_exe_trojan_derusbi
{

   meta:
        Author = "@seifreed"

   strings:
        $sa_1 = "USB" wide ascii
        $sa_2 = "RAM" wide ascii
        $sa_3 = "SHARE" wide ascii
        $sa_4 = "HOST: %s:%d"
        $sa_5 = "POST"
        $sa_6 = "User-Agent: Mozilla"
        $sa_7 = "Proxy-Connection: Keep-Alive"
        $sa_8 = "Connection: Keep-Alive"
        $sa_9 = "Server: Apache"
        $sa_10 = "HTTP/1.1"
        $sa_11 = "ImagePath"
        $sa_12 = "ZwUnloadDriver"
        $sa_13 = "ZwLoadDriver"
        $sa_14 = "ServiceMain"
        $sa_15 = "regsvr32.exe"
        $sa_16 = "/s /u" wide ascii
        $sa_17 = "rand"
        $sa_18 = "_time64"
        $sa_19 = "DllRegisterServer"
        $sa_20 = "DllUnregisterServer"
        $sa_21 = { 8b [5] 8b ?? d3 ?? 83 ?? 08 30 [5] 40 3b [5] 72 } // Decode Driver
        $sb_1 = "PCC_CMD_PACKET"
        $sb_2 = "PCC_CMD"
        $sb_3 = "PCC_BASEMOD"
        $sb_4 = "PCC_PROXY"
        $sb_5 = "PCC_SYS"
        $sb_6 = "PCC_PROCESS"
        $sb_7 = "PCC_FILE"
        $sb_8 = "PCC_SOCK"
        $sc_1 = "bcdedit -set testsigning" wide ascii
        $sc_2 = "update.microsoft.com" wide ascii
        $sc_3 = "_crt_debugger_hook" wide ascii
        $sc_4 = "ue8G5" wide ascii
        $sd_1 = "NET" wide ascii
        $sd_2 = "\\\\.\\pipe\\%s" wide ascii
        $sd_3 = ".dat" wide ascii
        $sd_4 = "CONNECT %s:%d" wide ascii
        $sd_5 = "\\Device\\" wide ascii
        $se_1 = "-%s-%04d" wide ascii
        $se_2 = "-%04d" wide ascii
        $se_3 = "FAL" wide ascii
        $se_4 = "OK" wide ascii
        $se_5 = "2.03" wide ascii
        $se_6 = "XXXXXXXXXXXXXXX" wide ascii

   condition:
      (uint16(0) == 0x5A4D) and ( (all of ($sa_*)) or ((13 of ($sa_*)) and ( (5 of ($sb_*)) or (3 of ($sc_*)) or (all of ($sd_*)) or ( (1 of ($sc_*)) and (all of ($se_*)) ) ) ) )
}


rule Trojan_Derusbi
{

    meta:
        Author = "RSA_IR"
        Date     = "4Sept13"
        File     = "derusbi_variants v 1.3"
        MD5      = " c0d4c5b669cc5b51862db37e972d31ec "

    strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ?? 40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4 A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}

    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8)
}

rule APT_Derusbi_DeepPanda
{

meta:
    author = "ThreatConnect Intelligence Research Team"
    reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"

strings:
    $D = "Dom4!nUserP4ss" wide ascii

condition:
    $D
}


rule APT_Derusbi_Gen
{

meta:
    author = "ThreatConnect Intelligence Research Team"

strings:
    $2 = "273ce6-b29f-90d618c0" wide ascii
    $A = "Ace123dx" fullword wide ascii
    $A1 = "Ace123dxl!" fullword wide ascii
    $A2 = "Ace123dx!@#x" fullword wide ascii
    $C = "/Catelog/login1.asp" wide ascii
    $DF = "~DFTMP$$$$$.1" wide ascii
    $G = "GET /Query.asp?loginid=" wide ascii
    $L = "LoadConfigFromReg failded" wide ascii
    $L1 = "LoadConfigFromBuildin success" wide ascii
    $ph = "/photoe/photo.asp HTTP" wide ascii
    $PO = "POST /photos/photo.asp" wide ascii
    $PC = "PCC_IDENT" wide ascii

condition:
    any of them
}

/*
    Yara Rule Set
    Author: Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud
    Date: 2015-12-09
   Reference = http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family
    Identifier: Derusbi Dez 2015
*/

rule derusbi_kernel
{

    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"

    strings:
        $token1 = "$$$--Hello"
        $token2 = "Wrod--$$$"
        $cfg = "XXXXXXXXXXXXXXX"
        $class = ".?AVPCC_BASEMOD@@"
        $MZ = "MZ"

    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}

rule derusbi_linux
{

    meta:
        description = "Derusbi Server Linux version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"

    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"

    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-15
    Identifier: Derusbi Dez 2015
*/

rule Derusbi_Kernel_Driver_WD_UDFS
{

    meta:
        description = "Detects Derusbi Kernel Driver"
        author = "Florian Roth"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
        date = "2015-12-15"
        score = 80
        hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
        hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
        hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
        hash4 = "e27fb16dce7fff714f4b05f2cef53e1919a34d7ec0e595f2eaa155861a213e59"

    strings:
        $x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
        $x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
        $x3 = "\\??\\pipe\\usbpcex%d" fullword wide
        $x4 = "\\??\\pipe\\usbpcg%d" fullword wide
        $x5 = "$$$--Hello" fullword ascii
        $x6 = "Wrod--$$$" fullword ascii
        $s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s2 = "Update.dll" fullword ascii
        $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
        $s4 = "\\Driver\\nsiproxy" fullword wide
        $s5 = "HOST: %s" fullword ascii

condition:
        uint16(0) == 0x5a4d and filesize < 800KB and (2 of ($x*) or all of ($s*))
}

rule Derusbi_Code_Signing_Cert
{

    meta:
        description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
        author = "Florian Roth"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
        date = "2015-12-15"
        score = 40

   strings:
      $s1 = "Fuqing Dawu Technology Co.,Ltd.0" fullword ascii
      $s2 = "XL Games Co.,Ltd.0" fullword ascii
      $s3 = "Wemade Entertainment co.,Ltd0" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule XOR_4byte_Key
{

    meta:
        description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
        author = "Florian Roth"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
        date = "2015-12-15"
        score = 60

   strings:
      /* Op Code */
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }
      /*
      test    ecx, ecx
      jz      short loc_590170
      xor     [esi], eax
      add     [esi], ebx
      add     esi, 4
      dec     ecx
      jmp     short loc_590162
      */

   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and all of them
}

rule apt_win32_dll_bergard_pgv_pvid_variant
{

    meta:
        copyright = "Fidelis Cybersecurity"
        reference = "http://www.threatgeek.com/2016/05/turbo-twist-two-64-bit-derusbi-strains-converge.html"

    strings:
        $ = "Accept:"
        $ = "User-Agent: %s"
        $ = "Host: %s:%d"
        $ = "Cache-Control: no-cache"
        $ = "Connection: Keep-Alive"
        $ = "Cookie: pgv_pvid="
        $ = "Content-Type: application/x-octet-stream"
        $ = "User-Agent: %s"
        $ = "Host: %s:%d"
        $ = "Pragma: no-cache"
        $ = "Connection: Keep-Alive"
        $ = "HTTP/1.0"

    condition:
        (uint16(0) == 0x5A4D) and (all of them)
}




rule ROKRAT_payload : TAU DPRK APT

{

meta:

    author = "CarbonBlack Threat Research" //JMyers

    date = "2018-Jan-11"

    description = "Designed to catch loader observed used with ROKRAT malware"
    
    reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"

    rule_version = 1

  	yara_version = "3.7.0"

    TLP = "White"

  	exemplar_hashes = "e200517ab9482e787a59e60accc8552bd0c844687cd0cf8ec4238ed2fc2fa573"

strings:

	$s1 = "api.box.com/oauth2/token" wide

	$s2 = "upload.box.com/api/2.0/files/content" wide

	$s3 = "api.pcloud.com/uploadfile?path=%s&filename=%s&nopartial=1" wide

	$s4 = "cloud-api.yandex.net/v1/disk/resources/download?path=%s" wide

	$s5 = "SbieDll.dll"

	$s6 = "dbghelp.dll"

	$s7 = "api_log.dll"

	$s8 = "dir_watch.dll"

	$s9 = "def_%s.jpg" wide

	$s10 = "pho_%s_%d.jpg" wide

	$s11 = "login=%s&password=%s&login_submit=Authorizing" wide

	$s12 = "gdiplus.dll"

	$s13 = "Set-Cookie:\\b*{.+?}\\n" wide

	$s14 = "charset={[A-Za-z0-9\\-_]+}" wide

condition:

	12 of ($s*)

}


rule Dubnium_Sample_1
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        hash1 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"

    strings:
        $key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
        $key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule Dubnium_Sample_2
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"

    strings:
        $x1 = ":*:::D:\\:c:~:" fullword ascii
        $s2 = "SPMUVR" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Dubnium_Sample_3
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        hash1 = "caefcdf2b4e5a928cdf9360b70960337f751ec4a5ab8c0b75851fc9a1ab507a8"
        hash2 = "e0362d319a8d0e13eda782a0d8da960dd96043e6cc3500faeae521d1747576e5"
        hash3 = "a77d1c452291a6f2f6ed89a4bac88dd03d38acde709b0061efd9f50e6d9f3827"

    strings:
        $x1 = "copy /y \"%s\" \"%s\" " fullword ascii
        $x2 = "del /f \"%s\" " fullword ascii
        $s1 = "del /f /ah \"%s\" " fullword ascii
        $s2 = "if exist \"%s\" goto Rept " fullword ascii
        $s3 = "\\*.*.lnk" fullword ascii
        $s4 = "Dropped" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and 5 of them
}

rule Dubnium_Sample_5
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        super_rule = 1
        hash1 = "16f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
        hash2 = "1feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
        hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
        hash4 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
        hash5 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
        hash6 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
        hash7 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
        hash8 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
        hash9 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"

    strings:
        $s1 = "$innn[i$[i$^i[e[mdi[m$jf1Wehn[^Whl[^iin_hf$11mahZijnjbi[^[W[f1n$dej$[hn]1[W1ni1l[ic1j[mZjchl$$^he[[j[a[1_iWc[e[" fullword ascii
        $s2 = "h$YWdh[$ij7^e$n[[_[h[i[[[\\][1$1[[j1W1[1cjm1[$[k1ZW_$$ncn[[Inbnnc[I9enanid[fZCX" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}

rule Dubnium_Sample_6
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        super_rule = 1
        hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
        hash2 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
        hash3 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"

    strings:
        $s1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&()`~-_=+[{]{;',." fullword ascii
        $s2 = "e_$0[bW\\RZY\\jb\\ZY[nimiRc[jRZ]" fullword ascii
        $s3 = "f_RIdJ0W9RFb[$Fbc9[k_?Wn" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}

rule Dubnium_Sample_7
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        super_rule = 1
        hash1 = "16f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
        hash2 = "1feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
        hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
        hash4 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
        hash5 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
        hash6 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
        hash7 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
        hash8 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"

    strings:
        $s1 = "hWI[$lZ![nJ_[[lk[8Ihlo8ZiIl[[[$Ynk[f_8[88WWWJW[YWnl$$Z[ilf!$IZ$!W>Wl![W!k!$l!WoW8$nj8![8n_I^$[>_n[ZY[[Xhn_c!nnfK[!Z" fullword ascii
        $s2 = "[i_^])[$n!]Wj^,h[,!WZmk^o$dZ[h[e!&W!l[$nd[d&)^Z\\^[[iWh][[[jPYO[g$$e&n\\,Wfg$[<g$[[ninn:j!!)Wk[nj[[o!!Y" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}

rule Dubnium_Sample_SSHOpenSSL
{

    meta:
        description = "Detects sample mentioned in the Dubnium Report"
        author = "Florian Roth"
        reference = "https://goo.gl/AW9Cuu"
        date = "2016-06-10"
        hash1 = "6f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
        hash2 = "feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
        hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
        hash4 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
        hash5 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
        hash6 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"

    strings:
        $s1 = "sshkeypairgen.exe" fullword wide
        $s2 = "OpenSSL: FATAL" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}

rule apt_duqu2_loaders 
{ 

    meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 samples"
		last_modified = "2015-06-09"
		version = "1.0"

    strings:
		$a1 = "{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide 
		$a2 = "\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a4 = "\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
		$a5 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
		$a8 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" wide
		$a9 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" wide
		$a7 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" wide
		$b1 = "MSI.dll"
		$b2 = "msi.dll"
		$b3 = "StartAction"
		$c1 = "msisvc_32@" wide
		$c2 = "PROP=" wide
		$c3 = "-Embedding" wide
		$c4 = "S:(ML;;NW;;;LW)" wide
		$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
		$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}
	
    condition:
		( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 ) or ( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}

rule apt_duqu2_drivers 
{ 

    meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 drivers"
		last_modified = "2015-06-09"
		version = "1.0"
	
    strings:
		$a1 = "\\DosDevices\\port_optimizer" wide nocase 
		$a2 = "romanian.antihacker" 
		$a3 = "PortOptimizerTermSrv" wide 
		$a4 = "ugly.gorilla1"
		$b1 = "NdisIMCopySendCompletePerPacketInfo" 
		$b2 = "NdisReEnumerateProtocolBindings"
		$b3 = "NdisOpenProtocolConfiguration"
	condition:
		uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000
}

/* Action Loader Samples --------------------------------------------------- */

rule Duqu2_Generic1 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Generic Rule"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		super_rule = 1
		hash0 = "3f9168facb13429105a749d35569d1e91465d313"
		hash1 = "0a574234615fb2382d85cd6d1a250d6c437afecc"
		hash2 = "38447ed1d5e3454fe17699f86c0039f30cc64cde"
		hash3 = "5282d073ee1b3f6ce32222ccc2f6066e2ca9c172"
		hash4 = "edfca3f0196788f7fde22bd92a8817a957c10c52"
		hash5 = "6a4ffa6ca4d6fde8a30b6c8739785f4bd2b5c415"
		hash6 = "00170bf9983e70e8dd4f7afe3a92ce1d12664467"
		hash7 = "32f8689fd18c723339414618817edec6239b18f3"
		hash8 = "f860acec9920bc009a1ad5991f3d5871c2613672"
		hash9 = "413ba509e41c526373f991d1244bc7c7637d3e13"
		hash10 = "29cd99a9b6d11a09615b3f9ef63f1f3cffe7ead8"
		hash11 = "dfe1cb775719b529138e054e7246717304db00b1"
	
    strings:
		$s0 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" fullword wide
		$s1 = "SetSecurityDescriptorSacl" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 189 times */
		$s2 = "msisvc_32@" fullword wide
		$s3 = "CompareStringA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1392 times */
		$s4 = "GetCommandLineW" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 1680 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule APT_Kaspersky_Duqu2_procexp 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Malicious MSI"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash1 = "2422835716066b6bcecb045ddd4f1fbc9486667a"
		hash2 = "b120620b5d82b05fee2c2153ceaf305807fa9f79"
		hash3 = "288ebfe21a71f83b5575dfcc92242579fb13910d"
	
    strings:
		$x1 = "svcmsi_32.dll" fullword wide
		$x2 = "msi3_32.dll" fullword wide
		$x3 = "msi4_32.dll" fullword wide
		$x4 = "MSI.dll" fullword ascii
		$s1 = "SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" fullword wide
		$s2 = "Sysinternals installer" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "Process Explorer" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 5 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) ) and ( all of ($s*) )
}

rule APT_Kaspersky_Duqu2_SamsungPrint 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - file 2a9a5afc342cde12c6eb9a91ad29f7afdfd8f0fb17b983dcfddceccfbc17af69"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "ce39f41eb4506805efca7993d3b0b506ab6776ca"
	
    strings:
		$s0 = "Installer for printer drivers and applications" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "msi4_32.dll" fullword wide
		$s2 = "HASHVAL" fullword wide
		$s3 = "SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" fullword wide
		$s4 = "ca.dll" fullword ascii
		$s5 = "Samsung Electronics Co., Ltd." fullword wide
	
    condition:
		uint16(0) == 0x5a4d and filesize < 82KB and all of them
}

rule APT_Kaspersky_Duqu2_msi3_32 
{

    meta:
		description = "Kaspersky APT Report - Duqu2 Sample - file d8a849654ab97debaf28ae5b749c3b1ff1812ea49978713853333db48c3972c3"
		author = "Florian Roth"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
	
    strings:
		$s0 = "ProcessUserAccounts" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s4 = "msi3_32.dll" fullword wide
		$s5 = "RunDLL" fullword ascii
		$s6 = "MSI Custom Action v3" fullword wide
		$s7 = "msi3_32" fullword wide
		$s8 = "Operating System" fullword wide /* PEStudio Blacklist: strings */ /* Goodware String - occured 9203 times */
	
    condition:
		uint16(0) == 0x5a4d and filesize < 72KB and all of them
}

rule Emissary_APT_Malware_1 
{

    meta:
        description = "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"
        author = "Florian Roth"
        reference = "http://goo.gl/V0epcf"
        date = "2016-01-02"
        score = 75
        hash1 = "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab"
        hash2 = "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629"
        hash3 = "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290"
        hash4 = "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664"
        hash5 = "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc"
        hash6 = "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b"
        hash7 = "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8"
        hash8 = "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9"
        hash9 = "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d"
        hash10 = "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538"
        hash11 = "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051"
        hash12 = "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0"
        hash13 = "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb"

    strings:
        $s1 = "cmd.exe /c %s > %s" fullword ascii
        $s2 = "execute cmd timeout." fullword ascii
        $s3 = "rundll32.exe \"%s\",Setting" fullword ascii
        $s4 = "DownloadFile - exception:%s." fullword ascii
        $s5 = "CDllApp::InitInstance() - Evnet create successful." fullword ascii
        $s6 = "UploadFile - EncryptBuffer Error" fullword ascii
        $s7 = "WinDLL.dll" fullword wide
        $s8 = "DownloadFile - exception:%s,code:0x%08x." fullword ascii
        $s9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" fullword ascii
        $s10 = "CDllApp::InitInstance() - Evnet already exists." fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and 3 of them
}
rule Backdoored_ssh {
meta:
author = "Kaspersky"
reference = "https://securelist.com/energetic-bear-crouching-yeti/85345/"
actor = "Energetic Bear/Crouching Yeti"
strings:
$a1 = "OpenSSH"
$a2 = "usage: ssh"
$a3 = "HISTFILE"
condition:
uint32(0) == 0x464c457f and filesize<1000000 and all of ($a*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-08
   Identifier: Equation Group hack tools leaked by ShadowBrokers

   Notice: Avoiding false positives is difficult with almost no antivirus
   coverage during the rule testing phase. Please report back false positives
   via https://github.com/Neo23x0/signature-base/issues
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_emptycriss {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file emptycriss"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a698d35a0c4d25fd960bd40c1de1022bb0763b77938bf279e91c9330060b0b91"
   strings:
      $s1 = "./emptycriss <target IP>" fullword ascii
      $s2 = "Cut and paste the following to the telnet prompt:" fullword ascii
      $s8 = "environ define TTYPROMPT abcdef" fullword ascii
   condition:
      ( filesize < 50KB and 1 of them )
}

rule EquationGroup_scripme {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scripme"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a1adf1c1caad96e7b7fd92cbf419c4cfa13214e66497c9e46ec274a487cd098a"
   strings:
      $x1 = "running \\\"tcpdump -n -n\\\", on the environment variable \\$INTERFACE, scripted" fullword ascii
      $x2 = "Cannot read $opetc/scripme.override -- are you root?" ascii
      $x3 = "$ENV{EXPLOIT_SCRIPME}" ascii
      $x4 = "$opetc/scripme.override" ascii
   condition:
      ( filesize < 30KB and 1 of them )
}

rule EquationGroup_cryptTool {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"
   strings:
      $s1 = "The encryption key is " fullword ascii
      $s2 = "___tempFile2.out" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EquationGroup_dumppoppy {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file dumppoppy"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4a5c01590063c78d03c092570b3206fde211daaa885caac2ab0d42051d4fc719"
   strings:
      $x1 = "Unless the -c (clobber) option is used, if two RETR commands of the" fullword ascii
      $x2 = "mywarn(\"End of $destfile determined by \\\"^Connection closed by foreign host\\\"\")" fullword ascii

      $l1 = "End of $destfile determined by \"^Connection closed by foreign host"
   condition:
      ( filesize < 20KB and 1 of them )
}

rule EquationGroup_Auditcleaner {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file Auditcleaner"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8c172a60fa9e50f0df493bf5baeb7cc311baef327431526c47114335e0097626"
   strings:
      $x1 = "> /var/log/audit/audit.log; rm -f ." ascii
      $x2 = "Pastables to run on target:" ascii
      $x3 = "cp /var/log/audit/audit.log .tmp" ascii

      $l1 = "Here is the first good cron session from" fullword ascii
      $l2 = "No need to clean LOGIN lines." fullword ascii
   condition:
      ( filesize < 300KB and 1 of them )
}

rule EquationGroup_reverse_shell {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file reverse.shell.script"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d29aa24e6fb9e3b3d007847e1630635d6c70186a36c4ab95268d28aa12896826"
   strings:
      $s1 = "sh >/dev/tcp/" ascii
      $s2 = " <&1 2>&1" fullword ascii
   condition:
      ( filesize < 1KB and all of them )
}

rule EquationGroup_tnmunger {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"
   strings:
      $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
      $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 10KB and 1 of them )
}

rule EquationGroup_ys_ratload {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a340e5b5cfd41076bd4d6ad89d7157eeac264db97a9dddaae15d935937f10d75"
   strings:
      $x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
      $x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $x3 = "CALLBACK_PORT=32177" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 3KB and 1 of them )
}

rule EquationGroup_eh_1_1_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0f8dd094516f1be96da5f9addc0f97bcac8f2a348374bd9631aa912344559628"
   strings:
      $x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
      $x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
      $x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and 1 of them )
}

rule EquationGroup_evolvingstrategy_1_0_1 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file evolvingstrategy.1.0.1.1"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "fe70e16715992cc86bbef3e71240f55c7d73815b4247d7e866c845b970233c1b"
   strings:
      $s1 = "chown root sh; chmod 4777 sh;" fullword ascii
      $s2 = "cp /bin/sh .;chown root sh;" fullword ascii

      $l1 = "echo clean up when elevated:" fullword ascii

      $x1 = "EXE=$DIR/sbin/ey_vrupdate" fullword ascii
   condition:
      ( filesize < 4KB and 1 of them )
}

rule EquationGroup_toast_v3_2_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file toast_v3.2.0.1-linux"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2ce2d16d24069dc29cf1464819a9dc6deed38d1e5ffc86d175b06ddb691b648b"
   strings:
      $x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
      $s5 = "Roasting ->%s<- at ->%d:%d<-" fullword ascii
      $s6 = "rbnoil -Roasting ->" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}

rule EquationGroup_sshobo {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"
   strings:
      $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
      $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
      $x3 = "~#  - list forwarded connections" fullword ascii
      $x4 = "packet_inject_ignore: block" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and all of them )
}

rule EquationGroup_magicjack_v1_1_0_0_client_1_1_0_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file magicjack_v1.1.0.0_client-1.1.0.0.py"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
   strings:
      $x1 = "result = self.send_command(\"ls -al %s\" % self.options.DIR)" fullword ascii
      $x2 = "cmd += \"D=-l%s \" % self.options.LISTEN_PORT" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 80KB and 1 of them )
}

rule EquationGroup_packrat {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file packrat"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d3e067879c51947d715fc2cf0d8d91c897fe9f50cae6784739b5c17e8a8559cf"
   strings:
      $x2 = "Use this on target to get your RAT:" fullword ascii
      $x3 = "$ratremotename && " fullword ascii
      $x5 = "$command = \"$nc$bindto -vv -l -p $port < ${ratremotename}\" ;" fullword ascii
   condition:
      ( filesize < 70KB and 1 of them )
}

rule EquationGroup_telex {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file telex"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "e9713b15fc164e0f64783e7a2eac189a40e0a60e2268bd7132cfdc624dfe54ef"
   strings:
      $x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
      $x2 = "target is not vulnerable. exiting" fullword ascii
      $s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
      $s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}

rule EquationGroup_calserver {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file calserver"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "048625e9a0ca46d7fe221e262c8dd05e7a5339990ffae2fb65a9b0d705ad6099"
   strings:
      $x1 = "usage: %s <host> <port> e <contents of a local file to be executed on target>" fullword ascii
      $x2 = "Writing your %s to target." fullword ascii
      $x3 = "(e)xploit, (r)ead, (m)ove and then write, (w)rite" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}

rule EquationGroup_porkclient {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "5c14e3bcbf230a1d7e2909876b045e34b1486c8df3c85fb582d9c93ad7c57748"
   strings:
      $s1 = "-c COMMAND: shell command string" fullword ascii
      $s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
      $s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}

rule EquationGroup_electricslide {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d27814b725568fa73641e86fa51850a17e54905c045b8b31a9a5b6d2bdc6f014"
   strings:
      $x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
      $x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
      $x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
      $x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}

rule EquationGroup_libXmexploit2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file libXmexploit2.8"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d7ed0234d074266cb37dd6a6a60119adb7d75cc6cc3b38654c8951b643944796"
   strings:
      $s1 = "Usage: ./exp command display_to_return_to" fullword ascii
      $s2 = "sizeof shellcode = %d" fullword ascii
      $s3 = "Execve failed!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 40KB and 1 of them )
}

rule EquationGroup_wrap_telnet {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4962b307a42ba18e987d82aa61eba15491898978d0e2f0e4beb02371bf0fd5b4"
   strings:
      $s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
      $s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 4KB and 1 of them )
}

rule EquationGroup_elgingamble {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"
   strings:
      $x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
      $x2 = "[-] kernel not vulnerable" fullword ascii
      $x3 = "[-] failed to spawn shell: %s" fullword ascii
      $x4 = "-s shell           Use shell instead of %s" fullword ascii
   condition:
      1 of them
}

rule EquationGroup_cmsd {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "634c50614e1f5f132f49ae204c4a28f62a32a39a3446084db5b0b49b564034b8"
   strings:
      $x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
      $x2 = "error: not vulnerable" fullword ascii

      $s1 = "port=%d connected! " fullword ascii
      $s2 = "xxx.XXXXXX" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_ebbshave {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ebbshave.v5"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "eb5e0053299e087c87c2d5c6f90531cc1946019c85a43a2998c7b66a6f19ca4b"
   strings:
      $s1 = "executing ./ebbnew_linux -r %s -v %s -A %s %s -t %s -p %s" fullword ascii
      $s2 = "./ebbnew_linux.wrapper -o 2 -v 2 -t 192.168.10.4 -p 32772" fullword ascii
      $s3 = "version 1 - Start with option #18 first, if it fails then try this option" fullword ascii
      $s4 = "%s is a wrapper program for ebbnew_linux exploit for Sparc Solaris RPC services" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 20KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_eggbasket {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
   strings:
      $x1 = "# Building Shellcode into exploit." fullword ascii
      $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
      $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_jparsescan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
   strings:
      $s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
      $s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them )
}

rule EquationGroup_sambal {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sambal"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2abf4bbe4debd619b99cb944298f43312db0947217437e6b71b9ea6e9a1a4fec"
   strings:
      $s1 = "+ Bruteforce mode." fullword ascii
      $s3 = "+ Host is not running samba!" fullword ascii
      $s4 = "+ connecting back to: [%d.%d.%d.%d:45295]" fullword ascii
      $s5 = "+ Exploit failed, try -b to bruteforce." fullword ascii
      $s7 = "Usage: %s [-bBcCdfprsStv] [host]" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_pclean_v2_1_1_2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
   strings:
      $s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
      $s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 40KB and all of them )
}

rule EquationGroup_envisioncollision {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file envisioncollision"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "75d5ec573afaf8064f5d516ae61fd105012cbeaaaa09c8c193c7b4f9c0646ea1"
   strings:
      $x1 = "mysql \\$D --host=\\$H --user=\\$U --password=\\\"\\$P\\\" -e \\\"select * from \\$T" fullword ascii
      $x2 = "Window 3: $0 -Uadmin -Ppassword -i127.0.0.1 -Dipboard -c\\\"sleep 500|nc" fullword ascii
      $s3 = "$ua->agent(\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\");" fullword ascii
      $s4 = "$url = $host . \"/admin/index.php?adsess=\" . $enter . \"&app=core&module=applications&section=hooks&do=install_hook\";" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_cmsex {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cmsex"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2d8ae842e7b16172599f061b5b1f223386684a7482e87feeb47a38a3f011b810"
   strings:
      $x1 = "Usage: %s -i <ip_addr/hostname> -c <command> -T <target_type> (-u <port> | -t <port>) " fullword ascii
      $x2 = "-i target ip address / hostname " fullword ascii
      $x3 = "Note: Choosing the correct target type is a bit of guesswork." fullword ascii
      $x4 = "Solaris rpc.cmsd remote root exploit" fullword ascii
      $x5 = "If one choice fails, you may want to try another." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_exze {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"
   strings:
      $s1 = "shellFile" fullword ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "zeke_remove" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and all of them )
}

rule EquationGroup_porkserver {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file porkserver"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "7b5f86e289047dd673e8a09438d49ec43832b561bac39b95098f5bf4095b8b4a"
   strings:
      $s1 = "%s/%s server failing (looping), service terminated" fullword ascii
      $s2 = "getpwnam: %s: No such user" fullword ascii
      $s3 = "execv %s: %m" fullword ascii
      $s4 = "%s/%s: unknown service" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and 3 of them )
}

rule EquationGroup_DUL {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "24d1d50960d4ebf348b48b4db4a15e50f328ab2c0e24db805b106d527fc5fe8e"
   strings:
      $x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
      $x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and 1 of them ) or ( all of them )
}

rule EquationGroup_slugger2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"
   strings:
      $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
      $x2 = "command must be less than 61 chars" fullword ascii

      $s1 = "__rw_read_waiting" fullword ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "__mutexkind" fullword ascii
      $s4 = "__rw_pshared" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ($x*) ) ) or ( all of them )
}

rule EquationGroup_ebbisland {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ebbisland"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "eba07c98c7e960bb6c71dafde85f5da9f74fd61bc87793c87e04b1ae2d77e977"
   strings:
      $x1 = "Usage: %s [-V] -t <target_ip> -p port" fullword ascii
      $x2 = "error - shellcode not as expected - unable to fix up" fullword ascii
      $x3 = "WARNING - core wipe mode - this will leave a core file on target" fullword ascii
      $x4 = "[-C] wipe target core file (leaves less incriminating core on failed target)" fullword ascii
      $x5 = "-A <jumpAddr> (shellcode address)" fullword ascii
      $x6 = "*** Insane undocumented incremental port mode!!! ***" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_jackpop {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jackpop"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0b208af860bb2c7ef6b1ae1fcef604c2c3d15fc558ad8ea241160bf4cbac1519"
   strings:
      $x1 = "%x:%d  --> %x:%d %d bytes" fullword ascii

      $s1 = "client: can't bind to local address, are you root?" fullword ascii
      $s2 = "Unable to register port" fullword ascii
      $s3 = "Could not resolve destination" fullword ascii
      $s4 = "raw troubles" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 3 of them ) or ( all of them )
}

rule EquationGroup_parsescan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
   strings:
      $s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
      $s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_jscan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"
   strings:
      $s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
      $s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_promptkill {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file promptkill"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "b448204503849926be249a9bafbfc1e36ef16421c5d3cfac5dac91f35eeaa52d"
   strings:
      $x1 = "exec(\"xterm $xargs -e /current/tmp/promptkill.kid.$tag $pid\");" fullword ascii
      $x2 = "$xargs=\"-title \\\"Kill process $pid?\\\" -name \\\"Kill process $pid?\\\" -bg white -fg red -geometry 202x19+0+0\" ;" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_epoxyresin_v1_0_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file epoxyresin.v1.0.0.1"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "eea8a6a674d5063d7d6fc9fe07060f35b16172de6d273748d70576b01bf01c73"
   strings:
      $x1 = "[-] kernel not vulnerable" fullword ascii

      $s1 = ".tmp.%d.XXXXXX" fullword ascii
      $s2 = "[-] couldn't create temp file" fullword ascii
      $s3 = "/boot/System.map-%s" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and $x1 ) or ( all of them )
}

rule EquationGroup_estopmoonlit {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estopmoonlit"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "707ecc234ed07c16119644742ebf563b319b515bf57fd43b669d3791a1c5e220"
   strings:
      $x1 = "[+] shellcode prepared, re-executing" fullword ascii
      $x2 = "[-] kernel not vulnerable: prctl" fullword ascii
      $x3 = "[-] shell failed" fullword ascii
      $x4 = "[!] selinux apparently enforcing.  Continue [y|n]? " fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_envoytomato {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file envoytomato"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "9bd001057cc97b81fdf2450be7bf3b34f1941379e588a7173ab7fffca41d4ad5"
   strings:
      $s1 = "[-] kernel not vulnerable" fullword ascii
      $s2 = "[-] failed to spawn shell" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_smash {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"
   strings:
      $x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
      $x2 = "no command given!! bailing..." fullword ascii
      $x3 = "no port. assuming 22..." fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_ratload {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ratload"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4a4a8f2f90529bee081ce2188131bac4e658a374a270007399f80af74c16f398"
   strings:
      $x1 = "/tmp/ratload.tmp.sh" fullword ascii
      $x2 = "Remote Usage: /bin/telnet locip locport < /dev/console | /bin/sh\"" fullword ascii
      $s6 = "uncompress -f ${NAME}.Z && PATH=. ${ARGS1} ${NAME} ${ARGS2} && rm -f ${NAME}" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_ys {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.auto"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a6387307d64778f8d9cfc60382fdcf0627cde886e952b8d73cc61755ed9fde15"
   strings:
      $x1 = "EXPLOIT_SCRIPME=\"$EXPLOIT_SCRIPME\"" fullword ascii
      $x3 = "DEFTARGET=`head /current/etc/opscript.txt 2>/dev/null | grepip 2>/dev/null | head -1`" fullword ascii
      $x4 = "FATAL ERROR: -x port and -n port MUST NOT BE THE SAME." fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_ewok {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"
   strings:
      $x1 = "Example: ewok -t target public" fullword ascii
      $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
      $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
      $x4 = "--- ewok version" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and 1 of them )
}

rule EquationGroup_xspy {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
   strings:
      $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}

rule EquationGroup_estesfox {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estesfox"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "33530cae130ee9d9deeee60df9292c00242c0fe6f7b8eedef8ed09881b7e1d5a"
   strings:
      $x1 = "chown root:root x;chmod 4777 x`' /tmp/logwatch.$2/cron" fullword ascii
   condition:
      all of them
}


rule EquationGroup_scanner {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scanner"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
   strings:
      $x1 = "program version netid     address             service         owner" fullword ascii
      $x4 = "*** Sorry about the raw output, I'll leave it for now" fullword ascii
      $x5 = "-scan winn %s one" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

/* Super Rules ------------------------------------------------------------- */

rule EquationGroup__ftshell_ftshell_v3_10_3_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
      hash2 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"
   strings:
      $s1 = "set uRemoteUploadCommand \"[exec cat /current/.ourtn-ftshell-upcommand]\"" fullword ascii
      $s2 = "send \"\\[ \\\"\\$BASH\\\" = \\\"/bin/bash\\\" -o \\\"\\$SHELL\\\" = \\\"/bin/bash\\\" \\] &&" ascii
      $s3 = "system rm -f /current/tmp/ftshell.latest" fullword ascii
      $s4 = "# ftshell -- File Transfer Shell" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__scanner_scanner_v2_1_2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files scanner, scanner.v2.1.2"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
      hash2 = "9807aaa7208ed6c5da91c7c30ca13d58d16336ebf9753a5cea513bcb59de2cff"
   strings:
      $s1 = "Welcome to the network scanning tool" fullword ascii
      $s2 = "Scanning port %d" fullword ascii
      $s3 = "/current/down/cmdout/scans" fullword ascii
      $s4 = "Scan for SSH version" fullword ascii
      $s5 = "program vers proto   port  service" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and 2 of them ) or ( all of them )
}

rule EquationGroup__ghost_sparc_ghost_x86_3 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
      hash2 = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"
   strings:
      $x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
      $x2 = "Sending shellcode as part of an open command..." fullword ascii
      $x3 = "cmdshellcode" fullword ascii
      $x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__pclean_v2_1_1_pclean_v2_1_1_4 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files pclean.v2.1.1.0-linux-i386, pclean.v2.1.1.0-linux-x86_64"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
      hash2 = "ab7f26faed8bc2341d0517d9cb2bbf41795f753cd21340887fc2803dc1b9a1dd"
   strings:
      $s1 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
      $s2 = "e.g.: -n 1-1024,1080,6666,31337 " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and all of them )
}

rule EquationGroup__jparsescan_parsescan_5 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files jparsescan, parsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      hash2 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
   strings:
      $s1 = "# default is to dump out all scanned hosts found" fullword ascii
      $s2 = "$bool .= \" -r \" if (/mibiisa.* -r/);" fullword ascii
      $s3 = "sadmind is available on two ports, this also works)" fullword ascii
      $s4 = "-x IP      gives \\\"hostname:# users:load ...\\\" if positive xwin scan" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 40KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__funnelout_v4_1_0_1 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files funnelout.v4.1.0.1.pl"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash2 = "457ed14e806fdbda91c4237c8dc058c55e5678f1eecdd78572eff6ca0ed86d33"
   strings:
      $s1 = "header(\"Set-Cookie: bbsessionhash=\" . \\$hash . \"; path=/; HttpOnly\");" fullword ascii
      $s2 = "if ($code =~ /proxyhost/) {" fullword ascii
      $s3 = "\\$rk[1] = \\$rk[1] - 1;" fullword ascii
      $s4 = "#existsUser($u) or die \"User '$u' does not exist in database.\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}

rule EquationGroup__magicjack_v1_1_0_0_client {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files magicjack_v1.1.0.0_client-1.1.0.0.py"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
   strings:
      $s1 = "temp = ((left >> 1) ^ right) & 0x55555555" fullword ascii
      $s2 = "right ^= (temp <<  16) & 0xffffffff" fullword ascii
      $s3 = "tempresult = \"\"" fullword ascii
      $s4 = "num = self.bytes2long(data)" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 80KB and 3 of them ) or ( all of them )
}

rule EquationGroup__ftshell {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
      hash4 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"
   strings:
      $s1 = "if { [string length $uRemoteUploadCommand]" fullword ascii
      $s2 = "processUpload" fullword ascii
      $s3 = "global dothisreallyquiet" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-09
   Identifier: Equation Group hack tools leaked by ShadowBrokers
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_store_linux_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"
   strings:
      $s1 = "[-] Failed to map file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "[!] Name has size of 0!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}

rule EquationGroup_morerats_client_genkey {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "0ce455fb7f46e54a5db9bef85df1087ff14d2fc60a88f2becd5badb9c7fe3e89"
   strings:
      $x1 = "rsakey_txt = lo_execute('openssl genrsa 2048 2> /dev/null | openssl rsa -text 2> /dev/null')" fullword ascii
      $x2 = "client_auth = binascii.hexlify(lo_execute('openssl rand 16'))" fullword ascii
   condition:
      ( filesize < 3KB and all of them )
}

rule EquationGroup_cursetingle_2_0_1_2_mswin32_v_2_0_1 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "614bf159b956f20d66cedf25af7503b41e91841c75707af0cdf4495084092a61"
   strings:
      $s1 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s2 = "0123456789abcdefABCEDF:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_cursesleepy_mswin32_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6293439b4b49e94f923c76e302f5fc437023c91e063e67877d22333f05a24352"
   strings:
      $s1 = "A}%j,R" fullword ascii
      $op1 = { a1 e0 43 41 00 8b 0d 34 44 41 00 6b c0 } /* Opcode */
      $op2 = { 33 C0 F3 A6 74 14 8B 5D 08 8B 4B 34 50 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_porkserver_v3_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "7b5f86e289047dd673e8a09438d49ec43832b561bac39b95098f5bf4095b8b4a"
   strings:
      $s1 = "%s: %s rpcprog=%d, rpcvers = %d/%d, proto=%s, wait.max=%d.%d, user.group=%s.%s builtin=%lx server=%s" fullword ascii
      $s2 = "%s/%s server failing (looping), service terminated" fullword ascii
      $s3 = "getpwnam: %s: No such user" fullword ascii
      $s4 = "execv %s: %m" fullword ascii
      $s5 = "%s/%s: getsockname: %m" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and 4 of them )
}

rule EquationGroup_cursehelper_win2k_i686_v_2_2_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "5ac6fde8a06f4ade10d672e60e92ffbf78c4e8db6b5152e23171f6f53af0bfe1"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}" fullword ascii

      $op1 = { 8d b5 48 ff ff ff 89 34 24 e8 56 2a 00 00 c7 44 } /* Opcode */
      $op2 = { e9 a2 f2 ff ff ff 85 b4 fe ff ff 8b 95 a8 fe ff } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_morerats_client_addkey {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6c67c03716d06a99f20c1044585d6bde7df43fee89f38915db0b03a42a3a9f4b"
   strings:
      $x1 = "print '  -s storebin  use storebin as the Store executable\\n'" fullword ascii
      $x2 = "os.system('%s --file=\"%s\" --wipe > /dev/null' % (storebin, b))" fullword ascii
      $x3 = "print '  -k keyfile   the key text file to inject'" fullword ascii
   condition:
      ( filesize < 20KB and 1 of them )
}

rule EquationGroup_noclient_3_3_2 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "3cf0eb010c431372af5f32e2ee8c757831215f8836cabc7d805572bb5574fc72"
   strings:
      $x1 = "127.0.0.1 is not advisable as a source. Use -l 127.0.0.1 to override this warning" fullword ascii
      $x2 = "iptables -%c OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;" fullword ascii
      $x3 = "noclient: failed to execute %s: %s" fullword ascii
      $x4 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
      $s5 = "Attempting connection from 0.0.0.0:" ascii
   condition:
      ( filesize < 1000KB and 1 of them )
}

rule EquationGroup_curseflower_mswin32_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "fdc452629ff7befe02adea3a135c3744d8585af890a4301b2a10a817e48c5cbf"
   strings:
      $s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii

      $op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_tmpwatch {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"
   strings:
      $s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
      $s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii
   condition:
      ( filesize < 1KB and 1 of them )
}

rule EquationGroup_orleans_stride_sunos5_9_v_2_4_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6a30efb87b28e1a136a66c7708178c27d63a4a76c9c839b2fc43853158cb55ff"
   strings:
      $s1 = "_lib_version" fullword ascii
      $s2 = ",%02d%03d" fullword ascii
      $s3 = "TRANSIT" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EquationGroup_morerats_client_noprep {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a5b191a8ede8297c5bba790ef95201c516d64e2898efaeb44183f8fdfad578bb"
   strings:
      $x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
      $x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
      $x3 = " -i                do not autokill after 5 hours" fullword ascii
   condition:
      ( filesize < 9KB and 1 of them )
}

rule EquationGroup_cursezinger_linuxrh7_3_v_2_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "af7c7d03f59460fa60c48764201e18f3bd3f72441fd2e2ff6a562291134d2135"
   strings:
      $s1 = ",%02d%03d" fullword ascii
      $s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s3 = "__strtoll_internal" fullword ascii
      $s4 = "__strtoul_internal" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and all of them )
}

rule EquationGroup_seconddate_ImplantStandalone_3_0_3 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"
   strings:
      $s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
      $s2 = "G8HcJ HcF LcF0LcN" fullword ascii
      $s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and all of them )
}

rule EquationGroup_watcher_solaris_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "395ec2531970950ffafde234dded0cce0c95f1f9a22763d1d04caa060a5222bb"
   strings:
      $s1 = "getexecname" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s6 = "__fpstart" fullword ascii
      $s12 = "GHFIJKLMNOPQRSTUVXW" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and all of them )
}

rule EquationGroup_gr_dev_bin_now {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "f5ed8312fc6e624b04e1e2d6614f3c651c9e9902ff41f4d069c32caca0869fa4"
   strings:
      $x1 = "HTTP_REFERER=\"https://127.0.0.1:6655/cgi/redmin?op=cron&action=once\"" fullword ascii
      $x2 = "exec /usr/share/redmin/cgi/redmin" fullword ascii
   condition:
      ( filesize < 1KB and 1 of them )
}

rule EquationGroup_gr_dev_bin_post {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "c1546155efa95dbc4e3cc95299a3968fc075f89d33164e78b00b76c7d08a0591"
   strings:
      $x1 = "op=cron&action=once&frame=cronOnceFrame&cronK=cronV&cronCommand=%2Ftmp%2Ftmpwatch&time=12%3A12+01%2F28%2F2005" ascii
   condition:
      ( filesize < 1KB and all of them )
}

rule EquationGroup_curseyo_win2k_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "5dc77614764b23a38610fdd8abe5b2274222f206889e4b0974a3fea569055ed6"
   strings:
      $s1 = "0123456789abcdefABCEDF:" fullword ascii

      $op0 = { c6 06 5b 8b bd 70 ff ff ff 8b 9d 64 ff ff ff 0f } /* Opcode */
      $op1 = { 55 b8 ff ff ff ff 89 e5 83 ec 28 89 7d fc 8b 7d } /* Opcode */
      $op2 = { ff 05 10 64 41 00 89 34 24 e8 df 1e 00 00 e9 31 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_gr {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "d3cd725affd31fa7f0e2595f4d76b09629918612ef0d0307bb85ade1c3985262"
   strings:
      $s1 = "if [ -f /tmp/tmpwatch ] ; then" fullword ascii
      $s2 = "echo \"bailing. try a different name\"" fullword ascii
   condition:
      ( filesize < 1KB and all of them )
}

rule EquationGroup_curseroot_win2k_v_2_1_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a1637948ed6ebbd2e582eb99df0c06b27a77c01ad1779b3d84c65953ca2cb603"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $op0 = { c7 44 24 04 ff ff ff ff 89 04 24 e8 46 65 01 00 } /* Opcode */
      $op1 = { 8d 5d 88 89 1c 24 e8 24 1b 01 00 be ff ff ff ff } /* Opcode */
      $op2 = { d3 e0 48 e9 0c ff ff ff 8b 45 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and $s1 and 2 of ($op*) )
}

rule EquationGroup_cursewham_curserazor_cursezinger_curseroot_win2k {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "aff27115ac705859871ab1bf14137322d1722f63705d6aeada43d18966843225"
      hash2 = "7a25e26950bac51ca8d37cec945eb9c38a55fa9a53bc96da53b74378fb10b67e"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $s3 = ",%02d%03d" fullword ascii
      $s4 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii

      $op1 = { 7d ec 8d 74 3f 01 0f af f7 c1 c6 05 } /* Opcode */
      $op2 = { 29 f1 89 fb d3 eb 89 f1 d3 e7 } /* Opcode */
      $op3 = { 7d e4 8d 5c 3f 01 0f af df c1 c3 05 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule EquationGroup_watcher_linux_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "ce4c9bfa25b8aad8ea68cc275187a894dec5d79e8c0b2f2f3ec4184dc5f402b8"
   strings:
      $s1 = "invalid option `" fullword ascii
      $s8 = "readdir64" fullword ascii
      $s9 = "89:z89:%r%opw" fullword wide
      $s13 = "Ropopoprstuvwypypop" fullword wide
      $s17 = "Missing argument for `-x'." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and all of them )
}

rule EquationGroup_charm_saver_win2k_v_2_0_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "0f7936a37482532a8ba5df4112643ed7579dd0e59181bfca9c641b9ba0a9912f"
   strings:
      $s2 = "0123456789abcdefABCEDF:" fullword ascii

      $op0 = { b8 ff ff ff ff 7f 65 eb 30 8b 55 0c 89 d7 0f b6 } /* Opcode */
      $op2 = { ba ff ff ff ff 83 c4 6c 89 d0 5b 5e 5f 5d c3 90 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_cursehappy_win2k_v_6_1_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "eb669afd246a7ac4de79724abcce5bda38117b3138908b90cac58936520ea632"
   strings:
      $op1 = { e8 24 2c 01 00 85 c0 89 c6 ba ff ff ff ff 74 d6 } /* Opcode */
      $op2 = { 89 4c 24 04 89 34 24 89 44 24 08 e8 ce 49 ff ff } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_morerats_client_Store {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "619944358bc0e1faffd652b6af0600de055c5e7f1f1d91a8051ed9adf5a5b465"
   strings:
      $s1 = "[-] Failed to mmap file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "Missing argument for `-x'." fullword ascii
      $s4 = "[!] Value has size of 0!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and 2 of them )
}

rule EquationGroup_watcher_linux_x86_64_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a8d65593f6296d6d06230bcede53b9152842f1eee56a2a72b0a88c4f463a09c3"
   strings:
      $s1 = "forceprismheader" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s3 = "forceprism" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and all of them )
}

rule EquationGroup_linux_exactchange {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      super_rule = 1
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
      hash3 = "39d4f83c7e64f5b89df9851bdba917cf73a3449920a6925b6cd379f2fdec2a8b"
      hash4 = "15e12c1c27304e4a68a268e392be4972f7c6edf3d4d387e5b7d2ed77a5b43c2c"
   strings:
      $x1 = "[+] looking for vulnerable socket" fullword ascii
      $x2 = "can't use 32-bit exploit on 64-bit target" fullword ascii
      $x3 = "[+] %s socket ready, exploiting..." fullword ascii
      $x4 = "[!] nothing looks vulnerable, trying everything" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}

rule EquationGroup_x86_linux_exactchange {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      super_rule = 1
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
   strings:
      $x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
      $x2 = "[+] kernel stack size is %d" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-15
   Identifier: Equation Group Toolset - Windows Folder
   Reference: https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_Toolset_Apr17_Eclipsedwing_Rpcproxy_Pcdlllauncher {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "48251fb89c510fb3efa14c4b5b546fbde918ed8bb25f041a801e3874bd4f60f8"
      hash2 = "237c22f4d43fdacfcbd6e1b5f1c71578279b7b06ea8e512b4b6b50f10e8ccf10"
      hash3 = "79a584c127ac6a5e96f02a9c5288043ceb7445de2840b608fc99b55cf86507ed"
   strings:
      $x1 = "[-] Failed to Prepare Payload!" fullword ascii
      $x2 = "ShellcodeStartOffset" fullword ascii
      $x3 = "[*] Waiting for AuthCode from exploit" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Explodingcantouch_1_2_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0cdde7472b077610d0068aa7e9035da89fe5d435549749707cae24495c8d8444"
   strings:
      $x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s2 = "[!]Warning: Error on first request - path size may actually be larger than indicated." fullword ascii
      $s4 = "<http://%s/%s> (Not <locktoken:write1>) <http://%s/>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Architouch_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
   strings:
      $s1 = "[+] Target is %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
   strings:
      $x1 = "[-] Error appending shellcode buffer" fullword ascii
      $x2 = "[-] Shellcode is too big" fullword ascii
      $x3 = "[+] Exploit Payload Sent!" fullword ascii
      $x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
   strings:
      $x1 = "[+] Connected to target %s:%d" fullword ascii
      $x2 = "[-] build_exploit_run_x64():" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Darkpulsar_1_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b439ed18262aec387984184e86bfdb31ca501172b1c066398f8c56d128ba855a"
   strings:
      $x1 = "[%s] - Error upgraded DLL architecture does not match target architecture (0x%x)" fullword ascii
      $x2 = "[%s] - Error building DLL loading shellcode" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Educatedscholar_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4cce9e39c376f67c16df3bcd69efd9b7472c3b478e2e5ef347e1410f1105c38d"
   strings:
      $x1 = "[+] Shellcode Callback %s:%d" fullword ascii
      $x2 = "[+] Exploiting Target" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Doublepulsar_1_3_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13"
   strings:
      $x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
      $x2 = "[.] Sending shellcode to inject DLL" fullword ascii
      $x3 = "[-] Error setting ShellcodeFile name" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Erraticgophertouch_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "729eacf20fe71bd74e57a6b829b45113c5d45003933118b53835779f0b049bad"
   strings:
      $x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
      $x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
      $x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Smbtouch_1_1_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
   strings:
      $x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Educatedscholartouch_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f4b958a0d3bb52cb34f18ea293d43fa301ceadb4a259d3503db912d0a9a1e4d8"
   strings:
      $x1 = "[!] A vulnerable target will not respond." fullword ascii
      $x2 = "[-] Target NOT Vulernable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Esteemaudittouch_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
   strings:
      $x1 = "[-] Touching the target failed!" fullword ascii
      $x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Rpctouch_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"
   strings:
      $x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
      $x2 = "[*] SMB String: %s (%s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Mofconfig_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"
   strings:
      $x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Easypi_Explodingcan {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "dc1ddad7e8801b5e37748ec40531a105ba359654ffe8bdb069bd29fb0b5afd94"
      hash2 = "97af543cf1fb59d21ba5ec6cb2f88c8c79c835f19c8f659057d2f58c321a0ad4"
   strings:
      $x1 = "[-] %s - Target might not be in a usable state." fullword ascii
      $x2 = "[*] Exploiting Target" fullword ascii
      $x3 = "[-] Encoding Exploit Payload failed!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Eclipsedwingtouch_1_0_4 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "46da99d80fc3eae5d1d5ab2da02ed7e61416e1eafeb23f37b180c46e9eff8a1c"
   strings:
      $x1 = "[-] The target is NOT vulnerable" fullword ascii
      $x2 = "[+] The target IS VULNERABLE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Iistouch_1_2_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"
   strings:
      $x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
      $x2 = "[+] IIS Target OS: %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Namedpipetouch_2_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "cb5849fcbc473c7df886828d225293ffbd8ee58e221d03b840fd212baeda6e89"
      hash2 = "043d1c9aae6be65f06ab6f0b923e173a96b536cf84e57bfd7eeb9034cd1df8ea"
   strings:
      $s1 = "[*] Summary: %d pipes found" fullword ascii
      $s3 = "[+] Testing %d pipes" fullword ascii
      $s6 = "[-] Error on SMB startup, aborting" fullword ascii
      $s12 = "92a761c29b946aa458876ff78375e0e28bc8acb0" fullword ascii

      $op1 = { 68 10 10 40 00 56 e8 e1 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_Easybee_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"
   strings:
      $x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
      $x2 = "Logging out of WebAdmin (as target account)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Regread_1_1_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
   strings:
      $s1 = "[+] Connected to the Registry Service" fullword ascii
      $s2 = "f08d49ac41d1023d9d462d58af51414daff95a6a" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Englishmansdentist_1_2_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"
   strings:
      $x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
      $x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Architouch_Eternalsynergy_Smbtouch {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
      hash2 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
      hash3 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
   strings:
      $s1 = "NtErrorMoreProcessingRequired" fullword ascii
      $s2 = "Command Format Error: Error=%x" fullword ascii
      $s3 = "NtErrorPasswordRestriction" fullword ascii

      $op0 = { 8a 85 58 ff ff ff 88 43 4d }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_Eternalromance_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
      hash3 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
   strings:
      $x1 = "[+] Backdoor shellcode written" fullword ascii
      $x2 = "[*] Attempting exploit method %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__Emphasismine {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "dcaf91bd4af7cc7d1fb24b5292be4e99c7adf4147892f6b3b909d1d84dd4e45b"
      hash2 = "348eb0a6592fcf9da816f4f7fc134bcae1b61c880d7574f4e19398c4ea467f26"
   strings:
      $x1 = "Error: Could not calloc() for shellcode buffer" fullword ascii
      $x2 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii
      $x3 = "Generating shellcode" fullword ascii
      $x4 = "([0-9a-zA-Z]+) OK LOGOUT completed" fullword ascii
      $x5 = "Error: Domino is not the expected version. (%s, %s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Eternalromance {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
   strings:
      $x1 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii
      $x2 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii
      $x3 = "[-] Error: Backdoor not present on target" fullword ascii
      $x4 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them ) or 2 of them
}

rule EquationGroup_Toolset_Apr17_Gen4 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "fe7ce2fdb245c62e4183c728bc97e966a98fdc8ffd795ed09da23f96e85dcdcd"
      hash2 = "0989bfe351342a7a1150b676b5fd5cbdbc201b66abcb23137b1c4de77a8f61a6"
      hash3 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      hash4 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
      hash5 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
      hash6 = "9d98e044eedc7272823ba8ed80dff372fde7f3d1bece4e5affb21e16f7381eb2"
      hash7 = "dfce29df4d198c669a87366dd56a7426192481d794f71cd5bb525b08132ed4f7"
      hash8 = "87fdc6c32b9aa8ae97c7efbbd5c9ae8ec5595079fc1488f433beef658efcb4e9"
      hash9 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      hash10 = "d94b99908f528fa4deb56b11eac29f6a6e244a7b3aac36b11b807f2f74c6d8be"
      hash11 = "4b07d9d964b2c0231c1db7526237631bb83d0db80b3c9574cc414463703462d3"
      hash12 = "30b63abde1e871c90df05137ec08df3fa73dedbdb39cb4bd2a2df4ca65bc4e53"
      hash13 = "02c1b08224b7ad4ac3a5b7b8e3268802ee61c1ec30e93e392fa597ae3acc45f7"
      hash14 = "690f09859ddc6cd933c56b9597f76e18b62a633f64193a51f76f52f67bc2f7f0"
   strings:
      $x1 = "[+] \"TargetPort\"      %hu" fullword ascii
      $x2 = "---<<<  Complete  >>>---" fullword ascii
      $x3 = "[+] \"NetworkTimeout\"  %hu" fullword ascii

      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and ( 1 of ($x*) or 2 of them ) )
}

rule EquationGroup_Toolset_Apr17_Gen1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "1b5b33931eb29733a42d18d8ee85b5cd7d53e81892ff3e60e2e97f3d0b184d31"
      hash2 = "139697168e4f0a2cc73105205c0ddc90c357df38d93dbade761392184df680c7"
   strings:
      $x1 = "Restart with the new protocol, address, and port as target." fullword ascii
      $x2 = "TargetPort      : %s (%u)" fullword ascii
      $x3 = "Error: strchr() could not find '@' in account name." fullword ascii
      $x4 = "TargetAcctPwd   : %s" fullword ascii
      $x5 = "Creating CURL connection handle..." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Gen2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "7fe425cd040608132d4f4ab2671e04b340a102a20c97ffdcf1b75be43a9369b5"
      hash2 = "561c0d4fc6e0ff0a78613d238c96aed4226fbb7bb9ceea1d19bc770207a6be1e"
      hash3 = "f2e90e04ddd05fa5f9b2fec024cd07365aebc098593d636038ebc2720700662b"
      hash4 = "8f7e10a8eedea37ee3222c447410fd5b949bd352d72ef22ef0b2821d9df2f5ba"
   strings:
      $s1 = "[+] Setting password : (NULL)" fullword ascii
      $s2 = "[-] TbBuffCpy() failed!" fullword ascii
      $s3 = "[+] SMB negotiation" fullword ascii
      $s4 = "12345678-1234-ABCD-EF00-0123456789AB" fullword ascii
      $s5 = "Value must end with 0000 (2 NULLs)" fullword ascii
      $s6 = "[*] Configuring Payload" fullword ascii
      $s7 = "[*] Connecting to listener" fullword ascii

      $op1 = { b0 42 40 00 89 44 24 30 c7 44 24 34 }
      $op2 = { eb 59 8b 4c 24 10 68 1c 46 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of ($s*) and 1 of ($op*) ) or 3 of them
}

rule EquationGroup_Toolset_Apr17_Gen3 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      hash2 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
      hash3 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
      hash4 = "9d98e044eedc7272823ba8ed80dff372fde7f3d1bece4e5affb21e16f7381eb2"
      hash5 = "dfce29df4d198c669a87366dd56a7426192481d794f71cd5bb525b08132ed4f7"
      hash6 = "87fdc6c32b9aa8ae97c7efbbd5c9ae8ec5595079fc1488f433beef658efcb4e9"
      hash7 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      hash8 = "d94b99908f528fa4deb56b11eac29f6a6e244a7b3aac36b11b807f2f74c6d8be"
      hash9 = "4b07d9d964b2c0231c1db7526237631bb83d0db80b3c9574cc414463703462d3"
      hash10 = "30b63abde1e871c90df05137ec08df3fa73dedbdb39cb4bd2a2df4ca65bc4e53"
      hash11 = "02c1b08224b7ad4ac3a5b7b8e3268802ee61c1ec30e93e392fa597ae3acc45f7"
      hash12 = "690f09859ddc6cd933c56b9597f76e18b62a633f64193a51f76f52f67bc2f7f0"
   strings:
      $s1 = "Logon failed.  Kerberos ticket not yet valid (target and KDC times not synchronized)" fullword ascii
      $s2 = "[-] Could not set \"CredentialType\"" fullword ascii

      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-15
   Identifier: Equation Group Tools - Resource Folder
   Reference: https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_Toolset_Apr17_yak {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "66ff332f84690642f4e05891a15bf0c9783be2a64edb2ef2d04c9205b47deb19"
   strings:
      $x1 = "-xd = dump archive data & store in scancodes.txt" fullword ascii
      $x2 = "-------- driver start token -------" fullword wide
      $x3 = "-------- keystart token -------" fullword wide
      $x4 = "-xta = same as -xt but show special chars & store in keys_all.txt" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_AdUser_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fd2efb226969bc82e2e38769a10a8a751138db69f4594a8de4b3c0522d4d885f"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule EquationGroup_Toolset_Apr17_RemoteExecute_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "770663c07c519677316934cf482e500a73540d9933342c425f3e56258e6e6d8b"
   strings:
      $op1 = { 53 00 63 00 68 00 65 00 64 00 75 00 6C 00 65 00
               00 00 00 00 53 00 65 00 72 00 76 00 69 00 63 00
               65 00 73 00 41 00 63 00 74 00 69 00 76 00 65 00
               00 00 00 00 FF FF FF FF 00 00 00 00 B0 17 00 68
               5C 00 70 00 69 00 70 00 65 00 5C 00 53 00 65 00
               63 00 6F 00 6E 00 64 00 61 00 72 00 79 00 4C 00
               6F 00 67 00 6F 00 6E 00 00 00 00 00 5C 00 00 00
               57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C 00
               44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00 00
               6E 00 63 00 61 00 63 00 6E 00 5F 00 6E 00 70 00
               00 00 00 00 5C 00 70 00 69 00 70 00 65 00 5C 00
               53 00 45 00 43 00 4C 00 4F 00 47 00 4F 00 4E }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Banner_Implant9x {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "5d69a8cfc9b636448f023fcf18d111f13a8e6bcb9a693eb96276e0d796ab4e0c"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii

      $op1 = { c9 c3 57 8d 85 2c eb ff ff }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and all of them )
}

rule EquationGroup_Toolset_Apr17_greatdoc_dll_config {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fd9d0abfa727784dd07562656967d220286fc0d63bcf7e2c35d4c02bc2e5fc2e"
   strings:
      $x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
      $x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
      $x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
      $x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_scanner {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f180bdb247687ea9f1b58aded225d5c80a13327422cd1e0515ea891166372c53"
   strings:
      $x1 = "+daemon_version,system,processor,refid,clock" fullword ascii
      $x2 = "Usage: %s typeofscan IP_address" fullword ascii
      $x3 = "# scanning ip  %d.%d.%d.%d" fullword ascii
      $x4 = "Welcome to the network scanning tool" fullword ascii
      $x5 = "***** %s ***** (length %d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Mcl_NtMemory_Std {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "087db4f2dbf8e0679de421fec8fb2e6dd50625112eb232e4acc1408cc0bcd2d7"
   strings:
      $op1 = { 44 24 37 50 c6 44 24 38 72 c6 44 }
      $op2 = { 44 24 33 6f c6 44 24 34 77 c6 }
      $op3 = { 3b 65 c6 44 24 3c 73 c6 44 24 3d 73 c6 44 24 3e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_tacothief {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c71953cc84c27dc61df8f6f452c870a7880a204e9e21d9fd006a5c023b052b35"
   strings:
      $x1 = "File too large!  Must be less than 655360 bytes." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ntevt {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4254ee5e688fc09bdc72bcc9c51b1524a2bb25a9fb841feaf03bc7ec1a9975bf"
   strings:
      $x1 = "c:\\ntevt.pdb" fullword ascii

      $s1 = "ARASPVU" fullword ascii

      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and $x1 or 3 of them )
}

rule EquationGroup_Toolset_Apr17_Processes_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "69cf7643dbecc5f9b4b29edfda6c0295bc782f0e438f19be8338426f30b4cc74"
   strings:
      $s1 = "Select * from Win32_Process" fullword ascii
      $s3 = "\\\\%ls\\root\\cimv2" fullword wide
      $s5 = "%4ls%2ls%2ls%2ls%2ls%2ls.%11l[0-9]%1l[+-]%6s" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_st_lp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3b6f756cca096548dcad2b6c241c1dafd16806c060bec82a530f4d38755286a2"
   strings:
      $x1 = "Previous command: set injection processes (status=0x%x)" fullword ascii
      $x2 = "Secondary injection process is <null> [no secondary process will be used]" fullword ascii
      $x3 = "Enter the address to be used as the spoofed IP source address (xxx.xxx.xxx.xxx) -> " fullword ascii
      $x4 = "E: Execute a Command on the Implant" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_FullThreadDump {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b68f3f32bfa6cf11145c9fb9bf0075a5ca3938ea218b1cc29ad62f7b9e043255"
   strings:
      $s1 = "FullThreadDump.class" fullword ascii
      $s2 = "ThreadMonitor.class" fullword ascii
      $s3 = "Deadlock$DeadlockThread.class" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_EpWrapper {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a8eed17665ee22198670e22458eb8c9028ff77130788f24f44986cce6cebff8d"
   strings:
      $x1 = "* Failed to get remote TCP socket address" fullword wide
      $x2 = "* Failed to get 'LPStart' export" fullword wide
      $s5 = "Usage: %ls <logdir> <dll_search_path> <dll_to_load_path> <socket>" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f9ea8ff5985b94f635d03f3aab9ad4fb4e8c2ad931137dba4f8ee8a809421b91"
   strings:
      $s1 = "0M1U1Z1p1" fullword ascii

      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_DllLoad_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a42d5201af655e43cefef30d7511697e6faa2469dc4a74bc10aa060b522a1cf5"
   strings:
      $s1 = "BzWKJD+" fullword ascii

      $op1 = { 44 24 6c 6c 88 5c 24 6d }
      $op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 }
      $op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_EXPA {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2017176d3b5731a188eca1b71c50fb938c19d6260c9ff58c7c9534e317d315f8"
   strings:
      $x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
      $x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
      $x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
      $x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_RemoteExecute_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4a649ca8da7b5499821a768c650a397216cdc95d826862bf30fcc4725ce8587f"
   strings:
      $s1 = "Win32_Process" fullword ascii
      $s2 = "\\\\%ls\\root\\cimv2" fullword wide

      $op1 = { 83 7b 18 01 75 12 83 63 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DS_ParseLogs {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0228691d63038b072cdbf50782990d505507757efbfa87655bb2182cf6375956"
   strings:
      $x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
      $x2 = "* Capture header not found at start of buffer" fullword wide
      $x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Oracle_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "8e9be4960c62ed7f210ce08f291e410ce0929cd3a86fe70315d7222e3df4587e"
   strings:
      $op0 = { fe ff ff ff 48 89 9c 24 80 21 00 00 48 89 ac 24 }
      $op1 = { e9 34 11 00 00 b8 3e 01 00 00 e9 2a 11 00 00 b8 }
      $op2 = { 48 8b ca e8 bf 84 00 00 4c 8b e0 8d 34 00 44 8d }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DmGz_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "5964966041f93d5d0fb63ce4a85cf9f7a73845065e10519b0947d4a065fdbdf2"
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii
      $s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetResourceName {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "537793d5158aecd0debae25416450bd885725adfc8ca53b0577a3df4b0222e2e"
   strings:
      $x1 = "Updates the name of the dll or executable in the resource file" fullword ascii
      $x2 = "*NOTE: SetResourceName does not work with PeddleCheap versions" fullword ascii
      $x3 = "2 = [appinit.dll] level4 dll" fullword ascii
      $x4 = "1 = [spcss32.exe] level3 exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_drivers_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "ee8b048f1c6ba821d92c15d614c2d937c32aeda7b7ea0943fd4f640b57b1c1ab"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "hZwLoadDriver" fullword ascii

      $op1 = { b0 01 e8 58 04 00 00 c3 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Shares_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "6c57fb33c5e7d2dee415ae6168c9c3e0decca41ffe023ff13056ff37609235cb"
   strings:
      $s1 = "Select * from Win32_Share" fullword ascii
      $s2 = "slocalhost" fullword wide
      $s3 = "\\\\%ls\\root\\cimv2" fullword wide
      $s4 = "\\\\%ls\\%ls" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DUMPEL {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "bf42532be2d36f522dca7d3d3eb40b1d25c33d508a5a37c7e28f148945136dc6"
   strings:
      $x1 = "dumpel -f file [-s \\\\server]" fullword ascii
      $x2 = "records will not appear in the dumped log." fullword ascii
      $x3 = "obj\\i386\\Dumpel.exe" fullword ascii
      $s13 = "DUMPEL Usage:    " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_ntfltmgr {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3df61b8ef42a995b8f15a0d38bc51f2f08f8d9a2afa1afc94c6f80671cf4a124"
      hash2 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
      hash3 = "980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43"
   strings:
      $s3 = "wCw3wDwAw2wNw@wEwZw2wDwEwBwZwFwFw4w2wZw5w1w4wFwZwGwOwGwGwEw5w2wFwGwDwFwOw" fullword ascii
      $s6 = "w+w;w2w0w6w4w.w(wRw" fullword ascii

      $op1 = { 80 f7 ff ff 49 89 84 34 18 02 00 00 41 83 a4 34 }
      $op2 = { ff 15 0b 34 00 00 eb 92 }
      $op3 = { 4d 8d b4 34 08 02 00 00 4d 85 f6 0f 84 ae }
      $op4 = { 8b ca 2b ce 8d 34 01 0f b7 3e 66 3b 7d f0 89 75 }
      $op5 = { 8a 40 01 00 c7 47 70 }
      $op6 = { e9 3c ff ff ff 6a ff 8d 45 f0 50 e8 27 11 00 00 }
      $op7 = { 8b 45 08 53 57 8b 7d 0c c7 40 34 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 4 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_BH {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7ae9a247b60dc31f424e8a7a3b3f1749ba792ff1f4ba67ac65336220021fce9f"
   strings:
      $op0 = { 44 89 20 e9 40 ff ff ff 8b c2 48 8b 5c 24 60 48 }
      $op1 = { 45 33 c9 49 8d 7f 2c 41 ba }
      $op2 = { 89 44 24 34 eb 17 4c 8d 44 24 28 8b 54 24 30 48 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_LP {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"
   strings:
      $s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
      $s2 = "Format: <command> <target port> [lp port]" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_RemoteCommand_Lp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "57b47613a3b5dd820dae59fc6dc2b76656bd578f015f367675219eb842098846"
   strings:
      $s1 = "Failure parsing command from %hs:%u: os=%u plugin=%u" fullword wide
      $s2 = "Unable to get TCP listen port: %08x" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_lp_mstcp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2ab1e1d23021d887759750a0c053522e9149b7445f840936bbc7e703f8700abd"
   strings:
      $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
      $s2 = "_PacketNDISRequestComplete@12\"" fullword ascii
      $s3 = "_LDNdis5RegDeleteKeys@4" fullword ascii

      $op1 = { 89 7e 04 75 06 66 21 46 02 eb }
      $op2 = { fc 74 1b 8b 49 04 0f b7 d3 66 83 }
      $op3 = { aa 0f b7 45 fc 8b 52 04 8d 4e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( all of ($s*) or all of ($op*) ) )
}

rule EquationGroup_Toolset_Apr17_renamer {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"
   strings:
      $s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
      $s2 = "Log file exists. You must delete it!!!" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_Exploit {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "77486bb828dba77099785feda0ca1d4f33ad0d39b672190079c508b3feb21fb0"
   strings:
      $s1 = "\\\\.\\pipe\\pcheap_reuse" fullword wide
      $s2 = "**** FAILED TO DUPLICATE SOCKET ****" fullword wide
      $s3 = "**** UNABLE TO DUPLICATE SOCKET TYPE %u ****" fullword wide
      $s4 = "YOU CAN IGNORE ANY 'ServiceEntry returned error' messages after this..." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_PC_Level3_Gen {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c7dd49b98f399072c2619758455e8b11c6ee4694bb46b2b423fa89f39b185a97"
      hash2 = "f6b723ef985dfc23202870f56452581a08ecbce85daf8dc7db4491adaa4f6e8f"
   strings:
      $s1 = "S-%u-%u" fullword ascii
      $s2 = "Copyright (C) Microsoft" fullword wide

      $op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
      $op2 = { 44 24 4e 41 88 5c 24 4f ff }
      $op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_put_Implant9x {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "8fcc98d63504bbacdeba0c1e8df82f7c4182febdf9b08c578d1195b72d7e3d5f"
   strings:
      $s1 = "3&3.3<3A3F3K3V3c3m3" fullword ascii

      $op1 = { c9 c2 08 00 b8 72 1c 00 68 e8 c9 fb ff ff 51 56 }
      $op2 = { 40 1b c9 23 c8 03 c8 38 5d 14 74 05 6a 03 58 eb }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_promiscdetect_safe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"
   strings:
      $s1 = "running on this computer!" fullword ascii
      $s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
      $s3 = "Active filter for the adapter:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PacketScan_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9b97cac66d73a9d268a15e47f84b3968b1f7d3d6b68302775d27b99a56fbb75a"
   strings:
      $op0 = { e9 ef fe ff ff ff b5 c0 ef ff ff 8d 85 c8 ef ff }
      $op1 = { c9 c2 04 00 b8 34 26 00 68 e8 40 05 00 00 51 56 }
      $op2 = { e9 0b ff ff ff 8b 45 10 8d 4d c0 89 58 08 c6 45 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetPorts {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "722d3cf03908629bc947c4cca7ce3d6b80590a04616f9df8f05c02de2d482fb2"
   strings:
      $s1 = "USAGE: SetPorts <input file> <output file> <version> <port1> [port2] [port3] [port4] [port5]" fullword ascii
      $s2 = "Valid versions are:  1 = PC 1.2   2 = PC 1.2 (24 hour)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_GrDo_FileScanner_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "8d2e43567e1360714c4271b75c21a940f6b26a789aa0fce30c6478ae4ac587e4"
   strings:
      $s1 = "system32\\winsrv.dll" fullword wide
      $s2 = "raw_open CreateFile error" fullword ascii
      $s3 = "\\dllcache\\" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_msgks_mskgu {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7b4986aee8f5c4dca255431902907b36408f528f6c0f7d7fa21f079fa0a42e09"
      hash2 = "ef906b8a8ad9dca7407e0a467b32d7f7cf32814210964be2bfb5b0e6d2ca1998"
   strings:
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Ifconfig_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "1ebfc0ce7139db43ddacf4a9af2cb83a407d3d1221931d359ee40588cfd0d02b"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%hs" fullword wide

      $op1 = { 0f be 37 85 f6 0f 85 4e ff ff ff 45 85 ed 74 21 }
      $op2 = { 4c 8d 44 24 34 48 8d 57 08 41 8d 49 07 e8 a6 4b }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "ffff3526ed0d550108e97284523566392af8523bbddb5f212df12ef61eaad3e6"
   strings:
      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Dsz_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
      hash2 = "ad1dddd11b664b7c3ad6108178a8dade0a6d9795358c4a7cedbe789c62016670"
   strings:
      $s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_GenKey {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b6f100b21da4f7e3927b03b8b5f0c595703b769d5698c835972ca0c81699ff71"
   strings:
      $x1 = "* PrivateEncrypt -> PublicDecrypt FAILED" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_wmi_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"
   strings:
      $x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_clocksvc {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c1bcd04b41c6b574a5c9367b777efc8b95fe6cc4e526978b7e8e09214337fac1"
   strings:
      $x1 = "~debl00l.tmp" fullword ascii
      $x2 = "\\\\.\\mailslot\\c54321" fullword ascii
      $x3 = "\\\\.\\mailslot\\c12345" fullword ascii
      $x4 = "nowMutex" fullword ascii

      $s1 = "System\\CurrentControlSet\\Services\\MSExchangeIS\\ParametersPrivate" fullword ascii
      $s2 = "000000005017C31B7C7BCF97EC86019F5026BE85FD1FB192F6F4237B78DB12E7DFFB07748BFF6432B3870681D54BEF44077487044681FB94D17ED04217145B98" ascii
      $s3 = "00000000E2C9ADBD8F470C7320D28000353813757F58860E90207F8874D2EB49851D3D3115A210DA6475CCFC111DCC05E4910E50071975F61972DCE345E89D88" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 2 of ($s*) ) )
}

rule EquationGroup_Toolset_Apr17_xxxRIDEAREA {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "214b0de83b04afdd6ad05567825b69663121eda9e804daff9f2da5554ade77c6"
   strings:
      $x1 = "USAGE: %s -i InputFile -o OutputFile [-f FunctionOrdinal] [-a FunctionArgument] [-t ThreadOption]" fullword ascii
      $x2 = "The output payload \"%s\" has a size of %d-bytes." fullword ascii
      $x3 = "ERROR: fwrite(%s) failed on ucPayload" fullword ascii
      $x4 = "Load and execute implant within the existing thread" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_yak_min_install {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f67214083d60f90ffd16b89a0ce921c98185b2032874174691b720514b1fe99e"
   strings:
      $s1 = "driver start" fullword ascii
      $s2 = "DeviceIoControl Error: %d" fullword ascii
      $s3 = "Phlook" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetOurAddr {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "04ccc060d401ddba674371e66e0288ebdbfa7df74b925c5c202109f23fb78504"
   strings:
      $s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
      $s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_GetAdmin_LSADUMP_ModifyPrivilege_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c8b354793ad5a16744cf1d4efdc5fe48d5a0cf0657974eb7145e0088fcf609ff"
      hash2 = "5f06ec411f127f23add9f897dc165eaa68cbe8bb99da8f00a4a360f108bb8741"
   strings:
      $s1 = "\\system32\\win32k.sys" fullword wide
      $s2 = "hKeAddSystemServiceTable" fullword ascii
      $s3 = "hPsDereferencePrimaryToken" fullword ascii
      $s4 = "CcnFormSyncExFBC" fullword wide
      $s5 = "hPsDereferencePrimaryToken" fullword ascii

      $op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
      $op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
      $op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and ( 4 of ($s*) or all of ($op*) ) )
}

rule EquationGroup_Toolset_Apr17_SendPKTrigger {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
   strings:
      $x1 = "----====**** PORT KNOCK TRIGGER BEGIN ****====----" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DmGz_Target_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "55ac29b9a67e0324044dafaba27a7f01ca3d8e4d8e020259025195abe42aa904"
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii

      $op0 = { e8 ce 34 00 00 b8 02 00 00 f0 e9 26 02 00 00 48 }
      $op1 = { 8b 4d 28 e8 02 05 00 00 89 45 34 eb 07 c7 45 34 }
      $op2 = { e8 c2 34 00 00 90 48 8d 8c 24 00 01 00 00 e8 a4 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_mstcp32_DXGHLP16_tdip {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
      hash2 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
      hash3 = "a5ec4d102d802ada7c5083af53fd9d3c9b5aa83be9de58dbb4fac7876faf6d29"
   strings:
      $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
      $s2 = "\\DosDevices\\%ws" fullword wide
      $s3 = "\\Device\\%ws_%ws" fullword wide
      $s4 = "sys\\mstcp32.dbg" fullword ascii
      $s5 = "%ws%03d%ws%wZ" fullword wide
      $s6 = "TCP/IP driver" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 4 of them )
}

rule EquationGroup_Toolset_Apr17_regprobe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "99a42440d4cf1186aad1fd09072bd1265e7c6ebbc8bcafc28340b4fe371767de"
   strings:
      $x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
      $x2 = "key does not exist or pinging w2k system" fullword ascii
      $x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DoubleFeatureDll_dll_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f265defd87094c95c7d3ddf009d115207cd9d4007cf98629e814eda8798906af"
      hash2 = "8d62ca9e6d89f2b835d07deb5e684a576607e4fe3740f77c0570d7b16ebc2985"
      hash3 = "634a80e37e4b32706ad1ea4a2ff414473618a8c42a369880db7cc127c0eb705e"
   strings:
      $s1 = ".dllfD" fullword ascii
      $s2 = "Khsppxu" fullword ascii
      $s3 = "D$8.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_GangsterThief_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "50b269bda5fedcf5a62ee0514c4b14d48d53dd18ac3075dcc80b52d0c2783e06"
   strings:
      $s1 = "\\\\.\\%s:" fullword wide
      $s4 = "raw_open CreateFile error" fullword ascii
      $s5 = "-PATHDELETED-" fullword ascii
      $s6 = "(deleted)" fullword wide
      $s8 = "NULLFILENAME" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_SetCallbackPorts {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "16f66c2593665c2507a78f96c0c2a9583eab0bda13a639e28f550c92f9134ff0"
   strings:
      $s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
      $s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_BH_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0654b4b8727488769390cd091029f08245d690dd90d1120e8feec336d1f9e788"
   strings:
      $s2 = "0M1U1Z1p1" fullword ascii /* base64 encoded string '3U5gZu' */
      $s14 = "SPRQWV" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_rc5 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "69e2c68c6ea7be338497863c0c5ab5c77d5f522f0a84ab20fe9c75c7f81318eb"
   strings:
      $s1 = "Usage: %s [d|e] session_key ciphertext" fullword ascii
      $s2 = "where session_key and ciphertext are strings of hex" fullword ascii
      $s3 = "d = decrypt mode, e = encrypt mode" fullword ascii
      $s4 = "Bad mode, should be 'd' or 'e'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_PC_Level_Generic {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7a6488dd13936e505ec738dcc84b9fec57a5e46aab8aff59b8cfad8f599ea86a"
      hash2 = "0e3cfd48732d0b301925ea3ec6186b62724ec755ed40ed79e7cd6d3df511b8a0"
      hash3 = "d1d6e3903b6b92cc52031c963e2031b5956cadc29cc8b3f2c8f38be20f98a4a7"
      hash4 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
      hash5 = "591abd3d7ee214df25ac25682b673f02219da108d1384261052b5167a36a7645"
      hash6 = "6b71db2d2721ac210977a4c6c8cf7f75a8f5b80b9dbcece1bede1aec179ed213"
      hash7 = "7be4c05cecb920f1010fc13086635591ad0d5b3a3a1f2f4b4a9be466a1bd2b76"
      hash8 = "f9cbccdbdf9ffd2ebf1ee84d0ddddd24a61dbe0858ab7f0131bef6c7b9a19131"
      hash9 = "3cf7a01bdf8e73769c80b75ca269b506c33464d81f574ded8bb20caec2d4cd13"
      hash10 = "a87a871fe32c49862ed68fda99d92efd762a33ababcd9b6b2b909f2e01f59c16"
   strings:
      $s1 = "wshtcpip.WSHGetSocketInformation" fullword ascii
      $s2 = "\\\\.\\%hs" fullword ascii
      $s3 = ".?AVResultIp@Mini_Mcl_Cmd_NetConnections@@" fullword ascii
      $s4 = "Corporation. All rights reserved." fullword wide
      $s5 = { 49 83 3c 24 00 75 02 eb 5d 49 8b 34 24 0f b7 46 }

      $op1 = { 44 24 57 6f c6 44 24 58 6e c6 44 24 59 }
      $op2 = { c6 44 24 56 64 88 5c 24 57 }
      $op3 = { 44 24 6d 4c c6 44 24 6e 6f c6 44 24 6f }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and ( 2 of ($s*) or all of ($op*) )
}

rule EquationGroup_Toolset_Apr17_PC_Level3_http_exe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3e855fbea28e012cd19b31f9d76a73a2df0eb03ba1cb5d22aafe9865150b020c"
   strings:
      $s1 = "Copyright (C) Microsoft" fullword wide

      $op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
      $op2 = { 44 24 4e 41 88 5c 24 4f ff }
      $op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ParseCapture {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c732d790088a4db148d3291a92de5a449e409704b12e00c7508d75ccd90a03f2"
   strings:
      $x1 = "* Encrypted log found.  An encryption key must be provided" fullword ascii
      $x2 = "encryptionkey = e.g., \"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"" fullword ascii
      $x3 = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_ActiveDirectory_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "33c1b7fdee7c70604be1e7baa9eea231164e62d5d5090ce7f807f43229fe5c36"
   strings:
      $s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
      $s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_Legacy_dll {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0cbc5cc2e24f25cb645fb57d6088bcfb893f9eb9f27f8851503a1b33378ff22d"
   strings:
      $op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 }
      $op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 }
      $op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_svctouch {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"
   strings:
      $s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_pwd_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "ee72ac76d82dfec51c8fbcfb5fc99a0a45849a4565177e01d8d23a358e52c542"
   strings:
      $s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii

      $op1 = { 40 50 89 44 24 18 FF 15 34 20 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_KisuComms_Target_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "94eea1bad534a1dc20620919de8046c9966be3dd353a50f25b719c3662f22135"
   strings:
      $s1 = "363<3S3c3l3q3v3{3" fullword ascii
      $s2 = "3!3%3)3-3135393@5" fullword ascii

      /* Recommendation - verify the opcodes on Binarly : http://www.binar.ly */
      /* Test each of them in the search field & reduce length until it generates matches */
      $op0 = { eb 03 89 46 54 47 83 ff 1a 0f 8c 40 ff ff ff 8b }
      $op1 = { 8b 46 04 85 c0 74 0f 50 e8 34 fb ff ff 83 66 04 }
      $op2 = { c6 45 fc 02 8d 8d 44 ff ff ff e8 d2 2f 00 00 eb }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) or all of ($op*) ) )
}

rule EquationGroup_Toolset_Apr17_SlDecoder {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b220f51ca56d9f9d7d899fa240d3328535f48184d136013fd808d8835919f9ce"
   strings:
      $x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
      $x2 = "KeyLogger_Data" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Windows_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "d38ce396926e45781daecd18670316defe3caf975a3062470a87c1d181a61374"
   strings:
      $s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_msgkd_msslu64_msgki_mssld {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9ab667b7b5b9adf4ff1d6db6f804824a22c7cc003eb4208d5b2f12809f5e69d0"
      hash2 = "320144a7842500a5b69ec16f81a9d1d4c8172bb92301afd07fb79bc0eca81557"
      hash3 = "c10f4b9abee0fde50fe7c21b9948a2532744a53bb4c578630a81d2911f6105a3"
      hash4 = "551174b9791fc5c1c6e379dac6110d0aba7277b450c2563e34581565609bc88e"
      hash5 = "8419866c9058d738ebc1a18567fef52a3f12c47270f2e003b3e1242d86d62a46"
   strings:
      $s1 = "PQRAPAQSTUVWARASATAUAVAW" fullword ascii
      $s2 = "SQRUWVAWAVAUATASARAQAP" fullword ascii
      $s3 = "iijymqp" fullword ascii
      $s4 = "AWAVAUATASARAQI" fullword ascii
      $s5 = "WARASATAUAVM" fullword ascii

      $op1 = { 0c 80 30 02 48 83 c2 01 49 83 e9 01 75 e1 c3 cc }
      $op2 = { e8 10 66 0d 00 80 66 31 02 48 83 c2 02 49 83 e9 }
      $op3 = { 48 b8 53 a5 e1 41 d4 f1 07 00 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of ($s*) or all of ($op*) )
}

rule EquationGroup_Toolset_Apr17_DoubleFeatureDll_dll_3 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "515374423b8b132258bd91acf6f29168dcc267a3f45ecb9d1fe18ee3a253195b"
   strings:
      $a = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $b = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $c = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetCallback {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
   strings:
      $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
      $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17__DoubleFeatureReader_DoubleFeatureReader_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "052e778c26120c683ee2d9f93677d9217e9d6c61ffc0ab19202314ab865e3927"
      hash2 = "5db457e7c7dba80383b1df0c86e94dc6859d45e1d188c576f2ba5edee139d9ae"
   strings:
      $x1 = "DFReader.exe logfile AESKey [-j] [-o outputfilename]" fullword ascii
      $x2 = "Double Feature Target Version" fullword ascii
      $x3 = "DoubleFeature Process ID" fullword ascii

      $op1 = { a1 30 21 41 00 89 85 d8 fc ff ff a1 34 21 41 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_Toolset_Apr17__vtuner_vtuner_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3e6bec0679c1d8800b181f3228669704adb2e9cbf24679f4a1958e4cdd0e1431"
      hash2 = "b0d2ebf455092f9d1f8e2997237b292856e9abbccfbbebe5d06b382257942e0e"
   strings:
      $s1 = "Unable to get -w hash.  %x" fullword wide
      $s2 = "!\"invalid instruction mnemonic constant Id3vil\"" fullword wide
      $s4 = "Unable to set -w provider. %x" fullword wide

      $op0 = { 2b c7 50 e8 3a 8c ff ff ff b6 c0 }
      $op2 = { a1 8c 62 47 00 81 65 e0 ff ff ff 7f 03 d8 8b c1 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17__ecwi_ESKE_EVFR_RPC2_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
   strings:
      $s1 = "Target is share name" fullword ascii
      $s2 = "Could not make UdpNetbios header -- bailing" fullword ascii
      $s3 = "Request non-NT session key" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17__EAFU_ecwi_ESKE_EVFR_RPC2_4 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3e181ca31f1f75a6244b8e72afaa630171f182fbe907df4f8b656cc4a31602f6"
      hash2 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash3 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash4 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash5 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
   strings:
      $x1 = "* Listening Post DLL %s() returned error code %d." fullword ascii

      $s1 = "WsaErrorTooManyProcesses" fullword ascii
      $s2 = "NtErrorMoreProcessingRequired" fullword ascii
      $s3 = "Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s4 = "ServerErrorBadNamePassword" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or 1 of ($x*) )
}

rule EquationGroup_Toolset_Apr17__SendCFTrigger_SendPKTrigger_6 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3bee31b9edca8aa010a4684c2806b0ca988b2bcc14ad0964fec4f11f3f6fb748"
      hash2 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
   strings:
      $s4 = "* Failed to connect to destination - %u" fullword wide
      $s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__AddResource {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "e83e4648875d4c4aa8bc6f3c150c12bad45d066e2116087cdf78a4a4efbab6f0"
      hash2 = "5a04d65a61ef04f5a1cbc29398c767eada367459dc09c54c3f4e35015c71ccff"
   strings:
      $s1 = "%s cm 10 2000 \"c:\\MY DIR\\myapp.exe\" c:\\MyResourceData.dat" fullword ascii
      $s2 = "<PE path> - the path to the PE binary to which to add the resource." fullword ascii
      $s3 = "Unable to get path for target binary." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17__ESKE_RPC2_8 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash2 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
   strings:
      $s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
      $s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__LSADUMP_Lp_ModifyPrivilege_Lp_PacketScan_Lp_put_Lp_RemoteExecute_Lp_Windows_Lp_wmi_Lp_9 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
      hash2 = "d92928a867a685274b0a74ec55c0b83690fca989699310179e184e2787d47f48"
      hash3 = "2d963529e6db733c5b74db1894d75493507e6e40da0de2f33e301959b50f3d32"
      hash4 = "e9f6a84899c9a042edbbff391ca076169da1a6f6dfb61b927942fe4be3327749"
      hash5 = "d989d610b032c72252a2df284d0b53f63f382e305de2a18b453a0510ab6246a3"
      hash6 = "23d98bca1f6e2f6989d53c2f2adff996ede2c961ea189744f8ae65621003b8b1"
      hash7 = "d7ae24816fda190feda6a60639cf3716ea00fb63a4bd1069b8ce52d10ad8bc7f"
   strings:
      $x1 = "Injection Lib -  " wide
      $x2 = "LSADUMP - - ERROR" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ETBL_ETRE_10 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
   strings:
      $x1 = "Probe #2 usage: %s -i TargetIp -p TargetPort -r %d [-o TimeOut] -t Protocol -n IMailUserName -a IMailPassword" fullword ascii
      $x6 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER : 0x%08X" fullword ascii
      $s19 = "Sending Implant Payload.. cEncImplantPayload size(%d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_ETBL_ETRE_EVFR_11 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash4 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
      hash5 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
   strings:
      $x1 = "Target is vulnerable" fullword ascii
      $x2 = "Target is NOT vulnerable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_RideArea2_12 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash4 = "e702223ab42c54fff96f198611d0b2e8a1ceba40586d466ba9aadfa2fd34386e"
   strings:
      $x2 = "** CreatePayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_13 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
   strings:
      $x1 = "Skip call to PackageRideArea().  Payload has already been packaged. Options -x and -q ignored." fullword ascii
      $s2 = "ERROR: pGvars->pIntRideAreaImplantPayload is NULL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__NameProbe_SMBTOUCH_14 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "fbe3a4501654438f502a93f51b298ff3abf4e4cad34ce4ec0fad5cb5c2071597"
      hash2 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
   strings:
      $s1 = "DEC Pathworks TCPIP service on Windows NT" fullword ascii
      $s2 = "<\\\\__MSBROWSE__> G" fullword ascii
      $s3 = "<IRISNAMESERVER>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_RPC2_15 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
   strings:
      $x1 = "** SendAndReceive ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
      $s8 = "Binding to RPC Interface %s over named pipe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_16 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
   strings:
      $x1 = "ERROR: TbMalloc() failed for encoded exploit payload" fullword ascii
      $x2 = "** EncodeExploitPayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
      $x4 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
      $s6 = "Sending Implant Payload (%d-bytes)" fullword ascii
      $s7 = "ERROR: Encoder failed on exploit payload" fullword ascii
      $s11 = "ERROR: VulnerableOS() != RET_SUCCESS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ETBL_ETRE_SMBTOUCH_17 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
      hash3 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
   strings:
      $x1 = "ERROR: Connection terminated by Target (TCP Ack/Fin)" fullword ascii
      $s2 = "Target did not respond within specified amount of time" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-17
   Identifier: Equation Group Tool Output
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_scanner_output {
   meta:
      description = "Detects output generated by EQGRP scanner.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-17"
   strings:
      $s1 = "# Scan for windows boxes" ascii fullword
      $s2 = "Going into send" ascii fullword
      $s3 = "# Does not work" ascii fullword
      $s4 = "You are the weakest link, goodbye" ascii fullword
      $s5 = "rpc   Scan for RPC  folks" ascii fullword
   condition:
      filesize < 1000KB and 2 of them
}

/* Equation APT ------------------------------------------------------------ */

rule apt_equation_exploitlib_mutexes
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect Equation group's Exploitation library http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
        $mz="MZ"
        $a1="prkMtx" wide
        $a2="cnFormSyncExFBC" wide
        $a3="cnFormVoidFBC" wide
        $a4="cnFormSyncExFBC"
        $a5="cnFormVoidFBC"

    condition:
        (($mz at 0) and any of ($a*))
}

rule apt_equation_doublefantasy_genericresource
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"

    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}

rule apt_equation_equationlaser_runtimeclasses
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect the EquationLaser malware"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "https://securelist.com/blog/"

    strings:
        $a1="?a73957838_2@@YAXXZ"
        $a2="?a84884@@YAXXZ"
        $a3="?b823838_9839@@YAXXZ"
        $a4="?e747383_94@@YAXXZ"
        $a5="?e83834@@YAXXZ"
        $a6="?e929348_827@@YAXXZ"

    condition:
        any of them
}

rule apt_equation_cryptotable
{

    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect the crypto library used in Equation group malware"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "https://securelist.com/blog/"

    strings:
        $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}

    condition:
        $a
}

/* Equation Group - Kaspersky ---------------------------------------------- */

rule Equation_Kaspersky_TripleFantasy_1
{

    meta:
        description = "Equation Group Malware - TripleFantasy http://goo.gl/ivt8EW"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "b2b2cd9ca6f5864ef2ac6382b7b6374a9fb2cbe9"

    strings:
        $mz = { 4d 5a }
        $s0 = "%SystemRoot%\\system32\\hnetcfg.dll" fullword wide
        $s1 = "%WINDIR%\\System32\\ahlhcib.dll" fullword wide
        $s2 = "%WINDIR%\\sjyntmv.dat" fullword wide
        $s3 = "Global\\{8c38e4f3-591f-91cf-06a6-67b84d8a0102}" fullword wide
        $s4 = "%WINDIR%\\System32\\owrwbsdi" fullword wide
        $s5 = "Chrome" fullword wide
        $s6 = "StringIndex" fullword ascii
        $x1 = "itemagic.net@443" fullword wide
        $x2 = "team4heat.net@443" fullword wide
        $x5 = "62.216.152.69@443" fullword wide
        $x6 = "84.233.205.37@443" fullword wide
        $z1 = "www.microsoft.com@80" fullword wide
        $z2 = "www.google.com@80" fullword wide
        $z3 = "127.0.0.1:3128" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 300000 and (( all of ($s*) and all of ($z*) ) or ( all of ($s*) and 1 of ($x*) ))
}

rule Equation_Kaspersky_DoubleFantasy_1
{

    meta:
        description = "Equation Group Malware - DoubleFantasy"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "d09b4b6d3244ac382049736ca98d7de0c6787fa2"

    strings:
        $mz = { 4d 5a }
        $z1 = "msvcp5%d.dll" fullword ascii
        $s0 = "actxprxy.GetProxyDllInfo" fullword ascii
        $s3 = "actxprxy.DllGetClassObject" fullword ascii
        $s5 = "actxprxy.DllRegisterServer" fullword ascii
        $s6 = "actxprxy.DllUnregisterServer" fullword ascii
        $x1 = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" ascii
        $x2 = "191H1a1" fullword ascii
        $x3 = "November " fullword ascii
        $x4 = "abababababab" fullword ascii
        $x5 = "January " fullword ascii
        $x6 = "October " fullword ascii
        $x7 = "September " fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 350000 and (( $z1 ) or ( all of ($s*) and 6 of ($x*) ))
}

rule Equation_Kaspersky_GROK_Keylogger
{

    meta:
        description = "Equation Group Malware - GROK keylogger"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "50b8f125ed33233a545a1aac3c9d4bb6aa34b48f"

    strings:
        $mz = { 4d 5a }
        $s0 = "c:\\users\\rmgree5\\" ascii
        $s1 = "msrtdv.sys" fullword wide
        $x1 = "svrg.pdb" fullword ascii
        $x2 = "W32pServiceTable" fullword ascii
        $x3 = "In forma" fullword ascii
        $x4 = "ReleaseF" fullword ascii
        $x5 = "criptor" fullword ascii
        $x6 = "astMutex" fullword ascii
        $x7 = "ARASATAU" fullword ascii
        $x8 = "R0omp4ar" fullword ascii
        $z1 = "H.text" fullword ascii
        $z2 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $z4 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Environment" wide fullword

    condition:
        ( $mz at 0 ) and filesize < 250000 and ($s0 or ( $s1 and 6 of ($x*) ) or ( 6 of ($x*) and all of ($z*) ))
}

rule Equation_Kaspersky_GreyFishInstaller
{

    meta:
        description = "Equation Group Malware - Grey Fish"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"

    strings:
        $s0 = "DOGROUND.exe" fullword wide
        $s1 = "Windows Configuration Services" fullword wide
        $s2 = "GetMappedFilenameW" fullword ascii

    condition:
        all of them
}

rule Equation_Kaspersky_EquationDrugInstaller
{

    meta:
        description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "61fab1b8451275c7fd580895d9c68e152ff46417"

    strings:
        $mz = { 4d 5a }

        $s0 = "\\system32\\win32k.sys" fullword wide
        $s1 = "ALL_FIREWALLS" fullword ascii
        $x1 = "@prkMtx" fullword wide
        $x2 = "STATIC" fullword wide
        $x3 = "windir" fullword wide
        $x4 = "cnFormVoidFBC" fullword wide
        $x5 = "CcnFormSyncExFBC" fullword wide
        $x6 = "WinStaObj" fullword wide
        $x7 = "BINRES" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*) and 5 of ($x*)
}

rule Equation_Kaspersky_EquationLaserInstaller
{

    meta:
        description = "Equation Group Malware - EquationLaser Installer"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "5e1f56c1e57fbff96d4999db1fd6dd0f7d8221df"

    strings:
        $mz = { 4d 5a }
        $s0 = "Failed to get Windows version" fullword ascii
        $s1 = "lsasrv32.dll and lsass.exe" fullword wide
        $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
        $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
        $s4 = "lsasrv32.dll" fullword ascii
        $s5 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" fullword ascii
        $s6 = "%s %02x %s" fullword ascii
        $s7 = "VIEWERS" fullword ascii
        $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 250000 and 6 of ($s*)
}

rule Equation_Kaspersky_FannyWorm
{

    meta:
        description = "Equation Group Malware - Fanny Worm"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"

    strings:
        $mz = { 4d 5a }
        $s1 = "x:\\fanny.bmp" fullword ascii
        $s2 = "32.exe" fullword ascii
        $s3 = "d:\\fanny.bmp" fullword ascii
        $x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
        $x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
        $x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
        $x4 = "\\system32\\win32k.sys" fullword wide
        $x5 = "\\AGENTCPD.DLL" fullword ascii
        $x6 = "agentcpd.dll" fullword ascii
        $x7 = "PADupdate.exe" fullword ascii
        $x8 = "dll_installer.dll" fullword ascii
        $x9 = "\\restore\\" fullword ascii
        $x10 = "Q:\\__?__.lnk" fullword ascii
        $x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
        $x12 = "\\shelldoc.dll" fullword ascii
        $x13 = "file size = %d bytes" fullword ascii
        $x14 = "\\MSAgent" fullword ascii
        $x15 = "Global\\RPCMutex" fullword ascii
        $x16 = "Global\\DirectMarketing" fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 300000 and (( 2 of ($s*) ) or ( 1 of ($s*) and 6 of ($x*) ) or ( 14 of ($x*)))
}

rule Equation_Kaspersky_HDD_reprogramming_module 
{

    meta:
        description = "Equation Group Malware - HDD reprogramming module"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
    
    strings:
        $mz = { 4d 5a }
        $s0 = "nls_933w.dll" fullword ascii
        $s1 = "BINARY" fullword wide
        $s2 = "KfAcquireSpinLock" fullword ascii
        $s3 = "HAL.dll" fullword ascii
        $s4 = "READ_REGISTER_UCHAR" fullword ascii
    condition:
        ( $mz at 0 ) and filesize < 300000 and all of ($s*)
}

rule Equation_Kaspersky_EOP_Package 
{

    meta:
        description = "Equation Group Malware - EoP package and malware launcher"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"

    strings:
        $mz = { 4d 5a }
        $s0 = "abababababab" fullword ascii
        $s1 = "abcdefghijklmnopq" fullword ascii
        $s2 = "@STATIC" fullword wide
        $s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
        $s4 = "@prkMtx" fullword wide
        $s5 = "prkMtx" fullword wide
        $s6 = "cnFormVoidFBC" fullword wide

    condition:
        ( $mz at 0 ) and filesize < 100000 and all of ($s*)
}

rule Equation_Kaspersky_TripleFantasy_Loader 
{

    meta:
        description = "Equation Group Malware - TripleFantasy Loader"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/16"
        hash = "4ce6e77a11b443cc7cbe439b71bf39a39d3d7fa3"
    
    strings:
        $mz = { 4d 5a }
        $x1 = "Original Innovations, LLC" fullword wide
        $x2 = "Moniter Resource Protocol" fullword wide
        $x3 = "ahlhcib.dll" fullword wide
        $s0 = "hnetcfg.HNetGetSharingServicesPage" fullword ascii
        $s1 = "hnetcfg.IcfGetOperationalMode" fullword ascii
        $s2 = "hnetcfg.IcfGetDynamicFwPorts" fullword ascii
        $s3 = "hnetcfg.HNetFreeFirewallLoggingSettings" fullword ascii
        $s4 = "hnetcfg.HNetGetShareAndBridgeSettings" fullword ascii
        $s5 = "hnetcfg.HNetGetFirewallSettingsPage" fullword ascii
    
    condition:
        ( $mz at 0 ) and filesize < 50000 and ( all of ($x*) and all of ($s*) )
}

/* Rule generated from the mentioned keywords */

rule Equation_Kaspersky_SuspiciousString 
{
  
    meta:
        description = "Equation Group Malware - suspicious string found in sample"
        author = "Florian Roth"
        reference = "http://goo.gl/ivt8EW"
        date = "2015/02/17"
        score = 60
   
    strings:
        $mz = { 4d 5a }
        $s1 = "i386\\DesertWinterDriver.pdb" fullword
        $s2 = "Performing UR-specific post-install..."
        $s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
        $s4 = "STRAITSHOOTER30.exe"
        $s5 = "standalonegrok_2.1.1.1"
        $s6 = "c:\\users\\rmgree5\\"
    
    condition:
        ( $mz at 0 ) and filesize < 500000 and all of ($s*)
}

/* EquationDrug Update 11.03.2015 - http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ */

rule EquationDrug_NetworkSniffer1
{

    meta:
        description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "sys\\mstcp32.dbg" fullword ascii
        $s7 = "mstcp32.sys" fullword wide
        $s8 = "p32.sys" fullword ascii
        $s9 = "\\Device\\%ws_%ws" fullword wide
        $s10 = "\\DosDevices\\%ws" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
    
    condition:
        all of them
}

rule EquationDrug_CompatLayer_UnilayDLL 
{

    meta:
        description = "EquationDrug - Unilay.DLL"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "a3a31937956f161beba8acac35b96cb74241cd0f"

    strings:
        $mz = { 4d 5a }
        $s0 = "unilay.dll" fullword ascii

    condition:
        ( $mz at 0 ) and $s0
}

rule EquationDrug_HDDSSD_Op 
{

    meta:
        description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"

    strings:
        $s0 = "nls_933w.dll" fullword ascii

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer2 
{

    meta:
        description = "EquationDrug - Network Sniffer - tdip.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "sys\\tdip.dbg" fullword ascii
        $s4 = "dip.sys" fullword ascii
        $s5 = "\\Device\\%ws_%ws" fullword wide
        $s6 = "\\DosDevices\\%ws" fullword wide
        $s7 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer3 
{

    meta:
        description = "EquationDrug - Network Sniffer - tdip.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "14599516381a9646cd978cf962c4f92386371040"

    strings:
        $s0 = "Corporation. All rights reserved." fullword wide
        $s1 = "IP Transport Driver" fullword wide
        $s2 = "tdip.sys" fullword wide
        $s3 = "tdip.pdb" fullword ascii

    condition:
        all of them
}

rule EquationDrug_VolRec_Driver 
{

    meta:
        description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"

    strings:
        $s0 = "msrstd.sys" fullword wide
        $s1 = "msrstd.pdb" fullword ascii
        $s2 = "msrstd driver" fullword wide

    condition:
        all of them
}

rule EquationDrug_KernelRootkit 
{

    meta:
        description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "Parmsndsrv.dbg" fullword ascii
        $s2 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s3 = "msndsrv.sys" fullword wide
        $s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" fullword wide
        $s6 = "\\Device\\%ws_%ws" fullword wide
        $s7 = "\\DosDevices\\%ws" fullword wide
        $s9 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_Keylogger 
{

    meta:
        description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"

    strings:
        $s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
        $s3 = "\\DosDevices\\Gk" fullword wide
        $s5 = "\\Device\\Gk0" fullword wide

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer4 
{

    meta:
        description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"

    strings:
        $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
        $s1 = "\\systemroot\\" fullword ascii
        $s2 = "RAVISENT Technologies Inc." fullword wide
        $s3 = "Created by VIONA Development" fullword wide
        $s4 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s5 = "\\device\\harddiskvolume" fullword wide
        $s7 = "ATMDKDRV.SYS" fullword wide
        $s8 = "\\Device\\%ws_%ws" fullword wide
        $s9 = "\\DosDevices\\%ws" fullword wide
        $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
        $s11 = "\\Device\\%ws" fullword wide
        $s13 = "CineMaster C 1.1 WDM" fullword wide

    condition:
        all of them
}

rule EquationDrug_PlatformOrchestrator 
{

    meta:
        description = "EquationDrug - Platform orchestrator - mscfg32.dll, svchost32.dll"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "febc4f30786db7804008dc9bc1cebdc26993e240"

    strings:
        $s0 = "SERVICES.EXE" fullword wide
        $s1 = "\\command.com" fullword wide
        $s2 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s3 = "LSASS.EXE" fullword wide
        $s4 = "Windows Configuration Services" fullword wide
        $s8 = "unilay.dll" fullword ascii

    condition:
        all of them
}

rule EquationDrug_NetworkSniffer5 
{

    meta:
        description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "09399b9bd600d4516db37307a457bc55eedcbd17"

    strings:
        $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
        $s1 = "\\Registry\\User\\CurrentUser\\" fullword wide
        $s2 = "atmdkdrv.sys" fullword wide
        $s4 = "\\Device\\%ws_%ws" fullword wide
        $s5 = "\\DosDevices\\%ws" fullword wide
        $s6 = "\\Device\\%ws" fullword wide

    condition:
        all of them
}

rule EquationDrug_FileSystem_Filter 
{

    meta:
        description = "EquationDrug - Filesystem filter driver – volrec.sys, scsi2mgr.sys"
        author = "Florian Roth @4nc4p"
        reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
        date = "2015/03/11"
        hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"

    strings:
        $s0 = "volrec.sys" fullword wide
        $s1 = "volrec.pdb" fullword ascii
        $s2 = "Volume recognizer driver" fullword wide

    condition:
        all of them
}

rule apt_equation_keyword 
{

    meta:
        description = "Rule to detect Equation group's keyword in executable file"
        author = "Florian Roth @4nc4p"
        last_modified = "2015-09-26"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"

    strings:
         $a1 = "Backsnarf_AB25" wide
         $a2 = "Backsnarf_AB25" ascii

    condition:
         uint16(0) == 0x5a4d and 1 of ($a*)
}



rule EQGRP_noclient_3_0_5 
{
    meta:
        description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $x1 = "-C %s 127.0.0.1\" scripme -F -t JACKPOPIN4 '&" fullword ascii
        $x2 = "Command too long!  What the HELL are you trying to do to me?!?!  Try one smaller than %d bozo." fullword ascii
        $x3 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
        $x4 = "Error from ourtn, did not find keys=target in tn.spayed" fullword ascii
        $x5 = "ourtn -d -D %s -W 127.0.0.1:%d  -i %s -p %d %s %s" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 700KB and 1 of them ) or ( all of them )
}

rule EQGRP_installdate 
{

    meta:
        description = "Detects tool from EQGRP toolset - file installdate.pl"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
        $x2 = "print \"Gimme hex: \";" fullword ascii
        $x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii
        $s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
        $s2 = "if (not($cmdInput)) {" fullword ascii
        $s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii

    condition:
        filesize < 2KB and ( 1 of ($x*) or 3 of them )
}

rule EQGRP_teflondoor 
{

    meta:
        description = "Detects tool from EQGRP toolset - file teflondoor.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
        $x2 = "%s: %li b (%li%%)" fullword ascii
        $s1 = "no winsock" fullword ascii
        $s2 = "%s: %s file '%s'" fullword ascii
        $s3 = "peer: connect" fullword ascii
        $s4 = "read: write" fullword ascii
        $s5 = "%s: done!" fullword ascii
        $s6 = "%s: %li b" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) and 3 of them
}

rule EQGRP_durablenapkin_solaris_2_0_1 
{

    meta:
        description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
        $s2 = "send_request: putmsg \"%s\": %s" fullword ascii
        $s3 = "port undefined" fullword ascii
        $s4 = "recv_ack: %s getmsg: %s" fullword ascii
        $s5 = ">> %d -- %d" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and 2 of them )
}

rule EQGRP_teflonhandle 
{

    meta:
        description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
        $s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
        $s3 = "Random Key : 0x" fullword ascii
        $s4 = "done (%i bytes written)." fullword ascii
        $s5 = "%s --> %s..." fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 20KB and 2 of them
}

rule EQGRP_false 
{

    meta:
        description = "Detects tool from EQGRP toolset - file false.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
            00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
            2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
            0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
            0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
            00 25 64 20 2D 20 25 64 }

    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and $s1
}

rule EQGRP_bc_genpkt 
{

    meta:
        description = "Detects tool from EQGRP toolset - file bc-genpkt"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $x1 = "load auxiliary object=%s requested by file=%s" fullword ascii
        $x2 = "size of new packet, should be %d <= size <= %d bytes" fullword ascii
        $x3 = "verbosity - show lengths, packet dumps, etc" fullword ascii
        $s1 = "%s: error while loading shared libraries: %s%s%s%s%s" fullword ascii
        $s2 = "cannot dynamically load executable" fullword ascii
        $s3 = "binding file %s to %s: %s symbol `%s' [%s]" fullword ascii
        $s4 = "randomize the initiator cookie" fullword ascii
    
    condition:
        uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($s*) and 3 of them )
}

rule EQGRP_dn_1_0_2_1 
{

    meta:
        description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
        $s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
        $s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
        $s4 = "Not everything is set yet" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 30KB and 2 of them )
}

rule EQGRP_morel 
{

    meta:
        description = "Detects tool from EQGRP toolset - file morel.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"
        hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"

    strings:
        $s1 = "%d - %d, %d" fullword ascii
        $s2 = "%d - %lu.%lu %d.%lu" fullword ascii
        $s3 = "%d - %d %d" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}

rule EQGRP_bc_parser 
{

    meta:
        description = "Detects tool from EQGRP toolset - file bc-parser"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"
        hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"

    strings:
        $s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
        $s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii

    condition:
        uint16(0) == 0x457f and 1 of them
}

rule EQGRP_1212 
{

    meta:
        description = "Detects tool from EQGRP toolset - file 1212.pl"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
        $s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
        $s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
        $s4 = "$dstport=hextoPort($dstport);" fullword ascii
        $s5 = "sub hextoPort" fullword ascii
        $s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii

    condition:
        filesize < 6KB and 4 of them
}

rule EQGRP_1212_dehex 
{

    meta:
        description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-15"

    strings:
        $s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
        $s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
        $s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
        $s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
        $s5 = "print hextoIP($ARGV[0]);" fullword ascii

    condition:
        ( uint16(0) == 0x2123 and filesize < 6KB and ( 5 of ($s*) ) ) or ( all of them )
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-08-16
    Identifier: EQGRP
*/

/* Rule Set ----------------------------------------------------------------- */

rule install_get_persistent_filenames 
{

    meta:
        description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"

    strings:
        $s1 = "Generates the persistence file name and prints it out." fullword ascii

    condition:
        ( uint16(0) == 0x457f and all of them )
}

rule EQGRP_create_dns_injection
{

    meta:
        description = "EQGRP Toolset Firewall - file create_dns_injection.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"

    strings:
        $s1 = "Name:   A hostname: 'host.network.com', a decimal numeric offset within" fullword ascii
        $s2 = "-a www.badguy.net,CNAME,1800,host.badguy.net \\\\" fullword ascii

    condition:
        1 of them
}

rule EQGRP_screamingplow 
{

    meta:
        description = "EQGRP Toolset Firewall - file screamingplow.sh"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"

    strings:
        $s1 = "What is the name of your PBD:" fullword ascii
        $s2 = "You are now ready for a ScreamPlow" fullword ascii

    condition:
        1 of them
}

rule EQGRP_MixText 
{

    meta:
        description = "EQGRP Toolset Firewall - file MixText.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"

    strings:
        $s1 = "BinStore enabled implants." fullword ascii

    condition:
        1 of them
}

rule EQGRP_tunnel_state_reader 
{

    meta:
        description = "EQGRP Toolset Firewall - file tunnel_state_reader"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"

    strings:
        $s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
        $s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii

    condition:
        1 of them
}

rule EQGRP_payload 
{

    meta:
        description = "EQGRP Toolset Firewall - file payload.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"

    strings:
        $s1 = "can't find target version module!" fullword ascii
        $s2 = "class Payload:" fullword ascii

    condition:
        all of them
}

rule EQGRP_eligiblecandidate 
{

    meta:
        description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"

    strings:
        $o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
        $o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii
        $c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
        $c2 = "self.build_exploit_payload(cmd)" fullword ascii

    condition:
        1 of them
}

rule EQGRP_BUSURPER_2211_724 
{

    meta:
        description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"

    strings:
        $s1 = ".got_loader" fullword ascii
        $s2 = "_start_text" fullword ascii
        $s3 = "IMPLANT" fullword ascii
        $s4 = "KEEPGOING" fullword ascii
        $s5 = "upgrade_implant" fullword ascii

    condition:
        all of them
}

rule EQGRP_networkProfiler_orderScans 
{

    meta:
        description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"

    strings:
        $x1 = "Unable to save off predefinedScans directory" fullword ascii
        $x2 = "Re-orders the networkProfiler scans so they show up in order in the LP" fullword ascii

    condition:
        1 of them
}

rule EQGRP_epicbanana_2_1_0_1 
{

    meta:
        description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"

    strings:
        $s1 = "failed to create version-specific payload" fullword ascii
        $s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii

    condition:
        1 of them
}

rule EQGRP_sniffer_xml2pcap 
{

    meta:
        description = "EQGRP Toolset Firewall - file sniffer_xml2pcap"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "f5e5d75cfcd86e5c94b0e6f21bbac886c7e540698b1556d88a83cc58165b8e42"

    strings:
        $x1 = "-s/--srcip <sourceIP>  Use given source IP (if sniffer doesn't collect source IP)" fullword ascii
        $x2 = "convert an XML file generated by the BLATSTING sniffer module into a pcap capture file." fullword ascii

    condition:
        1 of them
}

rule EQGRP_BananaAid 
{

    meta:
        description = "EQGRP Toolset Firewall - file BananaAid"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"

    strings:
        $x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
        $x2 = "scp BGLEE-" ascii
        $x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
        $x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii

    condition:
        1 of them
}

rule EQGRP_bo 
{

    meta:
        description = "EQGRP Toolset Firewall - file bo"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"

    strings:
        $s1 = "ERROR: failed to open %s: %d" fullword ascii
        $s2 = "__libc_start_main@@GLIBC_2.0" fullword ascii
        $s3 = "serial number: %s" fullword ascii
        $s4 = "strerror@@GLIBC_2.0" fullword ascii
        $s5 = "ERROR: mmap failed: %d" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 20KB and all of them )
}

rule EQGRP_SecondDate_2211 
{

    meta:
        description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"

    strings:
        $s1 = "SD_processControlPacket" fullword ascii
        $s2 = "Encryption_rc4SetKey" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EQGRP_config_jp1_UA 
{

    meta:
        description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"

    strings:
        $x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
        $x2 = "Error running config_implant." fullword ascii
        $x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
        $x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii

    condition:
        1 of them
}

rule EQGRP_userscript 
{

    meta:
        description = "EQGRP Toolset Firewall - file userscript.FW"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"

    strings:
        $x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii

    condition:
        1 of them
}

rule EQGRP_BBALL_M50FW08_2201 
{

    meta:
        description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"

    strings:
        $s1 = ".got_loader" fullword ascii
        $s2 = "LOADED" fullword ascii
        $s3 = "pageTable.c" fullword ascii
        $s4 = "_start_text" fullword ascii
        $s5 = "handler_readBIOS" fullword ascii
        $s6 = "KEEPGOING" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and 5 of ($s*) )
}

rule EQGRP_BUSURPER_3001_724 
{

    meta:
        description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"

    strings:
        $s1 = "IMPLANT" fullword ascii
        $s2 = "KEEPGOING" fullword ascii
        $s3 = "upgrade_implant" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}

rule EQGRP_workit 
{

    meta:
        description = "EQGRP Toolset Firewall - file workit.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"

    strings:
        $s1 = "macdef init > /tmp/.netrc;" fullword ascii
        $s2 = "/usr/bin/wget http://" fullword ascii
        $s3 = "HOME=/tmp ftp" fullword ascii
        $s4 = " >> /tmp/.netrc;" fullword ascii
        $s5 = "/usr/rapidstream/bin/tftp" fullword ascii
        $s6 = "created shell_command:" fullword ascii
        $s7 = "rm -f /tmp/.netrc;" fullword ascii
        $s8 = "echo quit >> /tmp/.netrc;" fullword ascii
        $s9 = "echo binary >> /tmp/.netrc;" fullword ascii
        $s10 = "chmod 600 /tmp/.netrc;" fullword ascii
        $s11 = "created cli_command:" fullword ascii
   
    condition:
        6 of them
}

rule EQGRP_tinyhttp_setup 
{

    meta:
        description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"
    
    strings:
        $x1 = "firefox http://127.0.0.1:8000/$_name" fullword ascii
        $x2 = "What is the name of your implant:" fullword ascii /* it's called conscience */
        $x3 = "killall thttpd" fullword ascii
        $x4 = "copy http://<IP>:80/$_name flash:/$_name" fullword ascii
    
    condition:
        ( uint16(0) == 0x2123 and filesize < 2KB and 1 of ($x*) ) or ( all of them )
}

rule EQGRP_shellcode 
{

    meta:
        description = "EQGRP Toolset Firewall - file shellcode.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "ac9decb971dd44127a6ca0d35ac153951f0735bb4df422733046098eca8f8b7f"

    strings:
        $s1 = "execute_post = '\\xe8\\x00\\x00\\x00\\x00\\x5d\\xbe\\xef\\xbe\\xad\\xde\\x89\\xf7\\x89\\xec\\x29\\xf4\\xb8\\x03\\x00\\x00\\x00" ascii
        $s2 = "tiny_exec = '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00\\x01\\x00\\x00" ascii
        $s3 = "auth_id = '\\x31\\xc0\\xb0\\x03\\x31\\xdb\\x89\\xe1\\x31\\xd2\\xb6\\xf0\\xb2\\x0d\\xcd\\x80\\x3d\\xff\\xff\\xff\\xff\\x75\\x07" ascii

        $c1 = { e8 00 00 00 00 5d be ef be ad de 89 f7 89 ec 29 f4 b8 03 00 00 00 }
        /* $c2 = { 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 02 00 03 00 01 00 00 }  too many fps */
        $c3 = { 31 c0 b0 03 31 db 89 e1 31 d2 b6 f0 b2 0d cd 80 3d ff ff ff ff 75 07 }

    condition:
        1 of them
}

rule EQGRP_EPBA 
{

    meta:
        description = "EQGRP Toolset Firewall - file EPBA.script"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"

    strings:
        $x1 = "./epicbanana_2.0.0.1.py -t 127.0.0.1 --proto=ssh --username=cisco --password=cisco --target_vers=asa804 --mem=NA -p 22 " fullword ascii
        $x2 = "-t TARGET_IP, --target_ip=TARGET_IP -- Either 127.0.0.1 or Win Ops IP" fullword ascii
        $x3 = "./bride-1100 --lp 127.0.0.1 --implant 127.0.0.1 --sport RHP --dport RHP" fullword ascii
        $x4 = "--target_vers=TARGET_VERS    target Pix version (pix712, asa804) (REQUIRED)" fullword ascii
        $x5 = "-p DEST_PORT, --dest_port=DEST_PORT defaults: telnet=23, ssh=22 (optional) - Change to LOCAL redirect port" fullword ascii
        $x6 = "this operation is complete, BananaGlee will" fullword ascii
        $x7 = "cd /current/bin/FW/BGXXXX/Install/LP" fullword ascii

    condition:
        ( uint16(0) == 0x2023 and filesize < 7KB and 1 of ($x*) ) or ( 3 of them )
}

rule EQGRP_BPIE 
{
    meta:
        description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"

    strings:
        $s1 = "profProcessPacket" fullword ascii
        $s2 = ".got_loader" fullword ascii
        $s3 = "getTimeSlotCmdHandler" fullword ascii
        $s4 = "getIpIpCmdHandler" fullword ascii
        $s5 = "LOADED" fullword ascii
        $s6 = "profStartScan" fullword ascii
        $s7 = "tmpData.1" fullword ascii
        $s8 = "resetCmdHandler" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 70KB and 6 of ($s*) )
}

rule EQGRP_jetplow_SH 
{

    meta:
        description = "EQGRP Toolset Firewall - file jetplow.sh"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"

    strings:
        $s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
        $s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
        $s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
        $s4 = "*****             Welcome to JetPlow              *****" fullword ascii

    condition:
        1 of them
}

rule EQGRP_BBANJO 
{

    meta:
        description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"

    strings:
        $s1 = "get_lsl_interfaces" fullword ascii
        $s2 = "encryptFC4Payload" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "beacon_getconfig" fullword ascii
        $s5 = "LOADED" fullword ascii
        $s6 = "FormBeaconPacket" fullword ascii
        $s7 = "beacon_reconfigure" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 50KB and all of them )
}

rule EQGRP_BPATROL_2201 
{

    meta:
        description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"

    strings:
        $s1 = "dumpConfig" fullword ascii
        $s2 = "getstatusHandler" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "xtractdata" fullword ascii
        $s5 = "KEEPGOING" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and all of them )
}

rule EQGRP_extrabacon 
{

    meta:
        description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"

    strings:
        $x1 = "To disable password checking on target:" fullword ascii
        $x2 = "[-] target is running" fullword ascii
        $x3 = "[-] problem importing version-specific shellcode from" fullword ascii
        $x4 = "[+] importing version-specific shellcode" fullword ascii
        $s5 = "[-] unsupported target version, abort" fullword ascii

    condition:
        1 of them
}

rule EQGRP_sploit_py 
{

    meta:
        description = "EQGRP Toolset Firewall - file sploit.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

    strings:
        $x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
        $x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
        $x3 = "[-] no response from health check - target may have crashed" fullword ascii
    
    condition:
        1 of them
}

rule EQGRP_uninstallPBD 
{

    meta:
        description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"

    strings:
        $s1 = "memset 00e9a05c 4 38845b88" fullword ascii
        $s2 = "_hidecmd" fullword ascii
        $s3 = "memset 013abd04 1 0d" fullword ascii
    
    condition:
        all of them
}

rule EQGRP_BICECREAM 
{

    meta:
        description = "EQGRP Toolset Firewall - file BICECREAM-2140"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"

    strings:
        $s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
        $s2 = "command data size is invalid for an exec cmd" fullword ascii
        $s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
        $s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
        $s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
        $s6 = "[%d] Execute code." fullword ascii
        $s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
        $s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
        $s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii
    
    condition:
        ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}

rule EQGRP_create_http_injection 
{

    meta:
        description = "EQGRP Toolset Firewall - file create_http_injection.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"

    strings:
        $x1 = "required by SECONDDATE" fullword ascii
        $s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
        $s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
        $s3 = "version='%prog 1.0'," fullword ascii
        $s4 = "usage='%prog [ ... options ... ] url'," fullword ascii

    condition:
        ( uint16(0) == 0x2123 and filesize < 3KB and ( $x1 or 2 of them ) ) or ( all of them )
}

rule EQGRP_BFLEA_2201 
{

    meta:
        description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"

    strings:
        $s1 = ".got_loader" fullword ascii
        $s2 = "LOADED" fullword ascii
        $s3 = "readFlashHandler" fullword ascii
        $s4 = "KEEPGOING" fullword ascii
        $s5 = "flashRtnsPix6x.c" fullword ascii
        $s6 = "fix_ip_cksum_incr" fullword ascii
        $s7 = "writeFlashHandler" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}

rule EQGRP_BpfCreator_RHEL4 
{

    meta:
        description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"

    strings:
        $s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
        $s2 = "error reading dump file: %s" fullword ascii
        $s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
        $s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
        $s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 2000KB and all of them )
}

rule EQGRP_StoreFc 
{

    meta:
        description = "EQGRP Toolset Firewall - file StoreFc.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"

    strings:
        $x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
        $x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
        $x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii

    condition:
        1 of them
}

rule EQGRP_hexdump 
{

    meta:
        description = "EQGRP Toolset Firewall - file hexdump.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"

    strings:
        $s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
        $s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
        $s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
        $s4 = "print >>out, sane(x[i:i+16])" fullword ascii

    condition:
        ( uint16(0) == 0x2123 and filesize < 1KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_BBALL 
{

    meta:
        description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"

    strings:
        $s1 = "Components/Modules/BiosModule/Implant/E28F6/../e28f640j3_asm.S" fullword ascii
        $s2 = ".got_loader" fullword ascii
        $s3 = "handler_readBIOS" fullword ascii
        $s4 = "cmosReadByte" fullword ascii
        $s5 = "KEEPGOING" fullword ascii
        $s6 = "checksumAreaConfirmed.0" fullword ascii
        $s7 = "writeSpeedPlow.c" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and 4 of ($s*) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule EQGRP_BARPUNCH_BPICKER 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

    strings:
        $x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
        $x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
        $x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
        $x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
        $x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii
   
    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and 1 of them ) or ( 3 of them )
}

rule EQGRP_Implants_Gen6 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
        hash7 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

    strings:
        $s1 = "LP.c:pixSecurity - Improper number of bytes read in Security/Interface Information" fullword ascii
        $s2 = "LP.c:pixSecurity - Not in Session" fullword ascii
        $s3 = "getModInterface__preloadedModules" fullword ascii
        $s4 = "showCommands" fullword ascii
        $s5 = "readModuleInterface" fullword ascii
        $s6 = "Wrapping_Not_Necessary_Or_Wrapping_Ok" fullword ascii
        $s7 = "Get_CMD_List" fullword ascii
        $s8 = "LP_Listen2" fullword ascii
        $s9 = "killCmdList" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and all of them )
}

rule EQGRP_Implants_Gen5 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
        hash8 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
   
    strings:
        $x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii
        $s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
        $s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
        $s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii
    
    condition:
        ( uint16(0) == 0x457f and 1 of ($x*) ) or ( all of them )
}

rule EQGRP_pandarock 
{

    meta:
        description = "EQGRP Toolset Firewall - from files pandarock_v1.11.1.1.bin, pit"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "1214e282ac7258e616ebd76f912d4b2455d1b415b7216823caa3fc0d09045a5f"
        hash2 = "c8a151df7605cb48feb8be2ab43ec965b561d2b6e2a837d645fdf6a6191ab5fe"
  
    strings:
        $x1 = "* Not attempting to execute \"%s\" command" fullword ascii
        $x2 = "TERMINATING SCRIPT (command error or \"quit\" encountered)" fullword ascii
        $x3 = "execute code in <file> passing <argX> (HEX)" fullword ascii
        $x4 = "* Use arrow keys to scroll through command history" fullword ascii
        $s1 = "pitCmd_processCmdLine" fullword ascii
        $s2 = "execute all commands in <file>" fullword ascii
        $s3 = "__processShellCmd" fullword ascii
        $s4 = "pitTarget_getDstPort" fullword ascii
        $s5 = "__processSetTargetIp" fullword ascii
        $o1 = "Logging commands and output - ON" fullword ascii
        $o2 = "This command is too dangerous.  If you'd like to run it, contact the development team" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*) ) or ( 4 of them ) or 1 of ($o*)
}

rule EQGRP_BananaUsurper_writeJetPlow
{

    meta:
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
 
    strings:
        $x1 = "Implant Version-Specific Values:" fullword ascii
        $x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii
        $s1 = "createSendRecv: recv'd an error from the target." fullword ascii
        $s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 2000KB and 1 of ($x*) ) or ( 3 of them )
}

rule EQGRP_Implants_Gen4 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash3 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash4 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"

    strings:
        $s1 = "Command has not yet been coded" fullword ascii
        $s2 = "Beacon Domain  : www.%s.com" fullword ascii
        $s3 = "This command can only be run on a PIX/ASA" fullword ascii
        $s4 = "Warning! Bad or missing Flash values (in section 2 of .dat file)" fullword ascii
        $s5 = "Printing the interface info and security levels. PIX ONLY." fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and 3 of them ) or ( all of them )
}

rule EQGRP_Implants_Gen3 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

    strings:
        $x1 = "incomplete and must be removed manually.)" fullword ascii
        $s1 = "%s: recv'd an error from the target." fullword ascii
        $s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
        $s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and 2 of them ) or ( all of them )
}

rule EQGRP_BLIAR_BLIQUER 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"

    strings:
        $x1 = "Do you wish to activate the implant that is already on the firewall? (y/n): " fullword ascii
        $x2 = "There is no implant present on the firewall." fullword ascii
        $x3 = "Implant Version :%lx%lx%lx" fullword ascii
        $x4 = "You may now connect to the implant using the pbd idkey" fullword ascii
        $x5 = "No reply from persistant back door." fullword ascii
        $x6 = "rm -rf pbd.wc; wc -c %s > pbd.wc" fullword ascii
        $p1 = "PBD_GetVersion" fullword ascii
        $p2 = "pbd/pbdEncrypt.bin" fullword ascii
        $p3 = "pbd/pbdGetVersion.pkt" fullword ascii
        $p4 = "pbd/pbdStartWrite.bin" fullword ascii
        $p5 = "pbd/pbd_setNewHookPt.pkt" fullword ascii
        $p6 = "pbd/pbd_Upload_SinglePkt.pkt" fullword ascii
        $s1 = "Unable to fetch hook and jmp addresses for this OS version" fullword ascii
        $s2 = "Could not get hook and jump addresses" fullword ascii
        $s3 = "Enter the name of a clean implant binary (NOT an image):" fullword ascii
        $s4 = "Unable to read dat file for OS version 0x%08lx" fullword ascii
        $s5 = "Invalid implant file" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and ( 1 of ($x*) or 1 of ($p*) ) ) or ( 3 of them )
}

rule EQGRP_sploit 
{

    meta:
        description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
        hash2 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

    strings:
        $s1 = "print \"[+] Connecting to %s:%s\" % (self.params.dst['ip'], self.params.dst['port'])" fullword ascii
        $s2 = "@overridable(\"Must be overriden if the target will be touched.  Base implementation should not be called.\")" fullword ascii
        $s3 = "@overridable(\"Must be overriden.  Base implementation should not be called.\")" fullword ascii
        $s4 = "exp.load_vinfo()" fullword ascii
        $s5 = "if not okay and self.terminateFlingOnException:" fullword ascii
        $s6 = "print \"[-] keyboard interrupt before response received\"" fullword ascii
        $s7 = "if self.terminateFlingOnException:" fullword ascii
        $s8 = "print 'Debug info ','='*40" fullword ascii

    condition:
        ( uint16(0) == 0x2123 and filesize < 90KB and 1 of ($s*) ) or ( 4 of them )
}

rule EQGRP_Implants_Gen2 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, writeJetPlow-2130"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash6 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
    
    strings:
        $x1 = "Modules persistence file written successfully" fullword ascii
        $x2 = "Modules persistence data successfully removed" fullword ascii
        $x3 = "No Modules are active on the firewall, nothing to persist" fullword ascii
        $s1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s " fullword ascii
        $s2 = "Error while attemping to persist modules:" fullword ascii
        $s3 = "Error while reading interface info from PIX" fullword ascii
        $s4 = "LP.c:pixFree - Failed to get response" fullword ascii
        $s5 = "WARNING: LP Timeout specified (%lu seconds) less than default (%u seconds).  Setting default" fullword ascii
        $s6 = "Unable to fetch config address for this OS version" fullword ascii
        $s7 = "LP.c: interface information not available for this session" fullword ascii
        $s8 = "[%s:%s:%d] ERROR: " fullword ascii
        $s9 = "extract_fgbg" fullword ascii

    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*) ) or ( 5 of them )
}

rule EQGRP_Implants_Gen1 
{

    meta:
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, lpexe, writeJetPlow-2130"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
        hash8 = "ee3e3487a9582181892e27b4078c5a3cb47bb31fc607634468cc67753f7e61d7"
        hash9 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
   
    strings:
        $s1 = "WARNING:  Session may not have been closed!" fullword ascii
        $s2 = "EXEC Packet Processed" fullword ascii
        $s3 = "Failed to insert the command into command list." fullword ascii
        $s4 = "Send_Packet: Trying to send too much data." fullword ascii
        $s5 = "payloadLength >= MAX_ALLOW_SIZE." fullword ascii
        $s6 = "Wrong Payload Size" fullword ascii
        $s7 = "Unknown packet received......" fullword ascii
        $s8 = "Returned eax = %08x" fullword ascii
    
    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and ( 2 of ($s*) ) ) or ( 5 of them )
}

rule EQGRP_eligiblebombshell_generic 
{

    meta:
        description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
        hash2 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
  
    strings:
        $s1 = "logging.error(\"       Perhaps you should run with --scan?\")" fullword ascii
        $s2 = "logging.error(\"ERROR: No entry for ETag [%s] in %s.\" %" fullword ascii
        $s3 = "\"be supplied\")" fullword ascii
  
    condition:
        ( filesize < 70KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_ssh_telnet_29 
{

    meta:
        description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"
        super_rule = 1
        hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
        hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"
    
    strings:
        $s1 = "received prompt, we're in" fullword ascii
        $s2 = "failed to login, bad creds, abort" fullword ascii
        $s3 = "sending command \" + str(n) + \"/\" + str(tot) + \", len \" + str(len(chunk) + " fullword ascii
        $s4 = "received nat - EPBA: ok, payload: mangled, did not run" fullword ascii
        $s5 = "no status returned from target, could be an exploit failure, or this is a version where we don't expect a stus return" ascii
        $s6 = "received arp - EPBA: ok, payload: fail" fullword ascii
        $s7 = "chopped = string.rstrip(payload, \"\\x0a\")" fullword ascii
   
    condition:
        ( filesize < 10KB and 2 of them ) or ( 3 of them )
}

/* Extras */

rule EQGRP_tinyexec 
{

    meta:
        description = "EQGRP Toolset Firewall - from files tinyexec"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"

    strings:
        $s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
        $s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }

    condition:
        uint32(0) == 0x464c457f and filesize < 270 and all of them
}

rule EQGRP_callbacks 
{

    meta:
        description = "EQGRP Toolset Firewall - Callback addresses"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"

    strings:
        $s1 = "30.40.50.60:9342" fullword ascii wide /* DoD */
    
    condition:
        1 of them
}

rule EQGRP_Extrabacon_Output 
{

    meta:
        description = "EQGRP Toolset Firewall - Extrabacon exploit output"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"

    strings:
        $s1 = "|###[ SNMPresponse ]###" fullword ascii
        $s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
        $s3 = "[+] building payload for mode pass-disable" fullword ascii
        $s4 = "[+] Executing:  extrabacon" fullword ascii
        $s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii
   
    condition:
        2 of them
}

rule EQGRP_Unique_Strings 
{

    meta:
        description = "EQGRP Toolset Firewall - Unique strings"
        author = "Florian Roth"
        reference = "Research"
        date = "2016-08-16"

    strings:
        $s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
        $s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"

    condition:
        1 of them
}

rule EQGRP_RC5_RC6_Opcode
{

    meta:
        description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
        author = "Florian Roth"
        reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
        date = "2016-08-17"

    strings:
        /*
            mov     esi, [ecx+edx*4-4]
            sub     esi, 61C88647h
            mov     [ecx+edx*4], esi
            inc     edx
            cmp     edx, 2Bh
        */
        $s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }
    
    condition:
        1 of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule BernhardPOS {
     meta:
          author = "Nick Hoffman / Jeremy Humble"
          last_update = "2015-07-14"
          source = "Morphick Inc."
          description = "BernhardPOS Credit Card dumping tool"
          reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
          md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"
          score = 70
     strings:
          $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
          $mutex_name = "OPSEC_BERNHARD" 
          $build_path = "C:\\bernhard\\Debug\\bernhard.pdb" 
          $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
     condition:
          any of them
 }

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule POS_bruteforcing_bot
{ 
	meta:
		maltype = "botnet"
    ref = "https://github.com/reed1713"
		reference = "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop"
		date = "3/11/2014"
		description = "botnet bruteforcing POS terms via RDP"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="\\AppData\\Roaming\\lsacs.exe"

	condition:
		all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule COZY_FANCY_BEAR_Hunt 
{

    meta:
        description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
        author = "Florian Roth"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
        date = "2016-06-14"

    strings:
        $s1 = "185.100.84.134" ascii wide fullword
        $s2 = "58.49.58.58" ascii wide fullword
        $s3 = "218.1.98.203" ascii wide fullword
        $s4 = "187.33.33.8" ascii wide fullword
        $s5 = "185.86.148.227" ascii wide fullword
        $s6 = "45.32.129.185" ascii wide fullword
        $s7 = "23.227.196.217" ascii wide fullword

    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_pagemgr_Hunt 
{

    meta:
        description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
        author = "Florian Roth"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
        date = "2016-06-14"

    strings:
        $s1 = "pagemgr.exe" wide fullword

    condition:
        uint16(0) == 0x5a4d and 1 of them
}
rule APT_fancybear_Downdelph_magic : Bootkit{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "APT28 downdelph magic string"
		reference = "https://www.threatminer.org/_reports/2016/eset-sednit-part3%20-%20ESET.pdf#viewer.action=download"
	strings:
		$str1 = " :3 "
	condition:
		$str1 at 0
}



rule APT_fancybear_Downdelph_MBR : Bootkit{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "APT28 downdelph string on MBR (get your MBR with BOOTICE on Win or #dd if=/dev/sda of=./sda.mbr bs=512 count=1"
		reference = "https://www.threatminer.org/_reports/2016/eset-sednit-part3%20-%20ESET.pdf#viewer.action=download"
	strings:
		$s1 = { 20 3A 33 20 } //string " :3 "
	condition:
		$s1 at 411  //posición 0x19b
}

/* FIVE EYES ------------------------------------------------------------------------------- */

rule FiveEyes_QUERTY_Malwareqwerty_20121 
{

    meta:
        description = "FiveEyes QUERTY Malware - file 20121.xml"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "8263fb58350f3b1d3c4220a602421232d5e40726"

    strings:
        $s0 = "<configFileName>20121_cmdDef.xml</configFileName>" fullword ascii
        $s1 = "<name>20121.dll</name>" fullword ascii
        $s2 = "<codebase>\"Reserved for future use.\"</codebase>" fullword ascii
        $s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
        $s4 = "<platform type=\"1\">" fullword ascii
        $s5 = "</plugin>" fullword ascii
        $s6 = "</pluginConfig>" fullword ascii
        $s7 = "<pluginConfig>" fullword ascii
        $s8 = "</platform>" fullword ascii
        $s9 = "</lpConfig>" fullword ascii
        $s10 = "<lpConfig>" fullword ascii
   
    condition:
        9 of them
}

rule FiveEyes_QUERTY_Malwaresig_20123_sys 
{
   
    meta:
        description = "FiveEyes QUERTY Malware - file 20123.sys.bin"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "a0f0087bd1f8234d5e847363d7e15be8a3e6f099"
  
    strings:
        $s0 = "20123.dll" fullword ascii
        $s1 = "kbdclass.sys" fullword wide
        $s2 = "IoFreeMdl" fullword ascii
        $s3 = "ntoskrnl.exe" fullword ascii
        $s4 = "KfReleaseSpinLock" fullword ascii
  
    condition:
        all of them
}

rule FiveEyes_QUERTY_Malwaresig_20123_cmdDef 
{
  
    meta:
        description = "FiveEyes QUERTY Malware - file 20123_cmdDef.xml"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "7b08fc77629f6caaf8cc4bb5f91be6b53e19a3cd"
   
   strings:
        $s0 = "<shortDescription>Keystroke Collector</shortDescription>" fullword ascii
        $s1 = "This plugin is the E_Qwerty Kernel Mode driver for logging keys.</description>" fullword ascii
        $s2 = "<commands/>" fullword ascii
        $s3 = "</version>" fullword ascii
        $s4 = "<associatedImplantId>20121</associatedImplantId>" fullword ascii
        $s5 = "<rightsRequired>System or Administrator (if Administrator, I think the DriverIns" ascii
        $s6 = "<platforms>Windows NT, Windows 2000, Windows XP (32/64 bit), Windows 2003 (32/64" ascii
        $s7 = "<projectpath>plugin/Collection</projectpath>" fullword ascii
        $s8 = "<dllDepend>None</dllDepend>" fullword ascii
        $s9 = "<minorType>0</minorType>" fullword ascii
        $s10 = "<pluginname>E_QwertyKM</pluginname>" fullword ascii
        $s11 = "</comments>" fullword ascii
        $s12 = "<comments>" fullword ascii
        $s13 = "<majorType>1</majorType>" fullword ascii
        $s14 = "<files>None</files>" fullword ascii
        $s15 = "<poc>Erebus</poc>" fullword ascii
        $s16 = "</plugin>" fullword ascii
        $s17 = "<team>None</team>" fullword ascii
        $s18 = "<?xml-stylesheet type=\"text/xsl\" href=\"../XSLT/pluginHTML.xsl\"?>" fullword ascii
        $s19 = "<pluginsDepend>U_HookManager v1.0, Kernel Covert Store v1.0</pluginsDepend>" fullword ascii
        $s20 = "<plugin id=\"20123\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi" ascii
  
    condition:
        14 of them
}

rule FiveEyes_QUERTY_Malwaresig_20121_dll 
{
    
    meta:
        description = "FiveEyes QUERTY Malware - file 20121.dll.bin"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "89504d91c5539a366e153894c1bc17277116342b"
    
    strings:
        $s0 = "WarriorPride\\production2.0\\package\\E_Wzowski" ascii
        $s1 = "20121.dll" fullword ascii
   
    condition:
        all of them
}

rule FiveEyes_QUERTY_Malwareqwerty_20123 
{

    meta:
        description = "FiveEyes QUERTY Malware - file 20123.xml"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "edc7228b2e27df9e7ff9286bddbf4e46adb51ed9"

    strings:
        $s0 = "<!-- edited with XMLSPY v5 rel. 4 U (http://www.xmlspy.com) by TEAM (RENEGADE) -" ascii
        $s1 = "<configFileName>20123_cmdDef.xml</configFileName>" fullword ascii
        $s2 = "<name>20123.sys</name>" fullword ascii
        $s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
        $s4 = "<codebase>/bin/i686-pc-win32/debug</codebase>" fullword ascii
        $s5 = "<platform type=\"1\">" fullword ascii
        $s6 = "</plugin>" fullword ascii
        $s7 = "</pluginConfig>" fullword ascii
        $s8 = "<pluginConfig>" fullword ascii
        $s9 = "</platform>" fullword ascii
        $s10 = "</lpConfig>" fullword ascii
        $s11 = "<lpConfig>" fullword ascii
   
    condition:
        9 of them
}

rule FiveEyes_QUERTY_Malwaresig_20120_dll 
{

    meta:
        description = "FiveEyes QUERTY Malware - file 20120.dll.bin"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "6811bfa3b8cda5147440918f83c40237183dbd25"

    strings:
        $s0 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.txt" fullword wide
        $s1 = "\\QwLog_%d-%02d-%02d-%02d%02d%02d.xml" fullword wide
        $s2 = "Failed to send the EQwerty_driverStatusCommand to the implant." fullword ascii
        $s3 = "- Log Used (number of windows) - %d" fullword wide
        $s4 = "- Log Limit (number of windows) - %d" fullword wide
        $s5 = "Process or User Default Language" fullword wide
        $s6 = "Windows 98/Me, Windows NT 4.0 and later: Vietnamese" fullword wide
        $s7 = "- Logging of keystrokes is switched ON" fullword wide
        $s8 = "- Logging of keystrokes is switched OFF" fullword wide
        $s9 = "Qwerty is currently logging active windows with titles containing the fo" wide
        $s10 = "Windows 95, Windows NT 4.0 only: Korean (Johab)" fullword wide
        $s11 = "FAILED to get Qwerty Status" fullword wide
        $s12 = "- Successfully retrieved Log from Implant." fullword wide
        $s13 = "- Logging of all Windows is toggled ON" fullword wide
        $s14 = "- Logging of all Windows is toggled OFF" fullword wide
        $s15 = "Qwerty FAILED to retrieve window list." fullword wide
        $s16 = "- UNSUCCESSFUL Log Retrieval from Implant." fullword wide
        $s17 = "The implant failed to return a valid status" fullword ascii
        $s18 = "- Log files were NOT generated!" fullword wide
        $s19 = "Windows 2000/XP: Armenian. This is Unicode only." fullword wide
        $s20 = "- This machine is using a PS/2 Keyboard - Continue on using QWERTY" fullword wide
   
    condition:
        10 of them
}

rule FiveEyes_QUERTY_Malwaresig_20120_cmdDef 
{

    meta:
        description = "FiveEyes QUERTY Malware - file 20120_cmdDef.xml"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "cda9ceaf0a39d6b8211ce96307302a53dfbd71ea"

    strings:
        $s0 = "This PPC gets the current keystroke log." fullword ascii
        $s1 = "This command will add the given WindowTitle to the list of Windows to log keys f" ascii
        $s2 = "This command will remove the WindowTitle corresponding to the given window title" ascii
        $s3 = "This command will return the current status of the Keyboard Logger (Whether it i" ascii
        $s4 = "This command Toggles logging of all Keys. If allkeys is toggled all keystrokes w" ascii
        $s5 = "<definition>Turn logging of all keys on|off</definition>" fullword ascii
        $s6 = "<name>Get Keystroke Log</name>" fullword ascii
        $s7 = "<description>Keystroke Logger Lp Plugin</description>" fullword ascii
        $s8 = "<definition>display help for this function</definition>" fullword ascii
        $s9 = "This command will switch ON Logging of keys. All keys taht are entered to a acti" ascii
        $s10 = "Set the log limit (in number of windows)" fullword ascii
        $s11 = "<example>qwgetlog</example>" fullword ascii
        $s12 = "<aliasName>qwgetlog</aliasName>" fullword ascii
        $s13 = "<definition>The title of the Window whose keys you wish to Log once it becomes a" ascii
        $s14 = "This command will switch OFF Logging of keys. No keystrokes will be captured" fullword ascii
        $s15 = "<definition>The title of the Window whose keys you no longer whish to log</defin" ascii
        $s16 = "<command id=\"32\">" fullword ascii
        $s17 = "<command id=\"3\">" fullword ascii
        $s18 = "<command id=\"7\">" fullword ascii
        $s19 = "<command id=\"1\">" fullword ascii
        $s20 = "<command id=\"4\">" fullword ascii
    
    condition:
        10 of them
}

rule FiveEyes_QUERTY_Malwareqwerty_20120 
{

    meta:
        description = "FiveEyes QUERTY Malware - file 20120.xml"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "597082f05bfd3225587d480c30f54a7a1326a892"

    strings:
        $s0 = "<configFileName>20120_cmdDef.xml</configFileName>" fullword ascii
        $s1 = "<name>20120.dll</name>" fullword ascii
        $s2 = "<codebase>\"Reserved for future use.\"</codebase>" fullword ascii
        $s3 = "<plugin xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceS" ascii
        $s4 = "<platform type=\"1\">" fullword ascii
        $s5 = "</plugin>" fullword ascii
        $s6 = "</pluginConfig>" fullword ascii
        $s7 = "<pluginConfig>" fullword ascii
        $s8 = "</platform>" fullword ascii
        $s9 = "</lpConfig>" fullword ascii
        $s10 = "<lpConfig>" fullword ascii
   
    condition:
        all of them
}

rule FiveEyes_QUERTY_Malwaresig_20121_cmdDef 
{

    meta:
        description = "FiveEyes QUERTY Malware - file 20121_cmdDef.xml"
        author = "Florian Roth"
        reference = "http://www.spiegel.de/media/media-35668.pdf"
        date = "2015/01/18"
        hash = "64ac06aa4e8d93ea6063eade7ce9687b1d035907"

    strings:
        $s0 = "<shortDescription>Keystroke Logger Plugin.</shortDescription>" fullword ascii
        $s1 = "<message>Failed to get File Time</message>" fullword ascii
        $s2 = "<description>Keystroke Logger Plugin.</description>" fullword ascii
        $s3 = "<message>Failed to set File Time</message>" fullword ascii
        $s4 = "</commands>" fullword ascii
        $s5 = "<commands>" fullword ascii
        $s6 = "</version>" fullword ascii
        $s7 = "<associatedImplantId>20120</associatedImplantId>" fullword ascii
        $s8 = "<message>No Comms. with Driver</message>" fullword ascii
        $s9 = "</error>" fullword ascii
        $s10 = "<message>Invalid File Size</message>" fullword ascii
        $s11 = "<platforms>Windows (User/Win32)</platforms>" fullword ascii
        $s12 = "<message>File Size Mismatch</message>" fullword ascii
        $s13 = "<projectpath>plugin/Utility</projectpath>" fullword ascii
        $s14 = "<pluginsDepend>None</pluginsDepend>" fullword ascii
        $s15 = "<dllDepend>None</dllDepend>" fullword ascii
        $s16 = "<pluginname>E_QwertyIM</pluginname>" fullword ascii
        $s17 = "<rightsRequired>None</rightsRequired>" fullword ascii
        $s18 = "<minorType>0</minorType>" fullword ascii
        $s19 = "<code>00001002</code>" fullword ascii
        $s20 = "<code>00001001</code>" fullword ascii
   
    condition:
        12 of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Furtim_nativeDLL 
{

    meta:
        description = "Detects Furtim malware - file native.dll"
        author = "Florian Roth"
        reference = "MISP 3971"
        date = "2016-06-13"
        hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"

    strings:
        $s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii
        $op0 = { e0 b3 42 00 c7 84 24 ac } /* Opcode */
        $op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 } /* Opcode */
        $op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 900KB and $s1 or all of ($op*)
}

rule Furtim_Parent_1 
{

    meta:
        description = "Detects Furtim Parent Malware"
        author = "Florian Roth"
        reference = "https://sentinelone.com/blogs/sfg-furtims-parent/"
        date = "2016-07-16"
        hash1 = "766e49811c0bb7cce217e72e73a6aa866c15de0ba11d7dda3bd7e9ec33ed6963"

    strings:
        /* RC4 encryption password */
        $x1 = "dqrChZonUF" fullword ascii
        /* Other strings */
        $s1 = "Egistec" fullword wide
        $s2 = "Copyright (C) 2016" fullword wide
        /* Op Code */
        $op1 = { c0 ea 02 88 55 f8 8a d1 80 e2 03 }
        $op2 = { 5d fe 88 55 f9 8a d0 80 e2 0f c0 }
        $op3 = { c4 0c 8a d9 c0 eb 02 80 e1 03 88 5d f8 8a d8 c0 }
  
    condition:
        ( uint16(0) == 0x5a4d and filesize < 900KB and ( $x1 or ( all of ($s*) and all of ($op*) ) ) ) or all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-08
   Identifier: ShadowBroker Screenshot Rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule FVEY_ShadowBrokers_Jan17_Screen_Strings 
{

   meta:
      description = "Detects strings derived from the ShadowBroker's leak of Windows tools/exploits"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/"
      date = "2017-01-08"

   strings:
      $x1 = "Danderspritz" ascii wide fullword
      $x2 = "DanderSpritz" ascii wide fullword
      $x3 = "PeddleCheap" ascii wide fullword
      $x4 = "ChimneyPool Addres" ascii wide fullword
      $a1 = "Getting remote time" fullword ascii
      $a2 = "RETRIEVED" fullword ascii
      $b1 = "Added Ops library to Python search path" fullword ascii
      $b2 = "target: z0.0.0.1" fullword ascii
      $c1 = "Psp_Avoidance" fullword ascii
      $c2 = "PasswordDump" fullword ascii
      $c3 = "InjectDll" fullword ascii
      $c4 = "EventLogEdit" fullword ascii
      $c5 = "ProcessModify" fullword ascii
      $d1 = "Mcl_NtElevation" fullword ascii wide
      $d2 = "Mcl_NtNativeApi" fullword ascii wide
      $d3 = "Mcl_ThreatInject" fullword ascii wide
      $d4 = "Mcl_NtMemory" fullword ascii wide

   condition:
      filesize < 2000KB and (1 of ($x*) or all of ($a*) or 1 of ($b*) or ( uint16(0) == 0x5a4d and 1 of ($c*) ) or 3 of ($c*) or ( uint16(0) == 0x5a4d and 3 of ($d*) ))
}


rule Control32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "b3dc808fc7cb4492669ec019911ef22a"
}

rule Control64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "bec30379078d5c5c7845d3be33707b89"
}

rule GH_PM32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "2f2c5b3f3b1f97908074f526ac90a28d"
}

rule GH_PM64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "fe6c0097412b2c7b7f4b8a489004dd14"
}

rule MemStub32_GH1 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "0a579ad25fdd4db8110aac4dbb7d2da3"
}

rule MemStub32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "8987652f26732607b769247adb4e9cce"
}

rule MemStub64_GH1 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "2350403a09e6928f0a7ba5d74da58cb9"
}

rule MemStub64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "6b5b46d3212fc3fc5b455d9efd8d3ffa"
}

rule msvcrt_Win7AMD64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "c8fc794cc5a22b5a1e0803b0b8acce77"
}

rule msvcrt_Win7x86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "7713e5c5a48b020c9575b1b50f2e5e9e"
}

rule msvcrt_WIN8AMD64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "33c59fcdf027470e0ab1d366f54a6ebf"
}

rule msvcrt_WIN8x86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "95490c2b284a9bb63f0ee49254ab727e"
}

rule msvcrt_WinXPx86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "b68f72d77754f8b76168ced0924a4174"
}

rule Network_Win7AMD64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "eb92031a38f17d0e63285b5142b31966"
}

rule Network_Win7x86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "548889baed7768b828d9c2f373abd225"
}

rule Network_WinXPx86 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "877341a16d5d223435c43a9db7f721bc"
}

rule RabbitStew32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "a9d2e8ae5ddbf8f2842d96f7de2faef8"
}

rule RabbitStew64 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "fa415b6280104e813770df520b303897"
}

rule Vbr {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "961d2fd68fde2ae0b7c52e0c90767d0d"
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-25
   Identifier: Greenbug Malware
*/

/* Rule Set ----------------------------------------------------------------- */

rule Greenbug_Malware_1 {
   meta:
      description = "Detects Malware from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
   strings:
      $s1 = "vailablez" fullword ascii
      $s2 = "Sfouglr" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule Greenbug_Malware_2 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      hash1 = "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
      hash2 = "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
      hash3 = "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
   strings:
      $x1 = "|||Command executed successfully" fullword ascii
      $x2 = "\\Release\\Bot Fresh.pdb" ascii
      $x3 = "C:\\ddd\\a1.txt" fullword wide
      $x4 = "Bots\\Bot5\\x64\\Release" ascii
      $x5 = "Bot5\\Release\\Ism.pdb" ascii
      $x6 = "Bot\\Release\\Ism.pdb" ascii
      $x7 = "\\Bot Fresh\\Release\\Bot" ascii

      $s1 = "/Home/SaveFile?commandId=CmdResult=" fullword wide
      $s2 = "raB3G:Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday" fullword ascii
      $s3 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
      $s4 = "SELECT * FROM AntiVirusProduct" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}

rule Greenbug_Malware_3 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash2 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
   strings:
      $x1 = "F:\\Projects\\Bot\\Bot\\Release\\Ism.pdb" fullword ascii
      $x2 = "C:\\ddd\\wer2.txt" fullword wide
      $x3 = "\\Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition:
      1 of them
}

rule Greenbug_Malware_4 {
   meta:
      description = "Detects ISMDoor Backdoor"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
   strings:
      $s1 = "powershell.exe -nologo -windowstyle hidden -c \"Set-ExecutionPolicy -scope currentuser" fullword ascii
      $s2 = "powershell.exe -c \"Set-ExecutionPolicy -scope currentuser -ExecutionPolicy unrestricted -f; . \"" fullword ascii
      $s3 = "c:\\windows\\temp\\tmp8873" fullword ascii
      $s4 = "taskkill /im winit.exe /f" fullword ascii
      $s5 = "invoke-psuacme"
      $s6 = "-method oobe -payload \"\"" fullword ascii
      $s7 = "C:\\ProgramData\\stat2.dat" fullword wide
      $s8 = "Invoke-bypassuac" fullword ascii
      $s9 = "Start Keylog Done" fullword wide
      $s10 = "Microsoft\\Windows\\WinIt.exe" fullword ascii
      $s11 = "Microsoft\\Windows\\Tmp9932u1.bat\"" fullword ascii
      $s12 = "Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them ) or ( 3 of them )
}

rule Greenbug_Malware_5 {
   meta:
      description = "Auto-generated rule - from files 308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f, 44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49, 7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c, 82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash3 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
      hash4 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
   strings:
      $x1 = "cmd /u /c WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter" fullword ascii
      $x2 = "cmd /a /c net user administrator /domain >>" fullword ascii
      $x3 = "cmd /a /c netstat -ant >>\"%localappdata%\\Microsoft\\" fullword ascii

      $o1 = "========================== (Net User) ==========================" ascii fullword
   condition:
      filesize < 2000KB and (
         ( uint16(0) == 0x5a4d and 1 of them ) or
         $o1
      )
}

rule IMPLANT_1_v1 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {6A ?? E8 ?? ?? FF FF 59 85 C0 74 0B 8B C8 E8 ?? ?? FF FF 8B F0
         EB 02 33 F6 8B CE E8 ?? ?? FF FF 85 F6 74 0E 8B CE E8 ?? ?? FF FF 56
         E8 ?? ?? FF FF 59}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_1_v2 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {83 3E 00 53 74 4F 8B 46 04 85 C0 74 48 83 C0 02 50 E8 ?? ?? 00
         00 8B D8 59 85 DB 74 38 8B 4E 04 83 F9 FF 7E 21 57 }
      $STR2 = {55 8B EC 8B 45 08 3B 41 08 72 04 32 C0 EB 1B 8B 49 04 8B 04 81
         80 78 19 01 75 0D FF 70 10 FF [5] 85 C0 74 E3 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_1_v3 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $rol7encode = { 0F B7 C9 C1 C0 07 83 C2 02 33 C1 0F B7 0A 47 66 85 C9 75 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_1_v4 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XOR_LOOP = { 8B 45 FC 8D 0C 06 33 D2 6A 0B 8B C6 5B F7 F3 8A 82 ?? ??
         ?? ?? 32 04 0F 46 88 01 3B 75 0C 7C E0 }
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_1_v5 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $drivername = { 6A 30 ?? 6A 33 [5] 6A 37 [5] 6A 32 [5] 6A 31 [5] 6A 77
         [5] 6A 69 [5] 6A 6E [5] 6A 2E [5] 6A 73 [5-9] 6A 79 [5] 6A 73 }
      $mutexname = { C7 45 ?? 2F 2F 64 66 C7 45 ?? 63 30 31 65 C7 45 ?? 6C 6C
         36 7A C7 45 ?? 73 71 33 2D C7 45 ?? 75 66 68 68 66 C7 45 ?? 66 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_1_v6 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XORopcodes_eax = { 35 (22 07 15 0e|56 d7 a7 0a) }
      $XORopcodes_others = { 81 (F1|F2|F3|F4|F5|F6|F7) (22 07 15 0E|56 D7 A7 0A) }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025) and any of them
}

*/

rule IMPLANT_1_v7 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v1 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8d ?? fa [2] e8 [2] FF FF C7 [2-5] 00 00 00 00 8D [2-5] 5? 6a 00 6a 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v2 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8]
         48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v3 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {C1 EB 07 8D ?? 01 32 1C ?? 33 D2 }
      $STR2 = {2B ?? 83 ?? 06 0F 83 ?? 00 00 00 EB 02 33 }
      $STR3 = {89 ?? ?? 89 ?? ?? 89 55 ?? 89 45 ?? 3B ?? 0F 83 ?? 00 00 00 8D
         ?? ?? 8D ?? ?? FE }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v4 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53
         56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68
         [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v5 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00 33
         C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15 ?? 00
         00 00 48 8B CC E8}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v6 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { e8 [2] ff ff 8b [0-6] 00 04 00 00 7F ?? [1-2] 00 02 00 00 7F
         ?? [1-2] 00 01 00 00 7F ?? [1-2] 80 00 00 00 7F ?? 83 ?? 40 7F}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v7 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $s1 = {10 A0 FA FD 83 3D 28 D4 1F FF 77 5? ?8 B4 50 CC 1E B0 78 D7 90 13
         21 C0 23 3D 28 BC 78 95 DE 4B B0 60 00 00 0F 7F 38 B4 50 C8 D5 9F E0
         25 DF F3 21 C0 28 BC 13 3D 2B 90 60 00 00 0F 7F 18 B4 50 C8 BC F2 21
         C0 28 B4 5E 48 B5 5E 00 8D 41 FE 83 F8 06 8B 45 ?? 72 ?? 8B 4D ?? 8B }
      $s2 = {28 D9 B0 00 00 00 00 FB 65 C0 AF E8 D3 40 28 B4 5? ?0 3C 20 FA FD
         88 D7 A0 18 D4 2F F3 3D 2F 77 5? ?C 1E B0 78 BC 73 21 C0 A3 3D 2B 90
         60 00 00 0F 7F 18 A4 D? ?8 B4 50 C8 0E 90 20 24 D? ?3 20 C0 28 B4 5?
         ?3 3D 2F 77 5? ?8 B4 50 C2 20 C0 28 BD 70 2D 93 01 E8 B4 D0 C8 D4 2F
         E3 B4 5E 88 B4 5? ?8 95 5? ?7 2A 05 F5 E5 B8 BE 55 DC 20 80 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v8 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {8B ?? 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA C1 EE 02 89
         74 24 58 44 8B ?? 41 F7 ?? 8B CA BA 03 00 00 00 C1 E9 02 89 0C 24 8D
         04 49 03 C0 44 2B ?? 44 89 ?? 24 04 3B F1 0F 83 ?? 01 00 00 8D 1C 76
         4C 89 6C 24 }
      $STR2 = {C5 41 F7 E0 ?? ?? ?? ?? ?? ?? 8D 0C 52 03 C9 2B C1 8B C8 ?? 8D
         04 ?? 46 0F B6 0C ?? 40 02 C7 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7
         E1 C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA 46 22 0C ?? 41 8D 48
         FE F7 E1 C1 EA 02 8D 04 52 03 C0 2B C8 8B C1 }
      $STR3 = {41 F7 E0 C1 EA 02 41 8B C0 8D 0C 52 03 C9 2B C1 8B C8 42 8D 04
         1B 46 0F B6 0C ?? 40 02 C6 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7 E1
         C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA }
      $STR4 = {46 22 0C ?? 41 8D 48 FE F7 E1 C1 EA 02 8D 04 52 8B 54 24 58 03
         C0 2B C8 8B C1 0F B6 4F FF 42 0F B6 04 ?? 41 0F AF CB C1 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v9 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8A C3 02 C0 02 D8 8B 45 F8 02 DB 83 C1 02 03 45 08 88 5D 0F 89
         45 E8 8B FF 0F B6 5C 0E FE 8B 45 F8 03 C1 0F AF D8 8D 51 01 89 55 F4
         33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B 45 F4 C1 EB 07 32 1C 32 33 D2
         F7 F7 8A C1 02 45 0F 2C 02 32 04 32 33 D2 88 45 FF 8B C1 8B F7 F7 F6
         8A 45 FF 8B 75 14 22 04 32 02 D8 8B 45 E8 30 1C 08 8B 4D F4 8D 51 FE
         3B D7 72 A4 8B 45 E4 8B 7D E0 8B 5D F0 83 45 F8 06 43 89 5D F0 3B D8
         0F 82 ?? ?? ?? ?? 3B DF 75 13 8D 04 7F 8B 7D 10 03 C0 2B F8 EB 09 33
         C9 E9 5B FF FF FF 33 FF 3B 7D EC 0F 83 ?? ?? ?? ?? 8B 55 08 8A CB 02
         C9 8D 04 19 02 C0 88 45 13 8D 04 5B 03 C0 8D 54 10 FE 89 45 E0 8D 4F
         02 89 55 E4 EB 09 8D 9B 00 00 00 00 8B 45 E0 0F B6 5C 31 FE 8D 44 01
         FE 0F AF D8 8D 51 01 89 55 0C 33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B
         45 0C C1 EB 07 32 1C 32 33 D2 F7 F7 8A C1 02 45 13 2C 02 32 04 32 33
         D2 88 45 0B 8B C1 8B F7 F7 F6 8A 45 0B 8B 75 14 22 04 32 02 D8 8B 45
         E4 30 1C 01 8B 4D 0C }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v10 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8]
         48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v11 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53
         56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68
         [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v12 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00
         33 C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15
         ?? 00 00 00 48 8B CC E8}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v13 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF
         [6-8] 48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v14 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {8B ?? 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA C1 EE 02 89
         74 24 58 44 8B ?? 41 F7 ?? 8B CA BA 03 00 00 00 C1 E9 02 89 0C 24 8D
         04 49 03 C0 44 2B ?? 44 89 ?? 24 04 3B F1 0F 83 ?? 01 00 00 8D 1C 76
         4C 89 6C 24  }
      $STR2 = {C5 41 F7 E0 ?? ?? ?? ?? ?? ?? 8D 0C 52 03 C9 2B C1 8B C8 ?? 8D
         04 ?? 46 0F B6 0C ?? 40 02 C7 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7
         E1 C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA 46 22 0C ?? 41 8D 48
         FE F7 E1 C1 EA 02 8D 04 52 03 C0 2B C8 8B C1 }
      $STR3 = {41 F7 E0 C1 EA 02 41 8B C0 8D 0C 52 03 C9 2B C1 8B C8 42 8D 04
         1B 46 0F B6 0C ?? 40 02 C6 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7 E1
         C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA }
      $STR4 = {46 22 0C ?? 41 8D 48 FE F7 E1 C1 EA 02 8D 04 52 8B 54 24 58 03
         C0 2B C8 8B C1 0F B6 4F FF 42 0F B6 04 ?? 41 0F AF CB C1 }
   condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v15 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XOR_LOOP1 = { 32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 }
      $XOR_LOOP2 = { 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 }
      $XOR_LOOP3 = { 02 C3 30 06 8B 5D F0 8D 41 FE 83 F8 06 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v16 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $OBF_FUNCT = { 0F B6 1C 0B 8D 34 08 8D 04 0A 0F AF D8 33 D2 8D 41 FF F7
         75 F8 8B 45 0C C1 EB 07 8D 79 01 32 1C 02 33 D2 8B C7 89 5D E4 BB 06
         00 00 00 F7 F3 8B 45 0C 8D 59 FE 02 5D FF 32 1C 02 8B C1 33 D2 B9 06
         00 00 00 F7 F1 8B 45 0C 8B CF 22 1C 02 8B 45 E4 8B 55 E0 02 C3 30 06
         8B 5D F0 8D 41 FE 83 F8 06 8B 45 DC 72 9A }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $OBF_FUNCT
}

rule IMPLANT_2_v17  {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 24108b44241c894424148b4424246836 }
      $STR2 = { 518d4ddc516a018bd08b4de4e8360400 }
      $STR3 = { e48178061591df75740433f6eb1a8b48 }
      $STR4 = { 33d2f775f88b45d402d903c641321c3a }
      $STR5 = { 006a0056ffd083f8ff74646a008d45f8 }
   condition:
      (uint16(0) == 0x5A4D) and 2 of them
}

rule IMPLANT_2_v18 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8A C1 02 C0 8D 1C 08 8B 45 F8 02 DB 8D 4A 02 8B 55 0C 88 5D FF
         8B 5D EC 83 C2 FE 03 D8 89 55 E0 89 5D DC 8D 49 00 03 C1 8D 34 0B 0F
         B6 1C 0A 0F AF D8 33 D2 8D 41 FF F7 75 F4 8B 45 0C C1 EB 07 8D 79 01
         32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 8B 45 0C 8D 59 FE
         02 5D FF 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B 45 0C 8B CF 22
         1C 02 8B 45 E4 8B 55 E0 02 C3 30 06 8B 5D DC 8D 41 FE 83 F8 06 8B 45
         F8 72 9B 8B 4D F0 8B 5D D8 8B 7D 08 8B F0 41 83 C6 06 89 4D F0 89 75
         F8 3B 4D D4 0F 82 ?? ?? ?? ?? 8B 55 E8 3B CB 75 09 8D 04 5B 03 C0 2B
         F8 EB 02 33 FF 3B FA 0F 83 ?? ?? ?? ?? 8B 5D EC 8A C1 02 C0 83 C3 FE
         8D 14 08 8D 04 49 02 D2 03 C0 88 55 0B 8D 48 FE 8D 57 02 03 C3 89 4D
         D4 8B 4D 0C 89 55 F8 89 45 D8 EB 06 8D 9B 00 00 00 00 0F B6 5C 0A FE
         8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42 FF 33 D2 F7 75 F4 C1
         EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1 8A 4D F8 8B 45 0C 80
         E9 02 02 4D 0B 32 0C 02 8B 45 F8 33 D2 F7 75 F4 8B 45 0C 22 0C 02 8B
         D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v19 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $obfuscated_RSA1 = { 7C 41 B4 DB ED B0 B8 47 F1 9C A1 49 B6 57 A6 CC D6
         74 B5 52 12 4D FC B1 B6 3B 85 73 DF AB 74 C9 25 D8 3C EA AE 8F 5E D2
         E3 7B 1E B8 09 3C AF 76 A1 38 56 76 BB A0 63 B6 9E 5D 86 E4 EC B0 DC
         89 1E FA 4A E5 79 81 3F DB 56 63 1B 08 0C BF DC FC 75 19 3E 1F B3 EE
         9D 4C 17 8B 16 9D 99 C3 0C 89 06 BB F1 72 46 7E F4 0B F6 CB B9 C2 11
         BE 5E 27 94 5D 6D C0 9A 28 F2 2F FB EE 8D 82 C7 0F 58 51 03 BF 6A 8D
         CD 99 F8 04 D6 F7 F7 88 0E 51 88 B4 E1 A9 A4 3B }
      $cleartext_RSA1 = { 06 02 00 00 00 A4 00 00 52 53 41 31 00 04 00 00 01
         00 01 00 AF BD 26 C9 04 65 45 9F 0E 3F C4 A8 9A 18 C8 92 00 B2 CC 6E
         0F 2F B2 71 90 FC 70 2E 0A F0 CA AA 5D F4 CA 7A 75 8D 5F 9C 4B 67 32
         45 CE 6E 2F 16 3C F1 8C 42 35 9C 53 64 A7 4A BD FA 32 99 90 E6 AC EC
         C7 30 B2 9E 0B 90 F8 B2 94 90 1D 52 B5 2F F9 8B E2 E6 C5 9A 0A 1B 05
         42 68 6A 3E 88 7F 38 97 49 5F F6 EB ED 9D EF 63 FA 56 56 0C 7E ED 14
         81 3A 1D B9 A8 02 BD 3A E6 E0 FA 4D A9 07 5B E6 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_2_v20 {
   meta:
      description = "CORESHELL/SOURFACE Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $func = { 0F B6 5C 0A FE 8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42
         FF 33 D2 F7 75 F4 C1 EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1
         8A 4D F8 8B 45 0C 80 E9 02 02 4D 0B 32 0C 02 8B 45 F8 33 D2 F7 75 F4
         8B 45 0C 22 0C 02 8B D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 8B 45
         D8 89 55 F8 72 A0 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_3_v1 {
   meta:
      description = "X-Agent/CHOPSTICK Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = ">process isn't exist<" ascii wide
      $STR2 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" ascii wide
      $STR3 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0" ascii wide
      $STR4 = "webhp?rel=psy&hl=7&ai=" ascii wide
      $STR5 = {0f b6 14 31 88 55 ?? 33 d2 8b c1 f7 75 ?? 8b 45 ?? 41 0f b6 14
         02 8a 45 ?? 03 fa}
   condition:
      any of them
}

rule IMPLANT_3_v2 {
   meta:
      description = "X-Agent/CHOPSTICK Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $base_key_moved = {C7 45 ?? 3B C6 73 0F C7 45 ?? 8B 07 85 C0 C7 45 ?? 74
         02 FF D0 C7 45 ?? 83 C7 04 3B C7 45 ?? FE 72 F1 5F C7 45 ?? 5E C3 8B
         FF C7 45 ?? 56 B8 D8 78 C7 45 ?? 75 07 50 E8 C7 45 ?? B1 D1 FF FF C7
         45 ?? 59 5D C3 8B C7 45 ?? FF 55 8B EC C7 45 ?? 83 EC 10 A1 66 C7 45
         ?? 33 35}
      $base_key_b_array = {3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE
         72 F1 5F 5E C3 8B FF 56 B8 D8 78 75 07 50 E8 B1 D1 FF FF 59 5D C3 8B
         FF 55 8B EC 83 EC 10 A1 33 35 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_3_v3 {
   meta:
      description = "X-Agent/CHOPSTICK Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = ".?AVAgentKernel@@"
      $STR2 = ".?AVIAgentModule@@"
      $STR3 = "AgentKernel"
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_4_v1 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {55 8B EC 81 EC 54 01 00 00 83 65 D4 00 C6 45 D8 61 C6 45 D9 64
         C6 45 DA 76 C6 45 DB 61 C6 45 DC 70 C6 45 DD 69 C6 45 DE 33 C6 45 DF
         32 C6 45 E0 2EE9 ?? ?? ?? ??} $STR2 = {C7 45 EC 5A 00 00 00 C7 45 E0
            46 00 00 00 C7 45 E8 5A 00 00 00 C7 45 E4 46 00 00 00}
   condition:
      (uint16(0)== 0x5A4D or uint16(0) == 0xCFD0 or uint16(0)== 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 1 of them
}

rule IMPLANT_4_v2 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $BUILD_USER32 = {75 73 65 72 ?? ?? ?? 33 32 2E 64}
      $BUILD_ADVAPI32 = {61 64 76 61 ?? ?? ?? 70 69 33 32}
      $CONSTANT = {26 80 AC C8}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

/* Some false positives - replaced with alternative rule (see below)

rule IMPLANT_4_v3 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $a1 = "Adobe Flash Player Installer" wide nocase
      $a3 = "regedt32.exe" wide nocase
      $a4 = "WindowsSysUtility" wide nocase
      $a6 = "USB MDM Driver" wide nocase
      $b1 = {00 05 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 3F 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 5C 04 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 1C 02 00 00 01 00 30 00 30
         00 31 00 35 00 30 00 34 00 62 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 46
         00 0F 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 55 00 53 00 42 00 20
         00 4D 00 44 00 4D 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00
         00 00 3C 00 0E 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
         00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00
         30 00 30 00 2E 00 35 00 35 00 31 00 32 00 00 00 4A 00 13 00 01 00 4C
         00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00
         68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
         00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 33 00 00 00 00 00
         3E 00 0B 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46
         00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 75 00 73 00 62 00
         6D 00 64 00 6D 00 2E 00 73 00 79 00 73 00 00 00 00 00 66 00 23 00 01
         00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00
         00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20
         00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4F 00 70 00 65 00
         72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65
         00 6D 00 00 00 00 00 40 00 0E 00 01 00 50 00 72 00 6F 00 64 00 75 00
         63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 2E
         00 31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00
         00 00 1C 02 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 62 00 30
         00 00 00 4C 00 16 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00
         4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73
         00 6F 00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F 00 72 00 61 00
         74 00 69 00 6F 00 6E 00 00 00 46 00 0F 00 01 00 46 00 69 00 6C 00 65
         00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00
         00 00 00 00 55 00 53 00 42 00 20 00 4D 00 44 00 4D 00 20 00 44 00 72
         00 69 00 76 00 65 00 72 00 00 00 00 00 3C 00 0E 00 01 00 46 00 69 00
         6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35
         00 2E 00 31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00
         32 00 00 00 4A 00 13 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F
         00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43 00 6F 00 70 00
         79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32
         00 30 00 31 00 33 00 00 00 00 00 3E 00 0B 00 01 00 4F 00 72 00 69 00
         67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D
         00 65 00 00 00 75 00 73 00 62 00 6D 00 64 00 6D 00 2E 00 73 00 79 00
         73 00 00 00 00 00 66 00 23 00 01 00 50 00 72 00 6F 00 64 00 75 00 63
         00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00
         6F 00 73 00 6F 00 66 00 74 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77
         00 73 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00
         20 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 40 00 0E 00 01
         00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00
         69 00 6F 00 6E 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00 30 00 30
         00 2E 00 35 00 35 00 31 00 32 00 00 00 48 00 00 00 01 00 56 00 61 00
         72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 28
         00 08 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00
         6F 00 6E 00 00 00 00 00 15 00 B0 04 09 04 B0 04}
      $b2 = {34 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 03 00 03 00 04 00 02 00 03 00 03 00 04 00 02 00 3F 00 00 00
         00 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 94 02 00 00 00 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 70 02 00 00 00 00 30 00 34
         00 30 00 39 00 30 00 34 00 65 00 34 00 00 00 4A 00 15 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 53 00 6F 00 6C 00 69 00 64 00 20 00 53 00 74 00 61 00 74 00 65 00
         20 00 4E 00 65 00 74 00 77 00 6F 00 72 00 6B 00 73 00 00 00 00 00 62
         00 1D 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 41 00 64 00 6F 00 62
         00 65 00 20 00 46 00 6C 00 61 00 73 00 68 00 20 00 50 00 6C 00 61 00
         79 00 65 00 72 00 20 00 49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 65
         00 72 00 00 00 00 00 30 00 08 00 01 00 46 00 69 00 6C 00 65 00 56 00
         65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 33 00 2E 00 33 00 2E
         00 32 00 2E 00 34 00 00 00 32 00 09 00 01 00 49 00 6E 00 74 00 65 00
         72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 68 00 6F 00 73
         00 74 00 2E 00 65 00 78 00 65 00 00 00 00 00 76 00 29 00 01 00 4C 00
         65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68
         00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00
         20 00 28 00 43 00 29 00 20 00 41 00 64 00 6F 00 62 00 65 00 20 00 53
         00 79 00 73 00 74 00 65 00 6D 00 73 00 20 00 49 00 6E 00 63 00 6F 00
         72 00 70 00 6F 00 72 00 61 00 74 00 65 00 64 00 00 00 00 00 3A 00 09
         00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00
         6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 6F 00 73 00 74 00 2E
         00 65 00 78 00 65 00 00 00 00 00 5A 00 1D 00 01 00 50 00 72 00 6F 00
         64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 41 00 64
         00 6F 00 62 00 65 00 20 00 46 00 6C 00 61 00 73 00 68 00 20 00 50 00
         6C 00 61 00 79 00 65 00 72 00 20 00 49 00 6E 00 73 00 74 00 61 00 6C
         00 6C 00 65 00 72 00 00 00 00 00 34 00 08 00 01 00 50 00 72 00 6F 00
         64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00
         00 33 00 2E 00 33 00 2E 00 32 00 2E 00 34 00 00 00 44 00 00 00 00 00
         56 00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00
         00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00
         74 00 69 00 6F 00 6E 00 00 00 00 00 09 04 E4 04 46 45 32 58}
      $b3 = {C8 02 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 17 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 28 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 04 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 65 00 34 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 48
         00 10 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 49 00 44 00 45 00 20
         00 50 00 6F 00 72 00 74 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00
         00 00 62 00 21 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
         00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00
         30 00 30 00 2E 00 35 00 35 00 31 00 32 00 20 00 28 00 78 00 70 00 73
         00 70 00 2E 00 30 00 38 00 30 00 34 00 31 00 33 00 2D 00 30 00 38 00
         35 00 32 00 29 00 00 00 00 00 4A 00 13 00 01 00 4C 00 65 00 67 00 61
         00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00
         43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43
         00 29 00 20 00 32 00 30 00 30 00 39 00 00 00 00 00 66 00 23 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00
         00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00
         57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4F 00 70 00 65 00 72
         00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00
         6D 00 00 00 00 00 40 00 0E 00 01 00 50 00 72 00 6F 00 64 00 75 00 63
         00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 2E 00
         31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00 00
         00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00
         6E 00 66 00 6F 00 00 00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E
         00 73 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 00 00 00 00 09 04 E4 04 }
      $b4 = {9C 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 06 00 01 40 B0 1D 01 00 06 00 01 40 B0 1D 3F 00 00 00
         00 00 00 00 04 00 04 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 FA 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 D6 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 58
         00 18 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 52 00 65 00 67 00 69
         00 73 00 74 00 72 00 79 00 20 00 45 00 64 00 69 00 74 00 6F 00 72 00
         20 00 55 00 74 00 69 00 6C 00 69 00 74 00 79 00 00 00 6C 00 26 00 01
         00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00
         00 00 00 00 36 00 2E 00 31 00 2E 00 37 00 36 00 30 00 30 00 2E 00 31
         00 36 00 33 00 38 00 35 00 20 00 28 00 77 00 69 00 6E 00 37 00 5F 00
         72 00 74 00 6D 00 2E 00 30 00 39 00 30 00 37 00 31 00 33 00 2D 00 31
         00 32 00 35 00 35 00 29 00 00 00 3A 00 0D 00 01 00 49 00 6E 00 74 00
         65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 72 00 65
         00 67 00 65 00 64 00 74 00 33 00 32 00 2E 00 65 00 78 00 65 00 00 00
         00 00 80 00 2E 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
         00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9 00 20 00 4D 00 69 00
         63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00 6F 00 72 00 70
         00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20 00 41 00 6C 00
         6C 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73
         00 65 00 72 00 76 00 65 00 64 00 2E 00 00 00 42 00 0D 00 01 00 4F 00
         72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E
         00 61 00 6D 00 65 00 00 00 72 00 65 00 67 00 65 00 64 00 74 00 33 00
         32 00 2E 00 65 00 78 00 65 00 00 00 00 00 6A 00 25 00 01 00 50 00 72
         00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00
         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57
         00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00
         72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65
         00 6D 00 00 00 00 00 42 00 0F 00 01 00 50 00 72 00 6F 00 64 00 75 00
         63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 36 00 2E
         00 31 00 2E 00 37 00 36 00 30 00 30 00 2E 00 31 00 36 00 33 00 38 00
         35 00 00 00 00 00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6C
         00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 24 00 04 00 00 00 54 00
         72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 00 00 00
         00 09 04 B0 04}
      $b5 = {78 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 00 00 05 00 6A 44 B1 1D 00 00 05 00 6A 44 B1 1D 3F 00 00 00
         00 00 00 00 04 00 04 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 D6 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 B2 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 4E
         00 13 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 57 00 69 00 6E 00 64
         00 6F 00 77 00 73 00 AE 00 53 00 79 00 73 00 55 00 74 00 69 00 6C 00
         69 00 74 00 79 00 00 00 00 00 72 00 29 00 01 00 46 00 69 00 6C 00 65
         00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00
         30 00 2E 00 37 00 36 00 30 00 31 00 2E 00 31 00 37 00 35 00 31 00 34
         00 20 00 28 00 77 00 69 00 6E 00 37 00 73 00 70 00 31 00 5F 00 72 00
         74 00 6D 00 2E 00 31 00 30 00 31 00 31 00 31 00 39 00 2D 00 31 00 38
         00 35 00 30 00 29 00 00 00 00 00 30 00 08 00 01 00 49 00 6E 00 74 00
         65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 6D 00 73
         00 69 00 65 00 78 00 65 00 63 00 00 00 80 00 2E 00 01 00 4C 00 65 00
         67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
         00 00 00 A9 00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00
         74 00 20 00 43 00 6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F
         00 6E 00 2E 00 20 00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68 00
         74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2E
         00 00 00 40 00 0C 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00
         6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 73
         00 69 00 65 00 78 00 65 00 63 00 2E 00 65 00 78 00 65 00 00 00 58 00
         1C 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D
         00 65 00 00 00 00 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 53 00
         79 00 73 00 55 00 74 00 69 00 6C 00 69 00 74 00 79 00 20 00 2D 00 20
         00 55 00 6E 00 69 00 63 00 6F 00 64 00 65 00 00 00 42 00 0F 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69
         00 6F 00 6E 00 00 00 35 00 2E 00 30 00 2E 00 37 00 36 00 30 00 31 00
         2E 00 31 00 37 00 35 00 31 00 34 00 00 00 00 00 44 00 00 00 01 00 56
         00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00
         00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74
         00 69 00 6F 00 6E 00 00 00 00 00 09 04 B0 04}
      $b6 = {D4 02 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 17 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 34 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         00 65 00 49 00 6E 00 66 00 6F 00 00 00 10 02 00 00 01 00 30 00 34 00
         30 00 39 00 30 00 34 00 65 00 34 00 00 00 4C 00 16 00 01 00 43 00 6F
         00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 00
         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00 6F
         00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 4E 00
         13 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69
         00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 53 00 65 00 72 00 69 00
         61 00 6C 00 20 00 50 00 6F 00 72 00 74 00 20 00 44 00 72 00 69 00 76
         00 65 00 72 00 00 00 00 00 62 00 21 00 01 00 46 00 69 00 6C 00 65 00
         56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31
         00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00 20 00
         28 00 78 00 70 00 73 00 70 00 2E 00 30 00 38 00 30 00 34 00 31 00 33
         00 2D 00 30 00 38 00 35 00 32 00 29 00 00 00 00 00 4A 00 13 00 01 00
         4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67
         00 68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00
         74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 30 00 34 00 00 00 00
         00 6A 00 25 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00
         61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
         00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00
         AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20
         00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 40 00 0E 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69
         00 6F 00 6E 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00 30 00 30 00
         2E 00 35 00 35 00 31 00 32 00 00 00 44 00 00 00 01 00 56 00 61 00 72
         00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 24 00
         04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F
         00 6E 00 00 00 00 00 09 04 E4 04}
   condition:
      (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
      (((any of ($a*)) and (uint32(uint32(0x3C)+8) == 0x00000000)) or
      (for any of ($b*): ($ in (uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+20))..(uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+20))+uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+16)))))))
}

*/

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-12
   Identifier: Grizzly Steppe Alternatives
*/

/* Alternative Rule Set ---------------------------------------------------- */

rule IMPLANT_4_v3_AlternativeRule {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      comment = "Alternative rule - not based on the original samples but samples on which the original rule matched"
      author = "Florian Roth"
      reference = "US CERT Grizzly Steppe Report"
      date = "2017-02-12"
      hash1 = "2244fe9c5d038edcb5406b45361613cf3909c491e47debef35329060b00c985a"
   strings:
      $op1 = { 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 53 1e 01 00 } /* Opcode */
      $op2 = { 21 da 40 00 00 a0 40 00 08 a0 40 00 b0 70 40 00 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and all of them )
}

/* Alternative Rule Set ---------------------------------------------------- */

rule IMPLANT_4_v4 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DK_format1 = "/c format %c: /Y /Q" ascii
      $DK_format2 = "/c format %c: /Y /X /FS:NTFS" ascii
      $DK_physicaldrive = "PhysicalDrive%d" wide
      $DK_shutdown = "shutdown /r /t %d"
   condition:
      uint16(0) == 0x5A4D and all of ($DK*)
}

rule IMPLANT_4_v5 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $GEN_HASH = {0F BE C9 C1 C0 07 33 C1}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or
      uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or
      uint32(1) == 0x6674725C) and all of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_4_v6 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "DispatchCommand" wide ascii
      $STR2 = "DispatchEvent" wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

*/

rule IMPLANT_4_v7 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $sb1 = {C7 [1-5] 33 32 2E 64 C7 [1-5] 77 73 32 5F 66 C7 [1-5] 6C 6C}
      $sb2 = {C7 [1-5] 75 73 65 72 C7 [1-5] 33 32 2E 64 66 C7 [1-5] 6C 6C}
      $sb3 = {C7 [1-5] 61 64 76 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb4 = {C7 [1-5] 77 69 6E 69 C7 [1-5] 6E 65 74 2E C7 [1-5] 64 6C 6C}
      $sb5 = {C7 [1-5] 73 68 65 6C C7 [1-5] 6C 33 32 2E C7 [1-5] 64 6C 6C}
      $sb6 = {C7 [1-5] 70 73 61 70 C7 [1-5] 69 2E 64 6C 66 C7 [1-5] 6C}
      $sb7 = {C7 [1-5] 6E 65 74 61 C7 [1-5] 70 69 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb8 = {C7 [1-5] 76 65 72 73 C7 [1-5] 69 6F 6E 2E C7 [1-5] 64 6C 6C}
      $sb9 = {C7 [1-5] 6F 6C 65 61 C7 [1-5] 75 74 33 32 C7 [1-5] 2E 64 6C 6C}
      $sb10 = {C7 [1-5] 69 6D 61 67 C7 [1-5] 65 68 6C 70 C7 [1-5] 2E 64 6C 6C}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 3 of them
}

rule IMPLANT_4_v8 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $f1 = {5E 81 EC 04 01 00 00 8B D4 68 04 01 00 00 52 6A 00 FF 57 1C 8B D4
         33 C9 03 D0 4A 41 3B C8 74 05 80 3A 5C 75 F5 42 81 EC 04 01 00 00 8B
         DC 52 51 53 68 04 01 00 00 FF 57 20 59 5A 66 C7 04 03 5C 20 56 57 8D
         3C 03 8B F2 F3 A4 C6 07 00 5F 5E 33 C0 50 68 80 00 00 00 6A 02 50 50
         68 00 00 00 40 53 FF 57 14 53 8B 4F 4C 8B D6 33 DB 30 1A 42 43 3B D9
         7C F8 5B 83 EC 04 8B D4 50 6A 00 52 FF 77 4C 8B D6 52 50 FF 57 24 FF
         57 18}
      $f2 = {5E 83 EC 1C 8B 45 08 8B 4D 08 03 48 3C 89 4D E4 89 75 EC 8B 45 08
         2B 45 10 89 45 E8 33 C0 89 45 F4 8B 55 0C 3B 55 F4 0F 86 98 00 00 00
         8B 45 EC 8B 4D F4 03 48 04 89 4D F4 8B 55 EC 8B 42 04 83 E8 08 D1 E8
         89 45 F8 8B 4D EC 83 C1 08 89 4D FC}
      $f3 = {5F 8B DF 83 C3 60 2B 5F 54 89 5C 24 20 8B 44 24 24 25 00 00 FF FF
         66 8B 18 66 81 FB 4D 5A 74 07 2D 00 00 01 00 EB EF 8B 48 3C 03 C8 66
         8B 19 66 81 FB 50 45 75 E0 8B E8 8B F7 83 EC 60 8B FC B9 60 00 00 00
         F3 A4 83 EF 60 6A 0D 59 E8 88 00 00 00 E2 F9 68 6C 33 32 00 68 73 68
         65 6C 54 FF 57}
      $a1 = {83 EC 04 60 E9 1E 01 00 00}
   condition:
      $a1 at pe.entry_point or any of ($f*)
}

rule IMPLANT_4_v9 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $a = "wevtutil clear-log" ascii wide nocase
      $b = "vssadmin delete shadows" ascii wide nocase
      $c = "AGlobal\\23d1a259-88fa-41df-935f-cae523bab8e6" ascii wide nocase
      $d = "Global\\07fd3ab3-0724-4cfd-8cc2-60c0e450bb9a" ascii wide nocase //$e = {57 55 33 c9 51 8b c3 99 57 52 50}
      $openPhysicalDiskOverwriteWithZeros = { 57 55 33 C9 51 8B C3 99 57 52
         50 E8 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 83 C4 10 84 C0 75 21 33 C0 89
         44 24 10 89 44 24 14 6A 01 8B C7 99 8D 4C 24 14 51 52 50 56 FF 15 ??
         ?? ?? ?? 85 C0 74 0B 83 C3 01 81 FB 00 01 00 00 7C B6 }
      $f = {83 c4 0c 53 53 6a 03 53 6a 03 68 00 00 00 c0}
   condition:
      ($a and $b) or $c or $d or ($openPhysicalDiskOverwriteWithZeros and $f)
}

rule IMPLANT_4_v10 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $ ={A1B05C72}
      $ ={EB3D0384}
      $ ={6F45594E}
      $ ={71815A4E}
      $ ={D5B03E72}
      $ ={6B43594E}
      $ ={F572993D}
      $ ={665D9DC0}
      $ ={0BE7A75A}
      $ ={F37443C5}
      $ ={A2A474BB}
      $ ={97DEEC67}
      $ ={7E0CB078}
      $ ={9C9678BF}
      $ ={4A37A149}
      $ ={8667416B}
      $ ={0A375BA4}
      $ ={DC505A8D}
      $ ={02F1F808}
      $ ={2C819712}
   condition:
      uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 and 15 of them
}

rule IMPLANT_4_v11 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $ = "/c format %c: /Y /X /FS:NTFS"
      $ = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" wide
      $ = ".dll.exe.xml.ttf.nfo.fon.ini.cfg.boot.jar" wide
      $= ".crt.bin.exe.db.dbf.pdf.djvu.doc.docx.xls.xlsx.jar.ppt.pptx.tib.vhd.iso.lib.mdb.accdb.sql.mdf.xml.rtf.ini.cf g.boot.txt.rar.msi.zip.jpg.bmp.jpeg.tiff" wide
      $tempfilename = "%ls_%ls_%ls_%d.~tmp" ascii wide
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 2 of them
}

/* Deactivated - Slowing down scanning

rule IMPLANT_4_v12 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $CMP1 = {81 ?? 4D 5A 00 00 }
      $SUB1 = {81 ?? 00 10 00 00}
      $CMP2 = {66 81 38 4D 5A}
      $SUB2 = {2D 00 10 00 00}
      $HAL = "HAL.dll"
      $OUT = {E6 64 E9 ?? ?? FF FF}
   condition:
   (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
   uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and ($CMP1 or $CMP2)
   and ($SUB1 or $SUB2) and $OUT and $HAL
}
*/

rule IMPLANT_4_v13 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XMLDOM1 = {81 BF 33 29 36 7B D2 11 B2 0E 00 C0 4F 98 3E 60}
      $XMLDOM2 = {90 BF 33 29 36 7B D2 11 B2 0E 00 C0 4F 98 3E 60}
      $XMLPARSE = {8B 06 [0-2] 8D 55 ?C 52 FF 75 08 [0-2] 50 FF 91 04 01 00 00
         66 83 7D ?C FF 75 3? 8B 06 [0-2] 8D 55 F? 52 50 [0-2] FF 51 30 85 C0
         78 2?}
      $EXP1 = "DispatchCommand"
      $EXP2 = "DispatchEvent"
      $BDATA = {85 C0 74 1? 0F B7 4? 06 83 C? 28 [0-6] 72 ?? 33 C0 5F 5E 5B 5D
         C2 08 00 8B 4? 0? 8B 4? 0? 89 01 8B 4? 0C 03 [0-2] EB E?}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_5_v1 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $hexstr = {2D 00 53 00 69 00 00 00 2D 00 53 00 70 00 00 00 2D 00 55 00
         70 00 00 00 2D 00 50 00 69 00 00 00 2D 00 50 00 70 00 00 00}
      $UDPMSG1 = "error 2005 recv from server UDP - %d\x0a"
      $TPSMSG1 = "error 2004 send to TPS - %d\x0a"
      $TPSMSG2 = "error 2003 recv from TPS - %d\x0a"
      $UDPMSG2 = "error 2002 send to server UDP - %d\x0a"
   condition:
      any of them
}

rule IMPLANT_5_v2 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $key0 = { 987AB999FE0924A2DF0A412B14E26093746FCDF9BA31DC05536892C33B116AD3 }
      $key1 = { 8B236C892D902B0C9A6D37AE4F9842C3070FBDC14099C6930158563C6AC00FF5 }
      $key2 = { E47B7F110CAA1DA617545567EC972AF3A6E7B4E6807B7981D3CFBD3D8FCC3373 }
      $key3 = { 48B284545CA1FA74F64FDBE2E605D68CED8A726D05EBEFD9BAAC164A7949BDC1 }
      $key4 = { FB421558E30FCCD95FA7BC45AC92D2991C44072230F6FBEAA211341B5BF2DC56 }
      $key5 = { 34F1AE17017AF16021ADA5CE3F77675BBC6E7DEC6478D6078A0B22E5FDFF3B31 }
      $key6 = { F0EA48F164395186E6F754256EBB812A2AFE168E77ED9501F8B8E6F5B72126A7 }
      $key7 = { 0B6E9970A8EAF68EE14AB45005357A2F3391BEAA7E53AB760B916BC2B3916ABE }
      $key8 = { FF032EA7ED2436CF6EEA1F741F99A3522A61FDA8B5A81EC03A8983ED1AEDAB1A }
      $key9 = { F0DAC1DDFEF7AC6DE1CBE1006584538FE650389BF8565B32E0DE1FFACBCB14BB }
      $key10 = { A5D699A3CD4510AF11F1AF767602055C523DF74B94527D74319D6EFC6883B80D }
      $key11 = { 5951B02696C1D5A7B2851D28872384DA607B25F4CEA268FF3FD7FBA75AB3B4B3 }
      $key12 = { 0465D99B26AF42D8346001BB838595E301BAD8CF5D40CE9C17C944717DF82481 }
      $key13 = { 5DFE1C83AD5F5CE1BF5D9C42E23225E3ECFDB2493E80E6554A2AC7C722EB4880 }
      $key14 = { E9650396C45F7783BC14C59F46EA8232E8357C26B5627BFF8C42C6AE2E0F2E17 }
      $key15 = { 7432AE389125BB4E3980ED7F6A6FB252A42E785A90F4591C3620CA642FF97CA3 }
      $key16 = { 2B2ADBBC4F960A8916F7088067BAD30BE84B65783FBF9476DF5FDA0E5856B183 }
      $key17 = { 808C3FD0224A59384161B8A81C8BB404D7197D16D8118CB77067C5C8BD764B3E }
      $key18 = { 028B0E24D5675C16C815BFE4A073E9778C668E65771A1CE881E2B03F58FC7D5B }
      $key19 = { 878B7F5CF2DC72BAF1319F91A4880931EE979665B1B24D3394FE72EDFAEF4881 }
      $key20 = { 7AC7DD6CA34F269481C526254D2F563BC6ECA1779FEEAA33EC1C20E60B686785 }
      $key21 = { 3044F1D394186815DD8E3A2BBD9166837D07FA1CF6A550E2C170C9CDD9305209 }
      $key22 = { 7544DC095C441E39D258648FE9CB1267D20D83C8B2D3AB734474401DA4932619 }
      $key23 = { D702223347406C1999D1A9829CBBE96EC86D377A40E2EE84562EA1FAC1C71498 }
      $key24 = { CA36CB1177382A1009D392A58F7C1357E94AD2292CC0AE82EE4F7DB0179148E1 }
      $key25 = { C714F23E4C1C4E55F0E1FA7F5D0DD64658A86F84681D07576D840784154F65DC }
      $key26 = { 63571BAF736904634AFEE2A70CB9ED64615DE8CA7AEF21E773286B8877D065DB }
      $key27 = { 27808A9BE98FFE348DE1DB999AC9FDFB26E6C5A0D5E688490EF3D186C43661EB }
      $key28 = { B6EB86A07A85D40866AFA100789FFB9E85C13F5AA7C7A3B6BA753C7EAB9D6A62 }
      $key29 = { 88F0020375D60BDB85ACDBFE4BD79CD098DB2B3FA2CEF55D4331DBEFCE455157 }
      $key30 = { 36535AAB296587AE1162AC5D39492DD1245811C72706246A38FF590645AA5D7B }
      $key31 = { FDB726261CADD52E10818B49CAB81BEF112CB63832DAA26AD9FC711EA6CE99A4 }
      $key32 = { 86C0CAA26D9FD07D215BC7EB14E2DA250E905D406AFFAB44FB1C62A2EAFC4670 }
      $key33 = { BC101329B0E3A7D13F6EBC535097785E27D59E92D449D6D06538725034B8C0F0 }
      $key34 = { C8D31A78B7C149F62F06497F9DC1DDC4967B566AC52C3A2A65AC7A99643B8A2D }
      $key35 = { 0EA4A5C565EFBB94F5041392C5F0565B6BADC630D9005B3EADD5D81110623E1F }
      $key36 = { 06E4E46BD3A0FFC8A4125A6A02B0C56D5D8B9E378CF97539CE4D4ADFAF89FEB5 }
      $key37 = { 6DE22040821F0827316291331256A170E23FA76E381CA7066AF1E5197AE3CFE7 }
      $key38 = { C6EF27480F2F6F40910074A45715143954BBA78CD74E92413F785BBA5B2AA121 }
      $key39 = { 19C96A28F8D9698ADADD2E31F2426A46FD11D2D45F64169EDC7158389BFA59B4 }
      $key40 = { C3C3DDBB9D4645772373A815B5125BB2232D8782919D206E0E79A6A973FF5D36 }
      $key41 = { C33AF1608037D7A3AA7FB860911312B4409936D236564044CFE6ED42E54B78A8 }
      $key42 = { 856A0806A1DFA94B5E62ABEF75BEA3B657D9888E30C8D2FFAEC042930BBA3C90 }
      $key43 = { 244496C524401182A2BC72177A15CDD2EF55601F1D321ECBF2605FFD1B9B8E3F }
      $key44 = { DF24050364168606D2F81E4D0DEB1FFC417F1B5EB13A2AA49A89A1B5242FF503 }
      $key45 = { 54FA07B8108DBFE285DD2F92C84E8F09CDAA687FE492237F1BC4343FF4294248 }
      $key46 = { 23490033D6BF165B9C45EE65947D6E6127D6E00C68038B83C8BFC2BCE905040C }
      $key47 = { 4E044025C45680609B6EC52FEB3491130A711F7375AAF63D69B9F952BEFD5F0C }
      $key48 = { 019F31C5F5B2269020EBC00C1F511F2AC23E9D37E89374514C6DA40A6A03176C }
      $key49 = { A2483197FA57271B43E7276238468CFB8429326CBDA7BD091461147F642BEB06 }
      $key50 = { 731C9D6E74C589B7ACB019E5F6A6E07ACF12E68CB9A396CE05AA4D69D5387048 }
      $key51 = { 540DB6C8D23F7F7FEF9964E53F445F0E56459B10E931DEEEDB2B57B063C7F8B7 }
      $key52 = { D5AF80A7EEFF26DE988AC3D7CE23E62568813551B2133F8D3E973DA15E355833 }
      $key53 = { E4D8DBD3D801B1708C74485A972E7F00AFB45161C791EE05282BA68660FFBA45 }
      $key54 = { D79518AF96C920223D687DD596FCD545B126A678B7947EDFBF24661F232064FB }
      $key55 = { B57CAA4B45CA6E8332EB58C8E72D0D9853B3110B478FEA06B35026D7708AD225 }
      $key56 = { 077C714C47DFCF79CA2742B1544F4AA8035BB34AEA9D519DEE77745E01468408 }
      $key57 = { C3F5550AD424839E4CC54FA015994818F4FB62DE99B37C872AF0E52C376934FA }
      $key58 = { 5E890432AE87D0FA4D209A62B9E37AAEDEDC8C779008FEBAF9E4E6304D1B2AAC }
      $key59 = { A42EDE52B5AF4C02CFE76488CADE36A8BBC3204BCB1E05C402ECF450071EFCAB }
      $key60 = { 4CDAFE02894A04583169E1FB4717A402DAC44DA6E2536AE53F5F35467D31F1CA }
      $key61 = { 0BEFCC953AD0ED6B39CE6781E60B83C0CFD166B124D1966330CBA9ADFC9A7708 }
      $key62 = { 8A439DC4148A2F4D5996CE3FA152FF702366224737B8AA6784531480ED8C8877 }
      $key63 = { CF253BE3B06B310901FF48A351471374AD35BBE4EE654B72B860F2A6EC7B1DBB }
      $key64 = { A0599F50C4D059C5CFA16821E97C9596B1517B9FB6C6116F260415127F32CE1F }
      $key65 = { 8B6D704F3DC9150C6B7D2D54F9C3EAAB14654ACA2C5C3952604E65DF8133FE0C }
      $key66 = { A06E5CDD3871E9A3EE17F7E8DAE193EE47DDB87339F2C599402A78C15D77CEFD }
      $key67 = { E52ADA1D9BC4C089DBB771B59904A3E0E25B531B4D18B58E432D4FA0A41D9E8A }
      $key68 = { 4778A7E23C686C171FDDCCB8E26F98C4CBEBDF180494A647C2F6E7661385F05B }
      $key69 = { FE983D3A00A9521F871ED8698E702D595C0C7160A118A7630E8EC92114BA7C12 }
      $key70 = { 52BA4C52639E71EABD49534BBA80A4168D15762E2D1D913BAB5A5DBF14D9D166 }
      $key71 = { 931EB8F7BC2AE1797335C42DB56843427EB970ABD601E7825C4441701D13D7B1 }
      $key72 = { 318FA8EDB989672DBE2B5A74949EB6125727BD2E28A4B084E8F1F50604CCB735 }
      $key73 = { 5B5F2315E88A42A7B59C1B493AD15B92F819C021BD70A5A6619AAC6666639BC2 }
      $key74 = { C2BED7AA481951FEB56C47F03EA38236BC425779B2FD1F1397CB79FE2E15C0F0 }
      $key75 = { D3979B1CB0EC1A655961559704D7CDC019253ACB2259DFB92558B7536D774441 }
      $key76 = { 0EDF5DBECB772424D879BBDD51899D6AAED736D0311589566D41A9DBB8ED1CC7 }
      $key77 = { CC798598F0A9BCC82378A5740143DEAF1A147F4B2908A197494B7202388EC905 }
      $key78 = { 074E9DF7F859BF1BD1658FD2A86D81C282000EAB09AF4252FAB45433421D3849 }
      $key79 = { 6CD540642E007F00650ED20D7B54CFFD54DDA95D8DEBB087A004BAE222F22C8E }
      $key80 = { C76CF2F66C71F6D17FC8DEFA1CAEF8718BA1CE188C7EA02C835A0FA54D3B3314 }
      $key81 = { A7250A149600E515C9C40FE5720756FDA8251635A3B661261070CB5DABFE7253 }
      $key82 = { 237C67B97D4CCE4610DE2B82E582808EA796C34A4C24715C953CBA403B2C935E }
      $key83 = { A8FA182547E66B57C497DAAA195A38C0F0FB0A3C1F7B98B4B852F5F37E885127 }
      $key84 = { 83694CCA50B821144FFBBE6855F62845F1328111AE1AC5666CBA59EB43AA12C6 }
      $key85 = { 145E906416B17865AD37CD022DF5481F28C930D6E3F53C50B0953BF33F4DB953 }
      $key86 = { AB49B7C2FA3027A767F5AA94EAF2B312BBE3E89FD924EF89B92A7CF977354C22 }
      $key87 = { 7E04E478340C209B01CA2FEBBCE3FE77C6E6169F0B0528C42FA4BDA6D90AC957 }
      $key88 = { 0EADD042B9F0DDBABA0CA676EFA4EDB68A045595097E5A392217DFFC21A8532F }
      $key89 = { 5623710F134ECACD5B70434A1431009E3556343ED48E77F6A557F2C7FF46F655 }
      $key90 = { 6968657DB62F4A119F8E5CB3BF5C51F4B285328613AA7DB9016F8000B576561F }
      $key91 = { DEBB9C95EAE6A68974023C335F8D2711135A98260415DF05845F053AD65B59B4 }
      $key92 = { 16F54900DBF08950F2C5835153AB636605FB8C09106C0E94CB13CEA16F275685 }
      $key93 = { 1C9F86F88F0F4882D5CBD32876368E7B311A84418692D652A6A4F315CC499AE8 }
      $key94 = { E920E0783028FA05F4CE2D6A04BBE636D56A775CFD4DAEA3F2A1B8BEEB52A6D4 }
      $key95 = { 73874CA3AF47A8A315D50E1990F44F655EC7C15B146FFE0611B6C4FC096BD07C }
      $key96 = { F21C1FA163C745789C53922C47E191A5A85301BDC2FFC3D3B688CFBFF39F3BE5 }
      $key97 = { BC5A861F21CB98BD1E2AE9650B7A0BB4CD0C71900B3463C1BC3380AFD2BB948E }
      $key98 = { 151BAE36E646F30570DC6A7B57752F2481A0B48DD5184E914BCF411D8AD5ACA0 }
      $key99 = { F05AD6D7A0CADC10A6468BFDBCBB223D5BD6CA30EE19C239E8035772D80312C9 }
      $key100 = { 5DE9A0FDB37C0D59C298577E5379BCAF4F86DF3E9FA17787A4CEFA7DD10C462E }
      $key101 = { F5E62BA862380224D159A324D25FD321E5B35F8554D70CF9A506767713BCA508 }
      $key102 = { A2D1B10409B328DA0CCBFFDE2AD2FF10855F95DA36A1D3DBA84952BB05F8C3A7 }
      $key103 = { C974ABD227D3AD339FAC11C97E11D904706EDEA610B181B8FAD473FFCC36A695 }
      $key104 = { AB5167D2241406C3C0178D3F28664398D5213EE5D2C09DCC9410CB604671F5F1 }
      $key105 = { C25CC4E671CAAA31E137700A9DB3A272D4E157A6A1F47235043D954BAE8A3C70 }
      $key106 = { E6005757CA0189AC38F9B6D5AD584881399F28DA949A0F98D8A4E3862E20F715 }
      $key107 = { 204E6CEB4FF59787EF4D5C9CA5A41DDF4445B9D8E0C970B86D543E9C7435B194 }
      $key108 = { 831D7FD21316590263B69E095ABBE89E01A176E16AE799D83BD774AF0D254390 }
      $key109 = { 42C36355D9BC573D72F546CDB12E6BB2CFE2933AC92C12040386B310ABF6A1ED }
      $key110 = { B9044393C09AD03390160041446BF3134D864D16B25F1AB5E5CDC690C4677E7D }
      $key111 = { 6BC1102B5BE05EEBF65E2C3ACA1F4E17A59B2E57FB480DE016D371DA3AEF57A5 }
      $key112 = { B068D00B482FF73F8D23795743C76FE8639D405EE54D3EFB20AFD55A9E2DFF4E }
      $key113 = { 95CF5ADDFE511C8C7496E3B75D52A0C0EFE01ED52D5DD04D0CA6A7ABD3A6F968 }
      $key114 = { 75534574A4620019F8E3D055367016255034FA7D91CBCA9E717149441742AC8D }
      $key115 = { 96F1013A5301534BE424A11A94B740E5EB3A627D052D1B769E64BAB6A666433C }
      $key116 = { 584477AB45CAF729EE9844834F84683ABECAB7C4F7D23A9636F54CDD5B8F19B3 }
      $key117 = { D3905F185B564149EE85CC3D093477C8FF2F8CF601C68C38BBD81517672ECA3A }
      $key118 = { BF29521A7F94636D1930AA236422EB6351775A523DE68AF9BF9F1026CEDA618D }
      $key119 = { 04B3A783470AF1613A9B849FBD6F020EE65C612343EB1C028B2C28590789E60B }
      $key120 = { 3D8D8E84977FE5D21B6971D8D873E7BED048E21333FE15BE2B3D1732C7FD3D04 }
      $key121 = { 8ACB88224B6EF466D7653EB0D8256EA86D50BBA14FD05F7A0E77ACD574E9D9FF }
      $key122 = { B46121FFCF1565A77AA45752C9C5FB3716B6D8658737DF95AE8B6A2374432228 }
      $key123 = { A4432874588D1BD2317224FB371F324DD60AB25D4191F2F01C5C13909F35B943 }
      $key124 = { 78E1B7D06ED2A2A044C69B7CE6CDC9BCD77C19180D0B082A671BBA06507349C8 }
      $key125 = { 540198C3D33A631801FE94E7CB5DA3A2D9BCBAE7C7C3112EDECB342F3F7DF793 }
      $key126 = { 7E905652CAB96ACBB7FEB2825B55243511DF1CD8A22D0680F83AAF37B8A7CB36 }
      $key127 = { 37218801DBF2CD92F07F154CD53981E6189DBFBACAC53BC200EAFAB891C5EEC8 }
   condition:
      any of them
}

rule IMPLANT_5_v3 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $BYTES1 = { 0F AF C0 6? C0 07 00 00 00 2D 01 00 00 00 0F AF ?? 39 ?8 }
      $BYTES2 = { 0F AF C0 6? C0 07 48 0F AF ?? 39 ?8 }
   condition:
      any of them
}

rule IMPLANT_5_v4 {
   meta:
      description = "XTunnel Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $FBKEY1 = { 987AB999FE0924A2DF0A412B14E26093746FCDF9BA31DC05536892C33B116AD3 }
      $FBKEY2 = { 8B236C892D902B0C9A6D37AE4F9842C3070FBDC14099C6930158563C6AC00FF5 }
      $FBKEY3 = { E47B7F110CAA1DA617545567EC972AF3A6E7B4E6807B7981D3CFBD3D8FCC3373 }
      $FBKEY4 = { 48B284545CA1FA74F64FDBE2E605D68CED8A726D05EBEFD9BAAC164A7949BDC1 }
      $FBKEY5 = { FB421558E30FCCD95FA7BC45AC92D2991C44072230F6FBEAA211341B5BF2DC56 }
   condition:
      all of them
}

rule IMPLANT_6_v1
{
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "dll.dll" wide ascii
      $STR2 = "Init1" wide ascii
      $STR3 = "netui.dll" wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v2 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $obf_func = { 8B 45 F8 6A 07 03 C7 33 D2 89 45 E8 8D 47 01 5B 02 4D 0F F7 F3 6A 07 8A 04 32 33 D2 F6 E9 8A C8 8B C7 F7 F3 8A 44 3E FE 02 45 FC 02 0C 32 B2 03 F6 EA 8A D8 8D 47 FF 33 D2 5F F7 F7 02 5D 14 8B 45 E8 8B 7D F4 C0 E3 06 02 1C 32 32 CB 30 08 8B 4D 14 41 47 83 FF 09 89 4D 14 89 7D F4 72 A1 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v3 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $deob_func = { 8D 46 01 02 D1 83 E0 07 8A 04 38 F6 EA 8B D6 83 E2 07 0A
         04 3A 33 D2 8A 54 37 FE 03 D3 03 D1 D3 EA 32 C2 8D 56 FF 83 E2 07 8A
         1C 3A 8A 14 2E 32 C3 32 D0 41 88 14 2E 46 83 FE 0A 7C ?? }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v4 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $ASM = {53 5? 5? [6-15] ff d? 8b ?? b? a0 86 01 00 [7-13] ff d? ?b
         [6-10] c0 [0-1] c3}
   condition:
   (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
   uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v5 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 83 EC 18 8B 4C 24 24 B8 AB AA AA AA F7 E1 8B 44 24 20 53 55 8B
         EA 8D 14 08 B8 AB AA AA AA 89 54 24 1C F7 E2 56 8B F2 C1 ED 02 8B DD
         57 8B 7C 24 38 89 6C 24 1C C1 EE 02 3B DE 89 5C 24 18 89 74 24 20 0F
         83 CF 00 00 00 8D 14 5B 8D 44 12 FE 89 44 24 10 3B DD 0F 85 CF 00 00
         00 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B CA 83 F9 06 89 4C 24 38 0F 83
         86 00 00 00 8A C3 B2 06 F6 EA 8B 54 24 10 88 44 24 30 8B 44 24 2C 8D
         71 02 03 D0 89 54 24 14 8B 54 24 10 33 C0 8A 44 37 FE 03 D6 8B D8 8D
         46 FF 0F AF DA 33 D2 BD 06 00 00 00 F7 F5 C1 EB 07 8A 04 3A 33 D2 32
         D8 8D 46 01 F7 F5 8A 44 24 30 02 C1 8A 0C 3A 33 D2 32 C8 8B C6 F7 F5
         8A 04 3A 22 C8 8B 44 24 14 02 D9 8A 0C 30 32 CB 88 0C 30 8B 4C 24 38
         41 46 83 FE 08 89 4C 24 38 72 A1 8B 5C 24 18 8B 6C 24 1C 8B 74 24 20
         8B 4C 24 10 43 83 C1 06 3B DE 89 4C 24 10 8B 4C 24 34 89 5C 24 18 0F
         82 3C FF FF FF 3B DD 75 1A 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B CA EB
         0D 33 C9 89 4C 24 38 E9 40 FF FF FF 33 C9 8B 44 24 24 33 D2 BE 06 00
         00 00 89 4C 24 38 F7 F6 3B CA 89 54 24 24 0F 83 95 00 00 00 8A C3 B2
         06 F6 EA 8D 1C 5B 88 44 24 30 8B 44 24 2C 8D 71 02 D1 E3 89 5C 24 34
         8D 54 03 FE 89 54 24 14 EB 04 8B 5C 24 34 33 C0 BD 06 00 00 00 8A 44
         3E FE 8B D0 8D 44 1E FE 0F AF D0 C1 EA 07 89 54 24 2C 8D 46 FF 33 D2
         BB 06 00 00 00 F7 F3 8B 5C 24 2C 8A 04 3A 33 D2 32 D8 8D 46 01 F7 F5
         8A 44 24 30 02 C1 8A 0C 3A 33 D2 32 C8 8B C6 F7 F5 8A 04 3A 22 C8 8B
         44 24 14 02 D9 8A 0C 06 32 CB 88 0C 06 8B 4C 24 38 8B 44 24 24 41 46
         3B C8 89 4C 24 38 72 8F 5F 5E 5D 5B 83 C4 18 C2 10 00 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_6_v6 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $Init1_fun = {68 10 27 00 00 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 6A FF 50
         FF 15 ?? ?? ?? ?? 33 C0 C3}
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_6_v7 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "Init1"
      $OPT1 = "ServiceMain"
      $OPT2 = "netids" nocase wide ascii
      $OPT3 = "netui" nocase wide ascii
      $OPT4 = "svchost.exe" wide ascii
      $OPT5 = "network" nocase wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $STR1 and 2 of ($OPT*)
}

*/

rule IMPLANT_7_v1 {
   meta:
      description = "Implant 7 by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8A 44 0A 03 32 C3 0F B6 C0 66 89 04 4E 41 3B CF 72 EE }
      $STR2 = { F3 0F 6F 04 08 66 0F EF C1 F3 0F 7F 04 11 83 C1 10 3B CF 72 EB }
   condition:
      (uint16(0) == 0x5A4D) and ($STR1 or $STR2)
}

rule IMPLANT_8_v1
{
   meta:
      description = "HAMMERTOSS / HammerDuke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DOTNET = "mscorlib" ascii
      $REF_URL = "https://www.google.com/url?sa=" wide
      $REF_var_1 = "&rct=" wide
      $REF_var_2 = "&q=&esrc=" wide
      $REF_var_3 = "&source=" wide
      $REF_var_4 = "&cd=" wide
      $REF_var_5 = "&ved=" wide
      $REF_var_6 = "&url=" wide
      $REF_var_7 = "&ei=" wide
      $REF_var_8 = "&usg=" wide
      $REF_var_9 = "&bvm=" wide
      $REF_value_1 = "QFj" wide
      $REF_value_2 = "bv.81" wide
   condition:
      (uint16(0) == 0x5A4D) and ($DOTNET) and ($REF_URL) and
      (3 of ($REF_var*)) and (1 of ($REF_value*))
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_8_v2 {
   meta:
      description = "HAMMERTOSS / HammerDuke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DOTNET= "mscorlib" ascii
      $XOR = {61 20 AA 00 00 00 61}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

*/

rule IMPLANT_9_v1 {
   meta:
      description = "Onion Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = { 8B 03 8A 54 01 03 32 55 FF 41 88 54 39 FF 3B CE 72 EE }
      $STR2 = { 8B C8 83 E1 03 8A 54 19 08 8B 4D 08 32 54 01 04 40 88 54 38 FF
         3B C6 72 E7 }
      $STR3 = { 8B 55 F8 8B C8 83 E1 03 8A 4C 11 08 8B 55 FC 32 0C 10 8B 17 88
         4C 02 04 40 3B 06 72 E3 }
   condition:
      (uint16(0) == 0x5A4D or uint16(0)) and all of them
}

/* TOO MANY FALSE POSITIVES

rule IMPLANT_10_v1 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {33 ?? 83 F2 ?? 81 E2 FF 00 00 00}
      $STR2 = {0F BE 14 01 33 D0 ?? F2 [1-4] 81 E2 FF 00 00 00 66 89 [6] 40 83
         F8 ?? 72}
   condition:
      uint16(0) == 0x5A4D and ($STR1 or $STR2)
}

*/

rule IMPLANT_10_v2 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $xor = { 34 ?? 66 33 C1 48 FF C1 }
      $nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00}
   condition:
      uint16(0) == 0x5A4D and $xor and $nop
}

/* Deactivated - Slowing down scanning

rule IMPLANT_11_v12 {
   meta:
      description = "Mini Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {63 74 00 00} // ct
      $STR2 = {72 6F 74 65} // rote
      $STR3 = {75 61 6C 50} // triV
      $STR4 = {56 69 72 74} // Plau
      $STR5 = { e8 00 00 00 00 }
      $STR6 = { 64 FF 35 00 00 00 00 }
      $STR7 = {D2 C0}
      $STR8 = /\x63\x74\x00\x00.{3,20}\x72\x6F\x74\x65.{3,20}\x75\x61\x6C\x50.{3,20}\x56\x69\x72\x74/
   condition:
      (uint16(0) == 0x5A4D) and #STR5 > 4 and all of them
}

rule IMPLANT_12_v1 {
   meta:
      description = "Cosmic Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $FUNC = {A1 [3-5] 33 C5 89 [2-3] 56 57 83 [4-6] 64}
   condition:
      (uint16(0) == 0x5A4D) and $FUNC
}

*/

rule Unidentified_Malware_Two {
   meta:
      description = "Unidentified Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $my_string_one = "/zapoy/gate.php"
      $my_string_two = { E3 40 FE 45 FD 0F B6 45 FD 0F B6 14 38 88 55 FF 00 55
         FC 0F B6 45 FC 8A 14 38 88 55 FE 0F B6 45 FD 88 14 38 0F B6 45 FC 8A
         55 FF 88 14 38 8A 55 FF 02 55 FE 8A 14 3A 8B 45 F8 30 14 30 }
      $my_string_three = "S:\\Lidstone\\renewing\\HA\\disable\\In.pdb"
      $my_string_four = { 8B CF 0F AF CE 8B C6 99 2B C2 8B 55 08 D1 F8 03 C8
         8B 45 FC 03 C2 89 45 10 8A 00 2B CB 32 C1 85 DB 74 07 }
      $my_string_five = "fuckyou1"
      $my_string_six = "xtool.exe"
   condition:
      ($my_string_one and $my_string_two)
      or ($my_string_three or $my_string_four)
      or ($my_string_five and $my_string_six)
}

rule bin_ndisk  
{
    
    meta:
        description = "Hacking Team Disclosure Sample - file ndisk.sys"
        author = "Florian Roth"
        reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
        date = "2015-07-07"
        hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
    
    strings:
        $s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide
        $s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide
        $s3 = "\\Driver\\DeepFrz" fullword wide
        $s4 = "Microsoft Kernel Disk Manager" fullword wide
        $s5 = "ndisk.sys" fullword wide
        $s6 = "\\Device\\MSH4DEV1" fullword wide
        $s7 = "\\DosDevices\\MSH4DEV1" fullword wide
        $s8 = "built by: WinDDK" fullword wide
    
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}

rule Hackingteam_Elevator_DLL 
{

    meta:
        description = "Hacking Team Disclosure Sample - file elevator.dll"
        author = "Florian Roth"
        reference = "http://t.co/EG0qtVcKLh"
        date = "2015-07-07"
        hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"
   
    strings:
        $s1 = "\\sysnative\\CI.dll" fullword ascii
        $s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii
        $s3 = "mitmproxy0" fullword ascii
        $s4 = "\\insert_cert.exe" fullword ascii
        $s5 = "elevator.dll" fullword ascii
        $s6 = "CRTDLL.DLL" fullword ascii
        $s7 = "fail adding cert" fullword ascii
        $s8 = "DownloadingFile" fullword ascii
        $s9 = "fail adding cert: %s" fullword ascii
        $s10 = "InternetOpenA fail" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 6 of them
}

rule HackingTeam_Elevator_EXE 
{

    meta:
        description = "Hacking Team Disclosure Sample - file elevator.exe"
        author = "Florian Roth"
        reference = "Hacking Team Disclosure elevator.c"
        date = "2015-07-07"
        hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
        hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"
        hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"

    strings:
        $x1 = "CRTDLL.DLL" fullword ascii
        $x2 = "\\sysnative\\CI.dll" fullword ascii
        $x3 = "\\SystemRoot\\system32\\CI.dll" fullword ascii
        $x4 = "C:\\\\Windows\\\\Sysnative\\\\ntoskrnl.exe" fullword ascii /* PEStudio Blacklist: strings */
        $s1 = "[*] traversing processes" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "_getkprocess" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "[*] LoaderConfig %p" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "loader.obj" fullword ascii /* PEStudio Blacklist: strings */
        $s5 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii /* PEStudio Blacklist: strings */
        $s6 = "[*] token restore" fullword ascii /* PEStudio Blacklist: strings */
        $s7 = "elevator.obj" fullword ascii
        $s8 = "_getexport" fullword ascii /* PEStudio Blacklist: strings */
   
    condition:
        uint16(0) == 0x5a4d and filesize < 3000KB and all of ($x*) and 3 of ($s*)
}

rule RCS_Backdoor
{
    
    meta:
        description = "Hacking Team RCS Backdoor"
        author = "botherder https://github.com/botherder"

    strings:
        $filter1 = "$debug3"
        $filter2 = "$log2"
        $filter3 = "error2"
        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii
        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii
        // Cause false positives.
        //$log3 = /\- About to call init routine at %p/ wide ascii
        //$log4 = /\- Calling init routine at %p/ wide ascii
        $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        (2 of ($debug*) or 2 of ($log*) or all of ($error*)) and not any of ($filter*)
}

rule RCS_Scout
{
    
    meta:
        description = "Hacking Team RCS Scout"
        author = "botherder https://github.com/botherder"

    strings:
        $filter1 = "$engine5"
        $filter2 = "$start4"
        $filter3 = "$upd2"
        $filter4 = "$lookma6"

        $engine1 = /(E)ngine started/ wide ascii
        $engine2 = /(R)unning in background/ wide ascii
        $engine3 = /(L)ocking doors/ wide ascii
        $engine4 = /(R)otors engaged/ wide ascii
        $engine5 = /(I)\'m going to start it/ wide ascii

        $start1 = /Starting upgrade\!/ wide ascii
        $start2 = /(I)\'m going to start the program/ wide ascii
        $start3 = /(i)s it ok\?/ wide ascii
        $start4 = /(C)lick to start the program/ wide ascii

        $upd1 = /(U)pdJob/ wide ascii
        $upd2 = /(U)pdTimer/ wide ascii

        $lookma1 = /(O)wning PCI bus/ wide
        $lookma2 = /(F)ormatting bios/ wide
        $lookma3 = /(P)lease insert a disk in drive A:/ wide
        $lookma4 = /(U)pdating CPU microcode/ wide
        $lookma5 = /(N)ot sure what's happening/ wide
        $lookma6 = /(L)ook ma, no thread id\! \\\\o\// wide

    condition:
        (all of ($engine*) or all of ($start*) or all of ($upd*) or 4 of ($lookma*)) and not any of ($filter*)
}



rule apt_hellsing_implantstrings
{ 
  
    meta:
        Author = "Costin Raiu, Kaspersky Lab"
        Date = "2015-04-07"
        Description = "detection for Hellsing implants"
        Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

    strings: 
        $mz="MZ"
        $a1="the file uploaded failed !" 
        $a2="ping 127.0.0.1"      
        $b1="the file downloaded failed !" 
        $b2="common.asp"
        $c="xweber_server.exe" 
        $d="action="
        $debugpath1="d:\\Hellsing\\release\\msger\\" nocase 
        $debugpath2="d:\\hellsing\\sys\\xrat\\" nocase 
        $debugpath3="D:\\Hellsing\\release\\exe\\" nocase 
        $debugpath4="d:\\hellsing\\sys\\xkat\\" nocase 
        $debugpath5="e:\\Hellsing\\release\\clare" nocase 
        $debugpath6="e:\\Hellsing\\release\\irene\\" nocase 
        $debugpath7="d:\\hellsing\\sys\\irene\\" nocase
        $e="msger_server.dll"
        $f="ServiceMain"

    condition:
        ($mz at 0) and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}

rule apt_hellsing_installer
{
    
    meta:
        Author = "Costin Raiu, Kaspersky Lab"
        Date = "2015-04-07"
        Description = "detection for Hellsing xweber/msger installers"
        Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back" 

    strings: 
        $mz="MZ"
        $cmd="cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
        $a1="xweber_install_uac.exe"
        $a2="system32\\cmd.exe" wide
        $a4="S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y=" 
        $a5="S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg=" $a6="7dqm2ODf5N/Y2N/m6+br3dnZpunl44g="
        $a7="vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw==" 
        $a8="vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSI Njl2tyI" $a9="C:\\Windows\\System32\\sysprep\\sysprep.exe" wide 
        $a10="%SystemRoot%\\system32\\cmd.exe" wide 
        $a11="msger_install.dll"
        $a12={00 65 78 2E 64 6C 6C 00}

    condition:
        ($mz at 0) and ($cmd and (2 of ($a*))) and filesize < 500000
}

rule apt_hellsing_proxytool
{
    
    meta:
        Author = "Costin Raiu, Kaspersky Lab"
        Date = "2015-04-07"
        Description = "detection for Hellsing proxy testing tool"
        Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back" 

    strings: 
        $mz="MZ"
        $a1="PROXY_INFO: automatic proxy url => %s " 
        $a2="PROXY_INFO: connection type => %d " 
        $a3="PROXY_INFO: proxy server => %s " 
        $a4="PROXY_INFO: bypass list => %s " 
        $a5="InternetQueryOption failed with GetLastError() %d" 
        $a6="D:\\Hellsing\\release\\exe\\exe\\" nocase

    condition:
        ($mz at 0) and (2 of ($a*)) and filesize < 300000
}

rule apt_hellsing_xkat 
{
    
    meta:
        Author = "Costin Raiu, Kaspersky Lab"
        Date = "2015-04-07"
        Description = "detection for Hellsing xKat tool"
        Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

    strings:
        $mz="MZ"
        $a1="\\Dbgv.sys"
        $a2="XKAT_BIN"
        $a3="release sys file error."
        $a4="driver_load error. "
        $a5="driver_create error."
        $a6="delete file:%s error."
        $a7="delete file:%s ok."
        $a8="kill pid:%d error."
        $a9="kill pid:%d ok."
        $a10="-pid-delete"
        $a11="kill and delete pid:%d error."
        $a12="kill and delete pid:%d ok."

    condition:
        ($mz at 0) and (6 of ($a*)) and filesize < 300000
}

rule apt_hellsing_msgertype2
{
    
    meta:
        Author = "Costin Raiu, Kaspersky Lab"
        Date = "2015-04-07"
        Description = "detection for Hellsing msger type 2 implants"
        Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

    strings:
        $mz="MZ"
        $a1="%s\\system\\%d.txt"
        $a2="_msger"
        $a3="http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
        $a4="http://%s/data/%s.1000001000"
        $a5="/lib/common.asp?action=user_upload&file="
        $a6="%02X-%02X-%02X-%02X-%02X-%02X"
    
    condition:
        ($mz at 0) and (4 of ($a*)) and filesize < 500000
}

rule apt_hellsing_irene
{
    
    meta:
        Author = "Costin Raiu, Kaspersky Lab"
        Date = "2015-04-07"
        Description = "detection for Hellsing msger irene installer"
        Reference = "http://securelist.com/analysis/publications/69567/the-chronicles-of-the-hellsing-apt-the-empire-strikes-back"

    strings: 
        $mz="MZ"
        $a1="\\Drivers\\usbmgr.tmp" wide
        $a2="\\Drivers\\usbmgr.sys" wide
        $a3="common_loadDriver CreateFile error! " 
        $a4="common_loadDriver StartService error && GetLastError():%d! " 
        $a5="irene" wide
        $a6="aPLib v0.43 - the smaller the better" 

    condition:
        ($mz at 0) and (4 of ($a*)) and filesize < 500000
}
rule apt_hiddencobra_rsakey {

meta:

	description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
	author = "US-CERT"
	url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

strings:

    $rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94

    A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77

    48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39

    73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2

    AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED

    39 3F FA D0 AD 3D D9 C5 3D 28 EF 3D 67 B1 E0 68

    3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13

    B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}

condition: 
	any of them
}


rule apt_hiddencobra_binaries {

meta:

    description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
    author = "US-CERT"
    url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

strings:

   $STR1 = "Wating" wide ascii

   $STR2 = "Reamin" wide ascii

   $STR3 = "laptos" wide ascii

condition: 
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and 2 of them
}


rule apt_hiddencobra_urlbuilder {

meta:

    description = "HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure" 
    author = "US-CERT"
    url = "https://www.us-cert.gov/ncas/alerts/TA17-164A"

strings:

$randomUrlBuilder = { 83 EC 48 53 55 56 57 8B 3D ?? ?? ?? ?? 33 C0 C7 44 24 28 B4 6F 41 00 C7 44 24 2C B0 6F 41 00 C7 44 24 30 AC 6F 41 00 C7 44 24 34 A8 6F 41 00 C7 44 24 38 A4 6F 41 00 C7 44 24 3C A0 6F 41 00 C7 44 24 40 9C 6F 41 00 C7 44 24 44 94 6F 41 00 C7 44 24 48 8C 6F 41 00 C7 44 24 4C 88 6F 41 00 C7 44 24 50 80 6F 41 00 89 44 24 54 C7 44 24 10 7C 6F 41 00 C7 44 24 14 78 6F 41 00 C7 44 24 18 74 6F 41 00 C7 44 24 1C 70 6F 41 00 C7 44 24 20 6C 6F 41 00 89 44 24 24 FF D7 99 B9 0B 00 00 00 F7 F9 8B 74 94 28 BA 9C 6F 41 00 66 8B 06 66 3B 02 74 34 8B FE 83 C9 FF 33 C0 8B 54 24 60 F2 AE 8B 6C 24 5C A1 ?? ?? ?? ?? F7 D1 49 89 45 00 8B FE 33 C0 8D 5C 11 05 83 C9 FF 03 DD F2 AE F7 D1 49 8B FE 8B D1 EB 78 FF D7 99 B9 05 00 00 00 8B 6C 24 5C F7 F9 83 C9 FF 33 C0 8B 74 94 10 8B 54 24 60 8B FE F2 AE F7 D1 49 BF 60 6F 41 00 8B D9 83 C9 FF F2 AE F7 D1 8B C2 49 03 C3 8B FE 8D 5C 01 05 8B 0D ?? ?? ?? ?? 89 4D 00 83 C9 FF 33 C0 03 DD F2 AE F7 D1 49 8D 7C 2A 05 8B D1 C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4 BF 60 6F 41 00 83 C9 FF F2 AE F7 D1 49 BE 60 6F 41 00 8B D1 8B FE 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FB 2B F9 8B CA 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7C 24 60 8D 75 04 57 56 E8 ?? ?? ?? ?? 83 C4 08 C6 04 3E 2E 8B C5 C6 03 00 5F 5E 5D 5B 83 C4 48 C3 }

condition: 
    $randomUrlBuilder
}


rule Malware_Updater
{
meta:
	Author="US-CERT Code Analysis Team"
	Date="2017/08/02"
	Incident="10132963"
	MD5_1="8F4FC2E10B6EC15A01E0AF24529040DD"
	MD5_2="584AC94142F0B7C0DF3D0ADDE6E661ED"
	Info="Malware may be used to update multiple systems with secondary payloads"
	super_rule=1
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10132963.pdf"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = { 8A4C040480F15D80C171884C04044083F8107CEC }
	$s1 = { 8A4D0080F19580E97C884D00454B75F0 }
condition: 
	any of them
} 

rule Unauthorized_Proxy_Server_RAT
{
meta:
	Author="US-CERT Code Analysis Team"
	Incident="10135536"
	MD5_1 = "C74E289AD927E81D2A1A56BC73E394AB"
	MD5_2 = "2950E3741D7AF69E0CA0C5013ABC4209"
	Info="Detects Proxy Server RAT"
	super_rule = 1
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-B_WHITE.PDF"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = {8A043132C288043125FF00000003C299F73D40404900A14440490003D0413BCF72DE5E5FC3}
	$s1 = {8A04318844241432C28804318B44241425FF00000003C299F73D40404900A14440490003D0413BCF72D65E5FC3}
	$s2 = {8A04318844241432C28804318B44241425FF00000003C299F73D5C394100A16039410003D0413BCF72D65E5FC3}
	$s3 = {8A043132C288043125FF00000003C299F73D5C394100A16039410003D0413BCF72DE5E5FC3}
	$s4 = {B91A7900008A140780F29A8810404975F4}
	$s5 = {399FE192769F839DCE9F2A9D2C9EAD9CEB9FD19CA59F7E9F539CEF9F029F969C6C9E5C9D949FC99F}
	$s6 = {8A04318844241432C28804318B44241425FF00000003C299F73D40600910A14460091003D0413BCF72D65E5FC3}
	$s7 = {3C5C75208A41014184C074183C72740C3C7474083C6274043C2275088A41014184C075DC}
	$s8 = {8B063D9534120077353D59341200722E668B4604663DE8037F24}
	$s9 = {8BC88B74241CC1E1052BC88B7C2418C1E1048B5C241403C88D04888B4C242083F9018944240C7523}
	$s10 = {8B063D9034120077353D59341200722E668B4604663DE8037F246685C0}
	$s11 = {30110FB60148FFC102C20FBEC09941F7F94103D249FFC875E7}
	$s12 = {448BE8B84FECC44E41F7EDC1FA038BCAC1E91F03D16BD21A442BEA4183C541}
	$s13 = {8A0A80F9627C2380F9797F1E80F9647C0A80F96D7F0580C10BEB0D80F96F7C0A80F9787F05}
condition:
	any of them
} 

rule NK_SSL_PROXY{
meta:
	Author = "US-CERT Code Analysis Team"
	Date = "2018/01/09"
	MD5_1 = "C6F78AD187C365D117CACBEE140F6230"
	MD5_2 = "C01DC42F65ACAF1C917C0CC29BA63ADC"
	Info= "Detects NK SSL PROXY"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = {8B4C24088A140880F24780C228881408403BC67CEF5E}
	$s1 = {568B74240C33C085F67E158B4C24088A140880EA2880F247881408403BC67CEF5E}
	$s2 = {4775401F713435747975366867766869375E2524736466}
	$s3 = {67686667686A75797566676467667472}
	$s4 = {6D2A5E265E676866676534776572}
	$s5 = {3171617A5853444332337765}
	$s6 = "ghfghjuyufgdgftr"
	$s7 = "q45tyu6hgvhi7^%$sdf"
	$s8 = "m*^&^ghfge4wer"
condition:
	($s0 and $s1 and $s2 and $s3 and $s4 and $s5) or ($s6 and $s7 and $s8)
} 

rule r4_wiper_1
{
meta:
	source = "NCCIC Partner"
	date = "2017-12-12"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$mbr_code = { 33 C0 8E D0 BC 00 7C FB 50 07 50 1F FC BE 5D 7C 33 C9 41 81 F9 00 ?? 74 24 B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 83 55 06 00 EB D5 BE 4D 7C B4 43 B0 00 CD 13 33 C9 BE 5D 7C EB C5 }
	$controlServiceFoundlnBoth = { 83 EC 1C 57 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 44 8B 44 24 24 53 56 6A 24 50 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 1C 8D 4C 24 0C 51 6A 01 56 FF 15 ?? ?? ?? ?? 68 E8 03 00 00 FF 15 ?? ?? ?? ?? 56 FF D3 57 FF D3 5E 5B 33 C0 5F 83 C4 1C C3 33 C0 5F 83 C4 1C C3 }
condition:
	uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and any of them
}

rule r4_wiper_2
{
meta:
	source = "NCCIC Partner"
	date = "2017-12-12"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	// BIOS Extended Write
	$PhysicalDriveSTR = "\\\\.\\PhysicalDrive" wide
	$ExtendedWrite = { B4 43 B0 00 CD 13 }
condition:
	uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and all of them
}

rule APT_Hikit_msrv
{

meta:
    author = "ThreatConnect Intelligence Research Team"

strings:
    $m = {6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}

condition:
    any of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-13
   Identifier: Industroyer
   Reference: https://goo.gl/x81cSy
*/

/* Rule Set ----------------------------------------------------------------- */

rule Industroyer_Malware_1 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "ad23c7930dae02de1ea3c6836091b5fb3c62a89bf2bcfb83b4b39ede15904910"
      hash2 = "018eb62e174efdcdb3af011d34b0bf2284ed1a803718fba6edffe5bc0b446b81"
   strings:
      $s1 = "haslo.exe" fullword ascii
      $s2 = "SYSTEM\\CurrentControlSet\\Services\\%ls" fullword wide
      $s3 = "SYS_BASCON.COM" fullword wide
      $s4 = "*.pcmt" fullword wide
      $s5 = "*.pcmi" fullword wide

      $x1 = { 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73
         00 5C 00 25 00 6C 00 73 00 00 00 49 00 6D 00 61
         00 67 00 65 00 50 00 61 00 74 00 68 00 00 00 43
         00 3A 00 5C 00 00 00 44 00 3A 00 5C 00 00 00 45
         00 3A 00 5C 00 00 00 }
      $x2 = "haslo.dat\x00Crash"
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) or 2 of them )
}

rule Industroyer_Malware_2 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "3e3ab9674142dec46ce389e9e759b6484e847f5c1e1fc682fc638fc837c13571"
      hash2 = "37d54e3d5e8b838f366b9c202f75fa264611a12444e62ae759c31a0d041aa6e4"
      hash3 = "ecaf150e087ddff0ec6463c92f7f6cca23cc4fd30fe34c10b3cb7c2a6d135c77"
      hash1 = "6d707e647427f1ff4a7a9420188a8831f433ad8c5325dc8b8cc6fc5e7f1f6f47"
   strings:
      $x1 = "sc create %ls type= own start= auto error= ignore binpath= \"%ls\" displayname= \"%ls\"" fullword wide
      $x2 = "10.15.1.69:3128" fullword wide

      $s1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" fullword wide
      $s2 = "/c sc stop %s" fullword wide
      $s3 = "sc start %ls" fullword wide
      $s4 = "93.115.27.57" fullword wide
      $s5 = "5.39.218.152" fullword wide
      $s6 = "tierexe" fullword wide
      $s7 = "comsys" fullword wide
      $s8 = "195.16.88.6" fullword wide
      $s9 = "TieringService" fullword wide

      $a1 = "TEMP\x00\x00DEF" fullword wide
      $a2 = "TEMP\x00\x00DEF-C" fullword wide
      $a3 = "TEMP\x00\x00DEF-WS" fullword wide
      $a4 = "TEMP\x00\x00DEF-EP" fullword wide
      $a5 = "TEMP\x00\x00DC-2-TEMP" fullword wide
      $a6 = "TEMP\x00\x00DC-2" fullword wide
      $a7 = "TEMP\x00\x00CES-McA-TEMP" fullword wide
      $a8 = "TEMP\x00\x00SRV_WSUS" fullword wide
      $a9 = "TEMP\x00\x00SRV_DC-2" fullword wide
      $a10 = "TEMP\x00\x00SCE-WSUS01" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) or 3 of them or 1 of ($a*) ) or ( 5 of them )
}

rule Industroyer_Portscan_3 {
   meta:
      description = "Detects Industroyer related custom port scaner"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "893e4cca7fe58191d2f6722b383b5e8009d3885b5913dcd2e3577e5a763cdb3f"
   strings:
      $s1 = "!ZBfamily" fullword ascii
      $s2 = ":g/outddomo;" fullword ascii
      $s3 = "GHIJKLMNOTST" fullword ascii
      /* Decompressed File */
      $d1 = "Error params Arguments!!!" fullword wide
      $d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
      $d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
      $d4 = "Error IP Range %ls - %ls" fullword wide
      $d5 = "Can't closesocket." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) or 2 of ($d*) )
}

rule Industroyer_Portscan_3_Output {
   meta:
      description = "Detects Industroyer related custom port scaner output file"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
   strings:
      $s1 = "WSA library load complite." fullword ascii
      $s2 = "Connection refused" fullword ascii
   condition:
      all of them
}

rule Industroyer_Malware_4 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "21c1fdd6cfd8ec3ffe3e922f944424b543643dbdab99fa731556f8805b0d5561"
   strings:
      $s1 = "haslo.dat" fullword wide
      $s2 = "defragsvc" fullword ascii

      /* .dat\x00\x00Crash */
      $a1 = { 00 2E 00 64 00 61 00 74 00 00 00 43 72 61 73 68 00 00 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or $a1 )
}

rule Industroyer_Malware_5 {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://goo.gl/x81cSy"
      date = "2017-06-13"
      hash1 = "7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad"
   strings:
      $x1 = "D2MultiCommService.exe" fullword ascii
      $x2 = "Crash104.dll" fullword ascii
      $x3 = "iec104.log" fullword ascii
      $x4 = "IEC-104 client: ip=%s; port=%s; ASDU=%u " fullword ascii

      $s1 = "Error while getaddrinfo executing: %d" fullword ascii
      $s2 = "return info-Remote command" fullword ascii
      $s3 = "Error killing process ..." fullword ascii
      $s4 = "stop_comm_service_name" fullword ascii
      $s5 = "*1* Data exchange: Send: %d (%s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( 1 of ($x*) or 4 of them ) ) or ( all of them )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule IronTiger_ASPXSpy
{
    
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "ASPXSpy detection. It might be used by other fraudsters"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "ASPXSpy" nocase wide ascii
        $str2 = "IIS Spy" nocase wide ascii
        $str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
    
    condition:
        any of ($str*)
}

rule IronTiger_ChangePort_Toolkit_driversinstall 
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Changeport Toolkit driverinstall"   
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "openmydoor" nocase wide ascii
        $str2 = "Install service error" nocase wide ascii
        $str3 = "start remove service" nocase wide ascii
        $str4 = "NdisVersion" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ChangePort_Toolkit_ChangePortExe 
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Toolkit ChangePort"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "Unable to alloc the adapter!" nocase wide ascii
        $str2 = "Wait for master fuck" nocase wide ascii
        $str3 = "xx.exe <HOST> <PORT>" nocase wide ascii
        $str4 = "chkroot2007" nocase wide ascii
        $str5 = "Door is bind on %s" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_dllshellexc2010 
{
    
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "dllshellexc2010 Exchange backdoor + remote shell"
        reference = "http://goo.gl/T5fSJC"
    
    strings:
        $str1 = "Microsoft.Exchange.Clients.Auth.dll" nocase ascii wide
        $str2 = "Dllshellexc2010" nocase wide ascii
        $str3 = "Users\\ljw\\Documents" nocase wide ascii
        $bla1 = "please input path" nocase wide ascii
        $bla2 = "auth.owa" nocase wide ascii
    
    condition:
        (uint16(0) == 0x5a4d) and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_dnstunnel 
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "\\DnsTunClient\\" nocase wide ascii
        $str2 = "\\t-DNSTunnel\\" nocase wide ascii
        $str3 = "xssok.blogspot" nocase wide ascii
        $str4 = "dnstunclient" nocase wide ascii
        $mistake1 = "because of error, can not analysis" nocase wide ascii
        $mistake2 = "can not deal witn the error" nocase wide ascii
        $mistake3 = "the other retun one RST" nocase wide ascii
        $mistake4 = "Coversation produce one error" nocase wide ascii
        $mistake5 = "Program try to use the have deleted the buffer" nocase wide ascii
    
    condition:
        (uint16(0) == 0x5a4d) and ((any of ($str*)) or (any of ($mistake*)))
}

rule IronTiger_EFH3_encoder 
{
  
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger EFH3 Encoder"
        reference = "http://goo.gl/T5fSJC"
  
    strings:
        $str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" nocase wide ascii
        $str2 = "123.EXE 123.EFH" nocase wide ascii
        $str3 = "ENCODER: b[i]: = " nocase wide ascii
  
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_GetPassword_x64
{
  
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - GetPassword x64"
        reference = "http://goo.gl/T5fSJC"
  
    strings:
        $str1 = "(LUID ERROR)" nocase wide ascii
        $str2 = "Users\\K8team\\Desktop\\GetPassword" nocase wide ascii
        $str3 = "Debug x64\\GetPassword.pdb" nocase wide ascii
        $bla1 = "Authentication Package:" nocase wide ascii
        $bla2 = "Authentication Domain:" nocase wide ascii
        $bla3 = "* Password:" nocase wide ascii
        $bla4 = "Primary User:" nocase wide ascii
  
    condition:
        uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_GetUserInfo
{
    
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - GetUserInfo"
        reference = "http://goo.gl/T5fSJC"
    
    strings:
        $str1 = "getuserinfo username" nocase wide ascii
        $str2 = "joe@joeware.net" nocase wide ascii
        $str3 = "If . specified for userid," nocase wide ascii
    
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_Gh0stRAT_variant
{
  
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
        reference = "http://goo.gl/T5fSJC"
  
    strings:
        $str1 = "Game Over Good Luck By Wind" nocase wide ascii
        $str2 = "ReleiceName" nocase wide ascii
        $str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
        $str4 = "Winds Update" nocase wide ascii
  
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_GTalk_Trojan 
{
  
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - GTalk Trojan"
        reference = "http://goo.gl/T5fSJC"
  
    strings:
        $str1 = "gtalklite.com" nocase wide ascii
        $str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" nocase wide ascii
        $str3 = "D13idmAdm" nocase wide ascii
        $str4 = "Error: PeekNamedPipe failed with %i" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTPBrowser_Dropper 
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - HTTPBrowser Dropper"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = ".dllUT" nocase wide ascii
        $str2 = ".exeUT" nocase wide ascii
        $str3 = ".urlUT" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTP_SOCKS_Proxy_soexe
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "listen SOCKET error." nocase wide ascii
        $str2 = "WSAAsyncSelect SOCKET error." nocase wide ascii
        $str3 = "new SOCKETINFO error!" nocase wide ascii
        $str4 = "Http/1.1 403 Forbidden" nocase wide ascii
        $str5 = "Create SOCKET error." nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (3 of ($str*))
}

rule IronTiger_NBDDos_Gh0stvariant_dropper
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "This service can't be stoped." nocase wide ascii
        $str2 = "Provides support for media palyer" nocase wide ascii
        $str4 = "CreaetProcess Error" nocase wide ascii
        $bla1 = "Kill You" nocase wide ascii
        $bla2 = "%4.2f GB" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_PlugX_DosEmulator
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - PlugX DosEmulator"  
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "Dos Emluator Ver" nocase wide ascii
        $str2 = "\\PIPE\\FASTDOS" nocase wide ascii
        $str3 = "FastDos.cpp" nocase wide ascii
        $str4 = "fail,error code = %d." nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_FastProxy
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - PlugX FastProxy"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "SAFEPROXY HTServerTimer Quit!" nocase wide ascii
        $str2 = "Useage: %s pid" nocase wide ascii
        $str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" nocase wide ascii
        $str4 = "p0: port for listener" nocase wide ascii
        $str5 = "\\users\\whg\\desktop\\plug\\" nocase wide ascii
        $str6 = "[+Y] cwnd : %3d, fligth:" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_Server
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - PlugX Server"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "\\UnitFrmManagerKeyLog.pas" nocase wide ascii
        $str2 = "\\UnitFrmManagerRegister.pas" nocase wide ascii
        $str3 = "Input Name..." nocase wide ascii
        $str4 = "New Value#" nocase wide ascii
        $str5 = "TThreadRControl.Execute SEH!!!" nocase wide ascii
        $str6 = "\\UnitFrmRControl.pas" nocase wide ascii
        $str7 = "OnSocket(event is error)!" nocase wide ascii
        $str8 = "Make 3F Version Ok!!!" nocase wide ascii
        $str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" nocase wide ascii
        $str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ReadPWD86
{
   
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - ReadPWD86"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "Fail To Load LSASRV" nocase wide ascii
        $str2 = "Fail To Search LSASS Data" nocase wide ascii
        $str3 = "User Principal" nocase wide ascii
   
    condition:
        uint16(0) == 0x5a4d and (all of ($str*))
}

rule IronTiger_Ring_Gh0stvariant
{
  
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Ring Gh0stvariant"
        reference = "http://goo.gl/T5fSJC"
  
    strings:
        $str1 = "RING RAT Exception" nocase wide ascii
        $str2 = "(can not update server recently)!" nocase wide ascii
        $str4 = "CreaetProcess Error" nocase wide ascii
        $bla1 = "Sucess!" nocase wide ascii
        $bla2 = "user canceled!" nocase wide ascii
  
    condition:
        uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_wmiexec
{
  
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Tool - wmi.vbs detection"
        reference = "http://goo.gl/T5fSJC"
  
    strings:
        $str1 = "Temp Result File , Change it to where you like" nocase wide ascii
        $str2 = "wmiexec" nocase wide ascii
        $str3 = "By. Twi1ight" nocase wide ascii
        $str4 = "[both mode] ,delay TIME to read result" nocase wide ascii
        $str5 = "such as nc.exe or Trojan" nocase wide ascii
        $str6 = "+++shell mode+++" nocase wide ascii
        $str7 = "win2008 fso has no privilege to delete file" nocase wide ascii
  
    condition:
        2 of ($str*)
}
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-09-16
    Identifier: Iron Panda
*/

/* Rule Set ----------------------------------------------------------------- */

rule IronPanda_DNSTunClient 
{

    meta:
        description = "Iron Panda malware DnsTunClient - file named.exe"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        score = 80
        hash = "a08db49e198068709b7e52f16d00a10d72b4d26562c0d82b4544f8b0fb259431"

    strings:
        $s1 = "dnstunclient -d or -domain <domain>" fullword ascii
        $s2 = "dnstunclient -ip <server ip address>" fullword ascii
        $s3 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"\\Microsoft\\Windows\\PLA\\System\\Microsoft Windows\" /tr " fullword ascii
        $s4 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"Microsoft Windows\" /tr " fullword ascii
        $s5 = "taskkill /im conime.exe" fullword ascii
        $s6 = "\\dns control\\t-DNSTunnel\\DnsTunClient\\DnsTunClient.cpp" fullword ascii
        $s7 = "UDP error:can not bing the port(if there is unclosed the bind process?)" fullword ascii
        $s8 = "use error domain,set domain pls use -d or -domain mark(Current: %s,recv %s)" fullword ascii
        $s9 = "error: packet num error.the connection have condurt,pls try later" fullword ascii
        $s10 = "Coversation produce one error:%s,coversation fail" fullword ascii
        $s11 = "try to add many same pipe to select group(or mark is too easy)." fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 400KB and 2 of them ) or 5 of them
}

rule IronPanda_Malware1 
{

    meta:
        description = "Iron Panda Malware"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "a0cee5822ddf254c254a5a0b7372c9d2b46b088a254a1208cb32f5fe7eca848a"

    strings:
        $x1 = "activedsimp.dll" fullword wide
        $s1 = "get_BadLoginAddress" fullword ascii
        $s2 = "get_LastFailedLogin" fullword ascii
        $s3 = "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" fullword ascii
        $s4 = "get_PasswordExpirationDate" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule IronPanda_Webshell_JSP 
{

    meta:
        description = "Iron Panda Malware JSP"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"
  
    strings:
        $s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
        $s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
        $s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii
  
    condition:
        filesize < 330KB and 1 of them
}

rule IronPanda_Malware_Htran 
{

    meta:
        description = "Iron Panda Malware Htran"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "7903f94730a8508e9b272b3b56899b49736740cea5037ea7dbb4e690bcaf00e7"
   
    strings:
        $s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
        $s2 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
        $s3 = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s4 = "[-] ERROR: Must supply logfile name." fullword ascii
        $s5 = "[SERVER]connection to %s:%d error" fullword ascii
        $s6 = "[+] Make a Connection to %s:%d...." fullword ascii
        $s7 = "[+] Waiting another Client on port:%d...." fullword ascii
        $s8 = "[+] Accept a Client on port %d from %s" fullword ascii
        $s9 = "[+] Make a Connection to %s:%d ......" fullword ascii
        $s10 = "cmshared_get_ptr_from_atom" fullword ascii
        $s11 = "_cmshared_get_ptr_from_atom" fullword ascii
        $s12 = "[+] OK! I Closed The Two Socket." fullword ascii
        $s13 = "[-] TransmitPort invalid." fullword ascii
        $s14 = "[+] Waiting for Client on port:%d ......" fullword ascii
   
    condition:
         ( uint16(0) == 0x5a4d and filesize < 125KB and 3 of them ) or 5 of them
}

rule IronPanda_Malware2 
{

    meta:
        description = "Iron Panda Malware"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "a89c21dd608c51c4bf0323d640f816e464578510389f9edcf04cd34090decc91"

    strings:
        $s0 = "\\setup.exe" fullword ascii
        $s1 = "msi.dll.urlUT" fullword ascii
        $s2 = "msi.dllUT" fullword ascii
        $s3 = "setup.exeUT" fullword ascii
        $s4 = "/c del /q %s" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule IronPanda_Malware3 
{

    meta:
        description = "Iron Panda Malware"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "5cd2af844e718570ae7ba9773a9075738c0b3b75c65909437c43201ce596a742"

    strings:
        $s0 = "PluginDeflater.exe" fullword wide
        $s1 = ".Deflated" fullword wide
        $s2 = "PluginDeflater" fullword ascii
        $s3 = "DeflateStream" fullword ascii /* Goodware String - occured 1 times */
        $s4 = "CompressionMode" fullword ascii /* Goodware String - occured 4 times */
        $s5 = "System.IO.Compression" fullword ascii /* Goodware String - occured 6 times */

    condition:
        uint16(0) == 0x5a4d and filesize < 10KB and all of them
}

rule IronPanda_Malware4 
{

    meta:
        description = "Iron Panda Malware"
        author = "Florian Roth"
        reference = "https://goo.gl/E4qia9"
        date = "2015-09-16"
        hash = "0d6da946026154416f49df2283252d01ecfb0c41c27ef3bc79029483adc2240c"

    strings:
        $s0 = "TestPlugin.dll" fullword wide
        $s1 = "<a href='http://www.baidu.com'>aasd</a>" fullword wide
        $s2 = "Zcg.Test.AspxSpyPlugins" fullword ascii
        $s6 = "TestPlugin" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 10KB and all of them
}

rule rtf_Kaba_jDoe
{

meta:
    author = "@patrickrolsen"
    maltype = "APT.Kaba"
    filetype = "RTF"
    version = "0.1"
    description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
    date = "2013-12-10"

strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }

condition:
    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
}


rule TidePool_Malware
{

    meta:
        description = "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"
        author = "Florian Roth"
        reference = "http://goo.gl/m2CXWR"
        date = "2016-05-24"
        hash1 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
        hash2 = "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed"
        hash3 = "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18"
        hash4 = "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f"
        hash5 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"

    strings:
        $x1 = "Content-Disposition: form-data; name=\"m1.jpg\"" fullword ascii
        $x2 = "C:\\PROGRA~2\\IEHelper\\mshtml.dll" fullword wide
        $x3 = "C:\\DOCUME~1\\ALLUSE~1\\IEHelper\\mshtml.dll" fullword wide
        $x4 = "IEComDll.dat" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=----=_Part_%x" fullword wide
        $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $s3 = "network.proxy.socks_port\", " fullword ascii
    
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) ) ) or ( 4 of them )
}


rule KeyBoy_Dropper
{

    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:
        $1 = "I am Admin"
        $2 = "I am User"
        $3 = "Run install success!"
        $4 = "Service install success!"
        $5 = "Something Error!"
        $6 = "Not Configed, Exiting"

    condition:
        all of them
}

rule KeyBoy_Backdoor
{

    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:
        $1 = "$login$"
        $2 = "$sysinfo$"
        $3 = "$shell$"
        $4 = "$fileManager$"
        $5 = "$fileDownload$"
        $6 = "$fileUpload$"

    condition:
        all of them
}

/*
*
* This section of the rules are all specific to the new 2016
* KeyBoy sample targeting the Tibetan community. Other following
* sections capture file characteristics observed across multiple
* years of development.
*
*/

rule new_keyboy_export
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header //PE signature //The malware family seems to share many exports //but this is the new kid on the block.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and pe.exports("cfsUpdate")
}

rule new_keyboy_header_codes
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's header codes"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "*l*" wide fullword
        $s2 = "*a*" wide fullword
        $s3 = "*s*" wide fullword
        $s4 = "*d*" wide fullword
        $s5 = "*f*" wide fullword
        $s6 = "*g*" wide fullword
        $s7 = "*h*" wide fullword

    condition:
        //MZ header //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and all of them
}


/*
*
* This section of the rules are all broader and will hit on
* older KeyBoy samples and other samples possibly part of a
* a larger development effort.
*
*/

rule keyboy_commands
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's sent and received commands"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "Update" wide fullword
        $s2 = "UpdateAndRun" wide fullword
        $s3 = "Refresh" wide fullword
        $s4 = "OnLine" wide fullword
        $s5 = "Disconnect" wide fullword
        $s6 = "Pw_Error" wide fullword
        $s7 = "Pw_OK" wide fullword
        $s8 = "Sysinfo" wide fullword
        $s9 = "Download" wide fullword
        $s10 = "UploadFileOk" wide fullword
        $s11 = "RemoteRun" wide fullword
        $s12 = "FileManager" wide fullword

    condition:
        //MZ header //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and 6 of them
}

rule keyboy_errors
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the sample's shell error2 log statements"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are in ASCII pre-2015 and UNICODE in 2016
        $error = "Error2" ascii wide
        //2016 specific:
        $s1 = "Can't find [%s]!Check the file name and try again!" ascii wide
        $s2 = "Open [%s] error! %d" ascii wide
        $s3 = "The Size of [%s] is zero!" ascii wide
        $s4 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s5 = "UploadFile [%s] Error:Connect Server Failed!" ascii wide
        $s6 = "Receive [%s] Error(Recved[%d] != Send[%d])!" ascii wide
        $s7 = "Receive [%s] ok! Use %2.2f seconds, Average speed %2.2f k/s" ascii wide
        $s8 = "CreateThread UploadFile[%s] Error!" ascii wide
        //Pre-2016:
        $s9 = "Ready Download [%s] ok!" ascii wide
        $s10 = "Get ControlInfo from FileClient error!" ascii wide
        $s11 = "FileClient has a error!" ascii wide
        $s12 = "VirtualAlloc SendBuff Error(%d)" ascii wide
        $s13 = "ReadFile [%s] Error(%d)..." ascii wide
        $s14 = "ReadFile [%s] Data[Readed(%d) != FileSize(%d)] Error..." ascii wide
        $s15 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s16 = "RecvData MyRecv_Info Size Error!" ascii wide
        $s17 = "RecvData MyRecv_Info Tag Error!" ascii wide
        $s18 = "SendData szControlInfo_1 Error!" ascii wide
        $s19 = "SendData szControlInfo_3 Error!" ascii wide
        $s20 = "VirtualAlloc RecvBuff Error(%d)" ascii wide
        $s21 = "RecvData Error!" ascii wide
        $s22 = "WriteFile [%s} Error(%d)..." ascii wide

    condition:
        //MZ header  //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and $error and 3 of ($s*)
}


rule keyboy_systeminfo
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the system information format before sending to C2"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are ASCII pre-2015 and UNICODE in 2016
        $s1 = "SystemVersion:    %s" ascii wide
        $s2 = "Product  ID:      %s" ascii wide
        $s3 = "InstallPath:      %s" ascii wide
        $s4 = "InstallTime:      %d-%d-%d, %02d:%02d:%02d" ascii wide
        $s5 = "ResgisterGroup:   %s" ascii wide
        $s6 = "RegisterUser:     %s" ascii wide
        $s7 = "ComputerName:     %s" ascii wide
        $s8 = "WindowsDirectory: %s" ascii wide
        $s9 = "System Directory: %s" ascii wide
        $s10 = "Number of Processors:       %d" ascii wide
        $s11 = "CPU[%d]:  %s: %sMHz" ascii wide
        $s12 = "RAM:         %dMB Total, %dMB Free." ascii wide
        $s13 = "DisplayMode: %d x %d, %dHz, %dbit" ascii wide
        $s14 = "Uptime:      %d Days %02u:%02u:%02u" ascii wide

    condition:
        //MZ header //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and 7 of them
}


rule keyboy_related_exports
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header //PE signature //The malware family seems to share many exports //but this is the new kid on the block.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 200KB and pe.exports("Embedding") or pe.exports("SSSS") or pe.exports("GetUP")
}

// Note: The use of the .Init section has been observed in nearly
// all samples with the exception of the 2013 VN dropper from the
// Rapid7 blog. The config data was stored in that sample's .data
// section.

rule keyboy_init_config_section
{

    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the Init section where the config is stored"
        date = "2016-08-28"

    condition:
        //MZ header //PE signature //Payloads are normally smaller but the new dropper we spotted //is a bit larger. //Observed virtual sizes of the .Init section vary but they've //always been 1024, 2048, or 4096 bytes.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 300KB and for any i in (0..pe.number_of_sections - 1): (pe.sections[i].name == ".Init" and pe.sections[i].virtual_size % 1024 == 0)
}

rule EliseLotusBlossom
{

meta:
    author = "Jose Ramon Palanco"
    date = "2015-06-23"
    description = "Elise Backdoor Trojan"
    ref = "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html"

strings:
    $magic = { 4d 5a }
    $s1 = "\",Update" wide
    $s2 = "LoaderDLL.dll"
    $s3 = "Kernel32.dll"
    $s4 = "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}"
    $s5 = "\\Network\\" wide
    $s6 = "0SSSSS"
    $s7 = "441202100205"
    $s8 = "0WWWWW"

condition:
    $magic at 0 and all of ($s*)    
}


rule MiniDionis_readerView 
{

    meta:
        description = "MiniDionis Malware - file readerView.exe / adobe.exe"
        author = "Florian Roth"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        date = "2015-07-20"
        /* Original Hash */
        hash1 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
        /* Derived Samples */
        hash2 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
        hash3 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
        hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
        hash5 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
        hash6 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"

    strings:
        $s1 = "%ws_out%ws" fullword wide /* score: '8.00' */
        $s2 = "dnlibsh" fullword ascii /* score: '7.00' */

        $op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b } /* Opcode */
        $op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f } /* Opcode */
        $op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 } /* Opcode */

    condition:
        uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) and 1 of ($op*)
}

/* Related - SFX files or packed files with typical malware content -------- */

rule Malicious_SFX1 
{

    meta:
        description = "SFX with voicemail content"
        author = "Florian Roth"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        date = "2015-07-20"
        hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"
   
    strings:
        $s0 = "voicemail" ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
        $s1 = ".exe" ascii
   
    condition:
        uint16(0) == 0x4b50 and filesize < 1000KB and $s0 in (3..80) and $s1 in (3..80) 
}

rule Malicious_SFX2 
{

    meta:
        description = "SFX with adobe.exe content"
        author = "Florian Roth"
        reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
        date = "2015-07-20"
        hash = "502e42dc99873c52c3ca11dd3df25aad40d2b083069e8c22dd45da887f81d14d"

    strings:
        $s1 = "adobe.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
        $s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00' */
        $s3 = "GETPASSWORD1" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00' */

    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule MiniDionis_VBS_Dropped 
{

    meta:
        description = "Dropped File - 1.vbs"
        author = "Florian Roth"
        reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
        date = "2015-07-21"
        hash = "97dd1ee3aca815eb655a5de9e9e8945e7ba57f458019be6e1b9acb5731fa6646"

    strings:
        $s1 = "Wscript.Sleep 5000" ascii
        $s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
        $s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
        $s4 = "If(FSO.FileExists(\"" ascii
        $s5 = "then FSO.DeleteFile(\".\\" ascii

    condition:
        filesize < 1KB and all of them and $s1 in (0..40)
}


rule MirageStrings
{
    meta:
        description = "Mirage Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

rule Mirage
{
    meta:
        description = "Mirage"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        MirageStrings
}

rule Mirage_APT
{
    meta:
        Author      = "Silas Cutler"
        Date        = "yyyy/mm/dd"
        Description = "Malware related to APT campaign"
        Reference   = "Useful link"
    
    strings:
        $a1 = "welcome to the desert of the real"
        $a2 = "Mirage"
        $b = "Encoding: gzip"
        $c = /\/[A-Za-z]*\?hl=en/

    condition: 
        (($a1 or $a2) or $b) and $c
}


rule Molerats_certs
{
    
    meta:
        Author      = "FireEye Labs"
        Date        = "2013/08/23"
        Description = "this rule detections code signed with certificates used by the Molerats actor"
        Reference   = "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html"

    strings:
        $cert1 = { 06 50 11 A5 BC BF 83 C0 93 28 16 5E 7E 85 27 75 }
        $cert2 = { 03 e1 e1 aa a5 bc a1 9f ba 8c 42 05 8b 4a bf 28 }
        $cert3 = { 0c c0 35 9c 9c 3c da 00 d7 e9 da 2d c6 ba 7b 6d }

    condition:
        1 of ($cert*)
}


rule Backdoor_APT_Mongal
{

    meta:
        author = "@patrickrolsen"
        maltype = "Backdoor.APT.Mongall"
        version = "0.1"
        reference = "fd69a799e21ccb308531ce6056944842" 
        date = "01/04/2014"
    
    strings:
        $author  = "author user"
        $title   = "title Vjkygdjdtyuj" nocase
        $comp    = "company ooo"
        $cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
        $passwd  = "password 00000000"
    
    condition:
        all of them
}

rule MongalCode
{
    meta:
        description = "Mongal code features"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
    
    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        
    condition:
        any of them
}

rule MongalStrings
{
    
    meta:
        description = "Mongal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    strings:
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}

rule Mongal 
{
    
    meta:
        description = "Mongal"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    condition:
        MongalCode or MongalStrings
}



rule apt_RU_MoonlightMaze_customlokitools {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	last_modified = "2017-03-22"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
	hash = "14cce7e641d308c3a177a8abb5457019"
	hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
	hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
	hash = "1980958afffb6a9d5a6c73fc1e2795c2"
	hash = "e59f92aadb6505f29a9f368ab803082e"

strings:

	$a1="Write file Ok..." ascii wide 
	$a2="ERROR: Can not open socket...." ascii wide
	$a3="Error in parametrs:"  ascii wide
	$a4="Usage: @<get/put> <IP> <PORT> <file>"  ascii wide
	$a5="ERROR: Not connect..."  ascii wide
	$a6="Connect successful...."  ascii wide
	$a7="clnt <%d> rqstd n ll kll"  ascii wide
	$a8="clnt <%d> rqstd swap"  ascii wide
	$a9="cld nt sgnl prcs grp" ascii wide
	$a10="cld nt sgnl prnt" ascii wide

	//keeping only ascii version of string ->
	$a11="ork error" ascii fullword

condition:

	((any of ($a*)))

}


rule apt_RU_MoonlightMaze_customsniffer {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-15"
	version = "1.1"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze sniffer tools"
	hash = "7b86f40e861705d59f5206c482e1f2a5"
	hash = "927426b558888ad680829bd34b0ad0e7"
	original_filename = "ora;tdn"
	
strings:


	//strings from ora ->
	$a1="/var/tmp/gogo" fullword
	$a2="myfilename= |%s|" fullword
	$a3="mypid,mygid=" fullword
	$a4="mypid=|%d| mygid=|%d|" fullword

	//strings from tdn ->
	$a5="/var/tmp/task" fullword
	$a6="mydevname= |%s|" fullword

condition:

	((any of ($a*)))

}


rule loki2crypto {

meta:
	
	author = "Costin Raiu, Kaspersky Lab"
	date = "2017-03-21"
	version = "1.0"
	description = "Rule to detect hardcoded DH modulus used in 1996/1997 Loki2 sourcecode; #ifdef STRONG_CRYPTO /* 384-bit strong prime */"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	hash = "19fbd8cbfb12482e8020a887d6427315"
	hash = "ea06b213d5924de65407e8931b1e4326"
	hash = "14ecd5e6fc8e501037b54ca263896a11"
	hash = "e079ec947d3d4dacb21e993b760a65dc"
	hash = "edf900cebb70c6d1fcab0234062bfc28"

strings:

	$modulus={DA E1 01 CD D8 C9 70 AF C2 E4 F2 7A 41 8B 43 39 52 9B 4B 4D E5 85 F8 49}

condition:

	(any of them)

}




rule apt_RU_MoonlightMaze_de_tool {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'de' and 'deg' tunnel tool"
	hash = "4bc7ed168fb78f0dc688ee2be20c9703"
	hash = "8b56e8552a74133da4bc5939b5f74243"

strings:

	$a1="Vnuk: %d" ascii fullword
	$a2="Syn: %d" ascii fullword

	//%s\r%s\r%s\r%s\r ->
	$a3={25 73 0A 25 73 0A 25 73 0A 25 73 0A}

condition:

	((2 of ($a*)))

}


rule apt_RU_MoonlightMaze_cle_tool {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'cle' log cleaning tool"
	hash = "647d7b711f7b4434145ea30d0ef207b0"

	
strings:

	$a1="./a filename template_file" ascii wide
	$a2="May be %s is empty?"  ascii wide
	$a3="template string = |%s|"   ascii wide
	$a4="No blocks !!!"
	$a5="No data in this block !!!!!!"  ascii wide
	$a6="No good line"

condition:

	((3 of ($a*)))

}


rule apt_RU_MoonlightMaze_xk_keylogger {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze 'xk' keylogger"

strings:

	$a1="Log ended at => %s"
	$a2="Log started at => %s [pid %d]"
	$a3="/var/tmp/task" fullword
	$a4="/var/tmp/taskhost" fullword
	$a5="my hostname: %s"
	$a6="/var/tmp/tasklog"
	$a7="/var/tmp/.Xtmp01" fullword
	$a8="myfilename=-%s-"
	$a9="/var/tmp/taskpid"
	$a10="mypid=-%d-" fullword
	$a11="/var/tmp/taskgid" fullword
	$a12="mygid=-%d-" fullword


condition:

	((3 of ($a*)))

}

rule apt_RU_MoonlightMaze_encrypted_keylog {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Moonlight Maze encrypted keylogger logs"

strings:

	$a1={47 01 22 2A 6D 3E 39 2C}

condition:

	($a1 at 0)

}

rule apt_RU_MoonlightMaze_IRIX_exploit_GEN {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect Irix exploits from David Hedley used by Moonlight Maze hackers"
	reference2 = "https://www.exploit-db.com/exploits/19274/"
	hash = "008ea82f31f585622353bd47fa1d84be" //df3
	hash = "a26bad2b79075f454c83203fa00ed50c" //log
	hash = "f67fc6e90f05ba13f207c7fdaa8c2cab" //xconsole
	hash = "5937db3896cdd8b0beb3df44e509e136" //xlock
	hash = "f4ed5170dcea7e5ba62537d84392b280" //xterm

strings:

	$a1="stack = 0x%x, targ_addr = 0x%x"
	$a2="execl failed"

condition:

	(uint32(0)==0x464c457f) and (all of them)

}


rule apt_RU_MoonlightMaze_u_logcleaner {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect log cleaners based on utclean.c"
	reference2 = "http://cd.textfiles.com/cuteskunk/Unix-Hacking-Exploits/utclean.c"
	hash = "d98796dcda1443a37b124dbdc041fe3b"
	hash = "73a518f0a73ab77033121d4191172820"

strings:

	$a1="Hiding complit...n"
	$a2="usage: %s <username> <fixthings> [hostname]"
	$a3="ls -la %s* ; /bin/cp  ./wtmp.tmp %s; rm  ./wtmp.tmp"

condition:

	(uint32(0)==0x464c457f) and (any of them)

}


rule apt_RU_MoonlightMaze_wipe {

meta:
	
	author = "Kaspersky Lab"
	date = "2017-03-27"
	version = "1.0"
	last_modified = "2017-03-27"
	reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
	description = "Rule to detect log cleaner based on wipe.c"
	reference2 = "http://www.afn.org/~afn28925/wipe.c"
	hash = "e69efc504934551c6a77b525d5343241"

strings:

	$a1="ERROR: Unlinking tmp WTMP file."
	$a2="USAGE: wipe [ u|w|l|a ] ...options..."
	$a3="Erase acct entries on tty :   wipe a [username] [tty]"
	$a4="Alter lastlog entry       :   wipe l [username] [tty] [time] [host]"

condition:

	(uint32(0)==0x464c457f) and (2 of them)

}


rule APT_NGO_wuaclt
{
   
   meta:
    author = "AlienVault Labs"
  
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    
    $d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
    $e = "0l23kj@nboxu"
    
    $f = "%%s.asp?id=%%d&Sid=%%d"
    $g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
    $h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}

rule APT_NGO_wuaclt_PDF
{
        meta:
            author = "AlienVault Labs"

    strings:
        $pdf  = "%PDF" nocase
        $comment = {3C 21 2D 2D 0D 0A 63 57 4B 51 6D 5A 6C 61 56 56 56 56 56 56 56 56 56 56 56 56 56 63 77 53 64 63 6A 4B 7A 38 35 6D 37 4A 56 6D 37 4A 46 78 6B 5A 6D 5A 6D 52 44 63 5A 58 41 73 6D 5A 6D 5A 7A 42 4A 31 79 73 2F 4F 0D 0A}
    
    condition:
        $pdf at 0 and $comment in (0..200)
}


rule OilRig_Malware_Campaign_Gen1 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "d808f3109822c185f1d8e1bf7ef7781c219dc56f5906478651748f0ace489d34"
      hash2 = "80161dad1603b9a7c4a92a07b5c8bce214cf7a3df897b561732f9df7920ecb3e"
      hash3 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
      hash4 = "903b6d948c16dc92b69fe1de76cf64ab8377893770bf47c29bf91f3fd987f996"
      hash5 = "c4fbc723981fc94884f0f493cb8711fdc9da698980081d9b7c139fcffbe723da"
      hash6 = "57efb7596e6d9fd019b4dc4587ba33a40ab0ca09e14281d85716a253c5612ef4"
      hash7 = "1b2fee00d28782076178a63e669d2306c37ba0c417708d4dc1f751765c3f94e1"
      hash8 = "9f31a1908afb23a1029c079ee9ba8bdf0f4c815addbe8eac85b4163e02b5e777"
      hash9 = "0cd9857a3f626f8e0c07495a4799c59d502c4f3970642a76882e3ed68b790f8e"
      hash10 = "4b5112f0fb64825b879b01d686e8f4d43521252a3b4f4026c9d1d76d3f15b281"
      hash11 = "4e5b85ea68bf8f2306b6b931810ae38c8dff3679d78da1af2c91032c36380353"
      hash12 = "c3c17383f43184a29f49f166a92453a34be18e51935ddbf09576a60441440e51"
      hash13 = "f3856c7af3c9f84101f41a82e36fc81dfc18a8e9b424a3658b6ba7e3c99f54f2"
      hash14 = "0c64ab9b0c122b1903e8063e3c2c357cbbee99de07dc535e6c830a0472a71f39"
      hash15 = "d874f513a032ccb6a5e4f0cd55862b024ea0bee4de94ccf950b3dd894066065d"
      hash16 = "8ee628d46b8af20c4ba70a2fe8e2d4edca1980583171b71fe72455c6a52d15a9"
      hash17 = "55d0e12439b20dadb5868766a5200cbbe1a06053bf9e229cf6a852bfcf57d579"
      hash18 = "528d432952ef879496542bc62a5a4b6eee788f60f220426bd7f933fa2c58dc6b"
      hash19 = "93940b5e764f2f4a2d893bebef4bf1f7d63c4db856877020a5852a6647cb04a0"
      hash20 = "e2ec7fa60e654f5861e09bbe59d14d0973bd5727b83a2a03f1cecf1466dd87aa"
      hash21 = "9c0a33a5dc62933f17506f20e0258f877947bdcd15b091a597eac05d299b7471"
      hash22 = "a787c0e42608f9a69f718f6dca5556607be45ec77d17b07eb9ea1e0f7bb2e064"
      hash23 = "3772d473a2fe950959e1fd56c9a44ec48928f92522246f75f4b8cb134f4713ff"
      hash24 = "3986d54b00647b507b2afd708b7a1ce4c37027fb77d67c6bc3c20c3ac1a88ca4"
      hash25 = "f5a64de9087b138608ccf036b067d91a47302259269fb05b3349964ca4060e7e"

   strings:
      $x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
      $x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
      $x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii
      /* Base64 encode config */
      /* $global:myhost = */
      $b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
      /* HOME="%public%\Libraries\" */
      $b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
      /* Set wss = CreateObject("wScript.Shell") */
      $b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
      /* $scriptdir = Split-Path -Parent -Path $ */
      $b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
      /* \x0aSet wss = CreateObject("wScript.Shell") */
      $b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
      /* whoami & hostname */
      $b6 = "d2hvYW1pICYgaG9zdG5hb" ascii
 
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal1 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "e17e1978563dc10b73fd54e7727cbbe95cc0b170a4e7bd0ab223e059f6c25fcc"

   strings:
      $x1 = "DownloadExecute=\"powershell \"\"&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile(" ascii
      $x2 = "-ExecutionPolicy Bypass -File \"&HOME&\"dns.ps1\"" fullword ascii
      $x3 = "CreateObject(\"WScript.Shell\").Run Replace(DownloadExecute,\"-_\",\"bat\")" fullword ascii
      $x4 = "CreateObject(\"WScript.Shell\").Run DnsCmd,0" fullword ascii
      $s1 = "http://winodwsupdates.me" ascii

   condition:
      ( uint16(0) == 0x4f48 and filesize < 4KB and 1 of them ) or ( 2 of them )
}

rule OilRig_Malware_Campaign_Gen2 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "c6437f57a8f290b5ec46b0933bfa8a328b0cb2c0c7fbeea7f21b770ce0250d3d"
      hash2 = "293522e83aeebf185e653ac279bba202024cedb07abc94683930b74df51ce5cb"

   strings:
      $s1 = "%userprofile%\\AppData\\Local\\Microsoft\\ " fullword ascii
      $s2 = "$fdn=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" fullword ascii
      $s3 = "&{$rn = Get-Random; $id = 'TR" fullword ascii
      $s4 = "') -replace '__',('DNS'+$id) | " fullword ascii
      $s5 = "\\upd.vbs" fullword ascii
      $s6 = "schtasks /create /F /sc minute /mo " fullword ascii
      $s7 = "') -replace '__',('HTP'+$id) | " fullword ascii
      $s8 = "&{$rn = Get-Random -minimum 1 -maximum 10000; $id = 'AZ" fullword ascii
      $s9 = "http://www.israirairlines.com/?mode=page&page=14635&lang=eng<" fullword ascii

   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 2 of ($s*) ) or ( 4 of them )
}

rule OilRig_Malware_Campaign_Gen3 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
      hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
      hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"

   strings:
      $x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
      $x2 = "\\Libraries\\fireueye.vbs" fullword ascii
      $x3 = "\\Libraries\\fireeye.vbs&" fullword wide

   condition:
      ( uint16(0) == 0xcfd0 and filesize < 100KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal2 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "65920eaea00764a245acb58a3565941477b78a7bcc9efaec5bf811573084b6cf"

   strings:
      $x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
      $x2 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $x3 = "mailto:Mohammed.sarah@gratner.com" fullword wide
      $x4 = "mailto:Tarik.Imam@gartner.com" fullword wide
      $x5 = "Call Extract(DnsPs1, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\dns.ps1\")" fullword ascii
      $x6 = "2dy53My5vcmcvMjAw" fullword wide /* base64 encoded string 'w.w3.org/200' */

   condition:
      ( uint16(0) == 0xcfd0 and filesize < 200KB and 1 of them )
}

rule OilRig_Campaign_Reconnaissance 
{

   meta:
      description = "Detects Windows discovery commands - known from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"

   strings:
      $s1 = "whoami & hostname & ipconfig /all" ascii
      $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
      $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii

   condition:
      ( filesize < 1KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal3 
{

   meta:
      description = "Detects malware from OilRig Campaign"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"

   strings:
      $x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
      $x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
      $x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii

   condition:
      ( filesize < 10KB and 1 of them )
}

rule OpClandestineWolf 
{
 
   meta:
        alert_severity = "HIGH"
        log = "false"
        author = "NDF"
        weight = 10
        alert = true
        source = " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html"
        version = 1
        date = "2015-06-23"
        description = "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
        hash0 = "1a4b710621ef2e69b1f7790ae9b7a288"
        hash1 = "917c92e8662faf96fffb8ffe7b7c80fb"
        hash2 = "975b458cb80395fa32c9dda759cb3f7b"
        hash3 = "3ed34de8609cd274e49bbd795f21acc4"
        hash4 = "b1a55ec420dd6d24ff9e762c7b753868"
        hash5 = "afd753a42036000ad476dcd81b56b754"
        hash6 = "fad20abf8aa4eda0802504d806280dd7"
        hash7 = "ab621059de2d1c92c3e7514e4b51751a"
        hash8 = "510b77a4b075f09202209f989582dbea"
        hash9 = "d1b1abfcc2d547e1ea1a4bb82294b9a3"
        hash10 = "4692337bf7584f6bda464b9a76d268c1"
        hash11 = "7cae5757f3ba9fef0a22ca0d56188439"
        hash12 = "1a7ba923c6aa39cc9cb289a17599fce0"
        hash13 = "f86db1905b3f4447eb5728859f9057b5"
        hash14 = "37c6d1d3054e554e13d40ea42458ebed"
        hash15 = "3e7430a09a44c0d1000f76c3adc6f4fa"
        hash16 = "98eb249e4ddc4897b8be6fe838051af7"
        hash17 = "1b57a7fad852b1d686c72e96f7837b44"
        hash18 = "ffb84b8561e49a8db60e0001f630831f"
        hash19 = "98eb249e4ddc4897b8be6fe838051af7"
        hash20 = "dfb4025352a80c2d81b84b37ef00bcd0"
        hash21 = "4457e89f4aec692d8507378694e0a3ba"
        hash22 = "48de562acb62b469480b8e29821f33b8"
        hash23 = "7a7eed9f2d1807f55a9308e21d81cccd"
        hash24 = "6817b29e9832d8fd85dcbe4af176efb6"

   strings:
        $s0 = "flash.Media.Sound()"
        $s1 = "call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)"
        $s2 = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        $s3 = "NetStream"

    condition:
        all of them
}

rule ZhoupinExploitCrew
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhoupin exploit crew" nocase
    $s2 = "zhopin exploit crew" nocase

  condition:
    1 of them
}

rule BackDoorLogger
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "BackDoorLogger"
    $s2 = "zhuAddress"

  condition:
    all of them
}

rule Jasus
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "pcap_dump_open"
    $s2 = "Resolving IPs to poison..."
    $s3 = "WARNNING: Gateway IP can not be found"

  condition:
    all of them
}

rule LoggerModule
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "%s-%02d%02d%02d%02d%02d.r"
    $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

  condition:
    all of them
}

rule NetC
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "NetC.exe" wide
    $s2 = "Net Service"

  condition:
    all of them
}

rule ShellCreator2
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "ShellCreator2.Properties"
    $s2 = "set_IV"

  condition:
    all of them
}

rule SmartCopy2
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "SmartCopy2.Properties"
    $s2 = "ZhuFrameWork"

  condition:
    all of them
}

rule SynFlooder
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    $s2 = "your target's IP is : %s"
    $s3 = "Raw TCP Socket Created successfully."

  condition:
    all of them
}

rule TinyZBot
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "NetScp" wide
    $s2 = "TinyZBot.Properties.Resources.resources"
    $s3 = "Aoao WaterMark"
    $s4 = "Run_a_exe"
    $s5 = "netscp.exe"
    $s6 = "get_MainModule_WebReference_DefaultWS"
    $s7 = "remove_CheckFileMD5Completed"
    $s8 = "http://tempuri.org/"
    $s9 = "Zhoupin_Cleaver"

  condition:
    ($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or ($s9)
}

rule antivirusdetector
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

    strings:
        $s1 = "getShadyProcess"
        $s2 = "getSystemAntiviruses"
        $s3 = "AntiVirusDetector"

    condition:
        all of them
}

rule csext
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "COM+ System Extentions"
    $s2 = "csext.exe"
    $s3 = "COM_Extentions_bin"

  condition:
    all of them
}

rule kagent
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "kill command is in last machine, going back"
    $s2 = "message data length in B64: %d Bytes"

  condition:
    all of them
}

rule mimikatzWrapper : Toolkit
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "mimikatzWrapper"
    $s2 = "get_mimikatz"

  condition:
    all of them
}

rule pvz_in
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "LAST_TIME=00/00/0000:00:00PM$"
    $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"

  condition:
    all of them
}

rule pvz_out
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "Network Connectivity Module" wide
    $s2 = "OSPPSVC" wide

  condition:
    all of them
}

rule wndTest
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "[Alt]" wide
    $s2 = "<< %s >>:" wide
    $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"

  condition:
    all of them
}

rule zhCat
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhCat -l -h -tp 1234"
    $s2 = "ABC ( A Big Company )" wide

  condition:
    all of them
}

rule zhLookUp
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "zhLookUp.Properties"

  condition:
    all of them
}

rule zhmimikatz
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "MimikatzRunner"
    $s2 = "zhmimikatz"

  condition:
    all of them
}

rule Zh0uSh311
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

  strings:
    $s1 = "Zh0uSh311"

  condition:
    all of them
}

rule OPCLEAVER_BackDoorLogger
{

    meta:
        description = "Keylogger used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "BackDoorLogger"
        $s2 = "zhuAddress"

    condition:
        all of them
}

rule OPCLEAVER_Jasus
{

    meta:
        description = "ARP cache poisoner used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "pcap_dump_open"
        $s2 = "Resolving IPs to poison..."
        $s3 = "WARNNING: Gateway IP can not be found"

    condition:
        all of them
}

rule OPCLEAVER_LoggerModule
{

    meta:
        description = "Keylogger used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "%s-%02d%02d%02d%02d%02d.r"
        $s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

    condition:
        all of them
}

rule OPCLEAVER_NetC
{

    meta:
        description = "Net Crawler used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "NetC.exe" wide
        $s2 = "Net Service"

    condition:
        all of them
}

rule OPCLEAVER_ShellCreator2
{

    meta:
        description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "ShellCreator2.Properties"
        $s2 = "set_IV"

    condition:
        all of them
}

rule OPCLEAVER_SmartCopy2
{

    meta:
        description = "Malware or hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "SmartCopy2.Properties"
        $s2 = "ZhuFrameWork"

    condition:
        all of them
}

rule OPCLEAVER_SynFlooder
{

    meta:
        description = "Malware or hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "Unable to resolve [ %s ]. ErrorCode %d"
        $s2 = "your target’s IP is : %s"
        $s3 = "Raw TCP Socket Created successfully."

    condition:
        all of them
}

rule OPCLEAVER_TinyZBot
{

    meta:
        description = "Tiny Bot used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "NetScp" wide
        $s2 = "TinyZBot.Properties.Resources.resources"
        $s3 = "Aoao WaterMark"
        $s4 = "Run_a_exe"
        $s5 = "netscp.exe"
        $s6 = "get_MainModule_WebReference_DefaultWS"
        $s7 = "remove_CheckFileMD5Completed"
        $s8 = "http://tempuri.org/"
        $s9 = "Zhoupin_Cleaver"

    condition:
        (($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9)
}

rule OPCLEAVER_ZhoupinExploitCrew
{

    meta:
        description = "Keywords used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "zhoupin exploit crew" nocase
        $s2 = "zhopin exploit crew" nocase

    condition:
        1 of them
}

rule OPCLEAVER_antivirusdetector
{

    meta:
        description = "Hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "getShadyProcess"
        $s2 = "getSystemAntiviruses"
        $s3 = "AntiVirusDetector"

    condition:
        all of them
}

rule OPCLEAVER_csext
{

    meta:
        description = "Backdoor used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "COM+ System Extentions"
        $s2 = "csext.exe"
        $s3 = "COM_Extentions_bin"

    condition:
        all of them
}

rule OPCLEAVER_kagent
{

    meta:
        description = "Backdoor used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "kill command is in last machine, going back"
        $s2 = "message data length in B64: %d Bytes"

    condition:
        all of them
}

rule OPCLEAVER_mimikatzWrapper
{

    meta:
        description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "mimikatzWrapper"
        $s2 = "get_mimikatz"

    condition:
        all of them
}

rule OPCLEAVER_pvz_in
{

    meta:
        description = "Parviz tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "LAST_TIME=00/00/0000:00:00PM$"
        $s2 = "if %%ERRORLEVEL%% == 1 GOTO line"

    condition:
        all of them
}

rule OPCLEAVER_pvz_out
{

    meta:
        description = "Parviz tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "Network Connectivity Module" wide
        $s2 = "OSPPSVC" wide

    condition:
        all of them
}

rule OPCLEAVER_wndTest
{

    meta:
        description = "Backdoor used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "[Alt]" wide
        $s2 = "<< %s >>:" wide
        $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"

    condition:
        all of them
}

rule OPCLEAVER_zhCat
{

    meta:
        description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
        $s2 = "ABC ( A Big Company )" wide fullword

    condition:
        all of them
}

rule OPCLEAVER_zhLookUp
{

    meta:
        description = "Hack tool used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "zhLookUp.Properties"

    condition:
        all of them
}

rule OPCLEAVER_zhmimikatz
{

    meta:
        description = "Mimikatz wrapper used by attackers in Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Cylance Inc."
        score = "70"

    strings:
        $s1 = "MimikatzRunner"
        $s2 = "zhmimikatz"

    condition:
        all of them
}

rule OPCLEAVER_Parviz_Developer
{

    meta:
        description = "Parviz developer known from Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Florian Roth"
        score = "70"

    strings:
        $s1 = "Users\\parviz\\documents\\" nocase

    condition:
        $s1
}

rule OPCLEAVER_CCProxy_Config
{

    meta:
        description = "CCProxy config known from Operation Cleaver"
        reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
        date = "2014/12/02"
        author = "Florian Roth"
        score = "70"

    strings:
        $s1 = "UserName=User-001" fullword ascii
        $s2 = "Web=1" fullword ascii
        $s3 = "Mail=1" fullword ascii
        $s4 = "FTP=0" fullword ascii
        $x1 = "IPAddressLow=78.109.194.114" fullword ascii

    condition:
        all of ($s*) or $x1
}

rule Misdat_Backdoor_Packed
{
    
    meta:
        author = "Cylance SPEAR Team"
        note = "Probably Prone to False Positive"

    strings:
        $upx = {33 2E 30 33 00 55 50 58 21}
        $send = {00 00 00 73 65 6E 64 00 00 00}
        $delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
        $shellexec = {00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 57 00 00 00}
        
    condition:
        filesize < 100KB and $upx and $send and $delphi_sec_pe and $shellexec
}

rule MiSType_Backdoor_Packed
{
    
    meta:
        author = "Cylance SPEAR Team"
        note = "Probably Prone to False Positive"

    strings:
        $upx = {33 2E 30 33 00 55 50 58 21}
        $send_httpquery = {00 00 00 48 74 74 70 51 75 65 72 79 49 6E 66 6F 41 00 00 73 65 6E 64 00 00}
        $delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
    
    condition:
        filesize < 100KB and $upx and $send_httpquery and $delphi_sec_pe
}

rule Misdat_Backdoor
{
   
   meta:
        author = "Cylance SPEAR Team"
        /* Decode Function
        CODE:00406C71 8B 55 F4                  mov     edx, [ebp+var_C]
        CODE:00406C74 8A 54 1A FF               mov     dl, [edx+ebx-1]
        CODE:00406C78 8B 4D F8                  mov     ecx, [ebp+var_8]
        CODE:00406C7B C1 E9 08                  shr     ecx, 8
        CODE:00406C7E 32 D1                     xor     dl, cl
        CODE:00406C80 88 54 18 FF               mov     [eax+ebx-1], dl
        CODE:00406C84 8B 45 F4                  mov     eax, [ebp+var_C]
        CODE:00406C87 0F B6 44 18 FF            movzx   eax, byte ptr [eax+ebx-1]
        CODE:00406C8C 03 45 F8                  add     eax, [ebp+var_8]
        CODE:00406C8F 69 C0 D9 DB 00 00         imul    eax, 0DBD9h
        CODE:00406C95 05 3B DA 00 00            add     eax, 0DA3Bh
        CODE:00406C9A 89 45 F8                  mov     [ebp+var_8], eax
        CODE:00406C9D 43                        inc     ebx
        CODE:00406C9E 4E                        dec     esi
        CODE:00406C9F 75 C9                     jnz     short loc_406C6A
        */
    
    strings:
        $imul = {03 45 F8 69 C0 D9 DB 00 00 05 3B DA 00 00}
        $delphi = {50 45 00 00 4C 01 08 00 19 5E 42 2A}
        
    condition:
        $imul and $delphi
}

rule SType_Backdoor
{
   
    meta:
        author = "Cylance SPEAR Team"
        
        /* Decode Function
        8B 1A       mov     ebx, [edx]
        8A 1B       mov     bl, [ebx]
        80 EB 02    sub     bl, 2
        8B 74 24 08 mov     esi, [esp+14h+var_C]
        32 1E       xor     bl, [esi]
        8B 31       mov     esi, [ecx]
        88 1E       mov     [esi], bl
        8B 1A       mov     ebx, [edx]
        43          inc     ebx
        89 1A       mov     [edx], ebx
        8B 19       mov     ebx, [ecx]
        43          inc     ebx
        89 19       mov     [ecx], ebx
        48          dec     eax
        75 E2       jnz     short loc_40EAC6
        */

    strings:
        $stype = "stype=info&data="
        $mmid = "?mmid="
        $status = "&status=run succeed"
        $mutex = "_KB10B2D1_CIlFD2C"
        $decode = {8B 1A 8A 1B 80 EB 02 8B 74 24 08 32 1E 8B 31 88 1E 8B 1A 43}
    
    condition:
        $stype or ($mmid and $status) or $mutex or $decode
}

rule Zlib_Backdoor
{
   
    meta:
        author = "Cylance SPEAR Team"
        
        /* String
        C7 45 FC 00 04 00 00          mov     [ebp+Memory], 400h
        C6 45 D8 50                   mov     [ebp+Str], 'P'
        C6 45 D9 72                   mov     [ebp+var_27], 'r'
        C6 45 DA 6F                   mov     [ebp+var_26], 'o'
        C6 45 DB 78                   mov     [ebp+var_25], 'x'
        C6 45 DC 79                   mov     [ebp+var_24], 'y'
        C6 45 DD 2D                   mov     [ebp+var_23], '-'
        C6 45 DE 41                   mov     [ebp+var_22], 'A'
        C6 45 DF 75                   mov     [ebp+var_21], 'u'
        C6 45 E0 74                   mov     [ebp+var_20], 't'
        C6 45 E1 68                   mov     [ebp+var_1F], 'h'
        C6 45 E2 65                   mov     [ebp+var_1E], 'e'
        C6 45 E3 6E                   mov     [ebp+var_1D], 'n'
        C6 45 E4 74                   mov     [ebp+var_1C], 't'
        C6 45 E5 69                   mov     [ebp+var_1B], 'i'
        C6 45 E6 63                   mov     [ebp+var_1A], 'c'
        C6 45 E7 61                   mov     [ebp+var_19], 'a'
        C6 45 E8 74                   mov     [ebp+var_18], 't'
        C6 45 E9 65                   mov     [ebp+var_17], 'e'
        C6 45 EA 3A                   mov     [ebp+var_16], ':'
        C6 45 EB 20                   mov     [ebp+var_15], ' '
        C6 45 EC 4E                   mov     [ebp+var_14], 'N'
        C6 45 ED 54                   mov     [ebp+var_13], 'T'
        C6 45 EE 4C                   mov     [ebp+var_12], 'L'
        C6 45 EF 4D                   mov     [ebp+var_11], 'M'
        C6 45 F0 20                   mov     [ebp+var_10], ' '
        */


    strings:
        $auth = {C6 45 D8 50 C6 45 D9 72 C6 45 DA 6F C6 45 DB 78 C6 45 DC 79 C6 45 DD 2D}
        $auth2 = {C7 45 FC 00 04 00 00 C6 45 ?? 50 C6 45 ?? 72 C6 45 ?? 6F}
        $ntlm = "NTLM" wide
    
    condition:
        ($auth or $auth2) and $ntlm
}
/*APT_OpDustStrom.yar loaded*/