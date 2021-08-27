if (Test-Path -Path $args -PathType Leaf) {
	$sha1=(Get-FileHash -Algorithm sha1 $args).hash
}
else {
	$sha1=$args	# If file does not exist, than argument is already a hash
}

try {
	$ProgressPreference = 'SilentlyContinue'
	$swVTFileReportWR = Invoke-WebRequest -Method GET -Uri "https://www.virustotal.com/api/v3/files/$sha1" -Headers @{"x-apikey"="$Env:zzVirusTotalAPI"}
	$ProgressPreference = 'Continue'
}
catch {
	Write-Host $_.Exception.Message -ForegroundColor Red
	$_.Exception
	Write-Host "404? SHA1 does not exit in VirusTotal?"
	Write-Host "401? No API key provided?"
	exit
}

$global:swVTFileReport = $swVTFileReportWR.content | ConvertFrom-Json

Write-Host "+----------------------------------------------------------------------------------------------------"
Write-Host "| IP ADDRESS: $args"
Write-Host "+----------------------------------------------------------------------------------------------------"
Write-Host "Clean ............... " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.harmless            -ForegroundColor Green
Write-Host "Suspicious .......... " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.suspicious          -ForegroundColor Yellow
Write-Host "Malware ............. " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.malicious           -ForegroundColor Red
Write-Host "Undetected .......... " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.undetected          -ForegroundColor Yellow
Write-Host "Failure ............. " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.failure             -ForegroundColor Yellow
Write-Host "Timeout ............. " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.timeout             -ForegroundColor Yellow
Write-Host "Type-unsupported .... " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.'type-unsupported'  -ForegroundColor Yellow
Write-Host "Confirmed-timeout ... " -NoNewLine ; Write-Host $swVTFileReport.data.attributes.last_analysis_stats.'confirmed-timeout' -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------------------------------------------"
Write-Host ("ESET ............... " + $args + " " +
	$swVTFileReport.data.attributes.last_analysis_results.'eset-nod32'.method + "ed: " +
	$swVTFileReport.data.attributes.last_analysis_results.'eset-nod32'.category + "/" +
	$swVTFileReport.data.attributes.last_analysis_results.'eset-nod32'.result)
Write-Host "----------------------------------------------------------------------------------------------------"
