/*
 * YARA rules written for meles, under the Detection Rule License 1.1
 * (LICENSES/DRL-1.1.txt). See README.md in this directory.
 */

rule MELES_Miner_XMRig_Proxy : FILE
{
	meta:
		description = "Detects xmrig-proxy, a mining proxy that bundles the connections of many miners"
		author = "meles project"
		date = "2026-11-06"
		reference = "https://github.com/xmrig/xmrig-proxy"
		source_url = "https://github.com/movray/meles/blob/main/charts/meles/rules/meles-own.yar"
		license_url = "https://github.com/movray/meles/blob/main/charts/meles/rules/LICENSES/DRL-1.1.txt"
		mitre_attack = "T1496"
		confidence = "high"

	strings:
		$usage = "Usage: xmrig-proxy [OPTIONS]" ascii
		$mode = "proxy mode" ascii
		$donate = "donate.ssl.xmrig.com" ascii
		$class = "N5xmrig5ProxyE" ascii

	condition:
		( uint16( 0 ) == 0x457f or uint16( 0 ) == 0x5a4d ) and filesize < 50MB and 2 of them
}

rule MELES_Miner_XMRig_Config : FILE
{
	meta:
		description = "Detects a JSON configuration of XMRig or xmrig-proxy with mining pools"
		author = "meles project"
		date = "2026-11-06"
		reference = "https://xmrig.com/docs/miner/config"
		source_url = "https://github.com/movray/meles/blob/main/charts/meles/rules/meles-own.yar"
		license_url = "https://github.com/movray/meles/blob/main/charts/meles/rules/LICENSES/DRL-1.1.txt"
		mitre_attack = "T1496"
		confidence = "high"

	strings:
		$donate = "\"donate-level\"" ascii
		$pools = "\"pools\"" ascii
		$url = "\"url\"" ascii
		$user = "\"user\"" ascii

	condition:
		uint8( 0 ) == 0x7b and filesize < 128KB and all of them
}

rule MELES_Miner_Ariominer : FILE
{
	meta:
		description = "Detects ariominer, a CPU and GPU miner for Arionum"
		author = "meles project"
		date = "2026-11-06"
		reference = "https://github.com/bogdanadnan/ariominer"
		source_url = "https://github.com/movray/meles/blob/main/charts/meles/rules/meles-own.yar"
		license_url = "https://github.com/movray/meles/blob/main/charts/meles/rules/LICENSES/DRL-1.1.txt"
		mitre_attack = "T1496"
		confidence = "high"

	strings:
		$name = "Arionum CPU/GPU Miner" ascii
		$mine = "this instance will mine for arionum" ascii
		$help = "Type ariominer --help for usage information." ascii
		$class = "ariopool_client" ascii

	condition:
		( uint16( 0 ) == 0x457f or uint16( 0 ) == 0x5a4d ) and filesize < 50MB and 2 of them
}
