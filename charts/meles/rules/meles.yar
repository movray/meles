/*
 * meles default YARA rules, executed by ClamAV's YARA support.
 *
 * Selected from the YARA Forge package 20261018 (https://yarahq.github.io/):
 * rules for containers, cryptominers, Linux malware and webshells that load
 * in ClamAV and compile in YARA-X, from sources with a license only.
 * Every rule keeps its meta block (only empty values, which ClamAV rejects,
 * are removed): author, source_url and license_url name
 * the author, the original rule and its license. Licenses and selection:
 * README.md in this directory.
 */

rule DITEKSHEN_INDICATOR_TOOL_PET_Peirates : FILE
{
	meta:
		description = "Detects Kubernetes penetration tool Peirates"
		author = "ditekSHen"
		id = "74ce83ed-0d93-5cb0-97e8-6885ae83b336"
		date = "2020-11-06"
		modified = "2024-09-25"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_tools.yar#L677-L694"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "321f06af098283638f99d027dc3c95a25a72192a25c7afa5081a7dbff8c3acb7"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "DeprecatedServiceAccount" fullword ascii
		$s2 = "LivenessProbe" fullword ascii
		$s3 = "\\t\\tkubectl expose rs nginx --port=80 --target-port=8000" ascii
		$s4 = "\\t\\tkubectl run hazelcast --image=hazelcast --port=5701" ascii
		$s5 = "COMPREPLY[$i]=${COMPREPLY[$i]#\"$colon_word\"}" ascii
		$s6 = "%*polymorphichelpers.HistoryViewerFunc" ascii
		$s7 = "ListenAndServeTLS" ascii
		$s8 = "DownwardAPI" ascii
		$s9 = "; plural=(n%10==1 && n%100!=11 ? 0 : n != 0 ? 1 : 2);proto:" ascii
		$s10 = "name: attack-" ascii

	condition:
		uint16( 0 ) == 0x457f and 9 of them
}

rule DITEKSHEN_MALWARE_Linux_Kinsing : FILE
{
	meta:
		description = "Kinsing RAT payload"
		author = "ditekSHen"
		id = "b13d2c36-c8d3-5138-9e9a-8b5390a93c8d"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L1361-L1376"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "566eb7d1864e3a8088ad4f5d032d6d62a33080bbfc5c20c2520315cfc8146afc"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "backconnect" ascii
		$s2 = "connectForSocks" ascii
		$s3 = "downloadAndExecute" ascii
		$s4 = "download_and_exec" ascii
		$s5 = "masscan" ascii
		$s6 = "UpdateCommand:" ascii
		$s7 = "exec_out" ascii
		$s8 = "doTask with type %s" ascii

	condition:
		uint16( 0 ) == 0x457f and 6 of them
}

rule SEKOIA_Bot_Lin_Kinsing_Strings : FILE
{
	meta:
		description = "Catch Kinsing malware based on strings"
		author = "Sekoia.io"
		id = "ce41b6d0-bc22-4a85-a3bb-ed3234871524"
		date = "2023-11-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/bot_lin_kinsing_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "164b22734541d43047a2ea868cf0a269efe69c64a6392030168f4d391b1be777"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "MinerUrl" ascii
		$s2 = "main.masscan" ascii
		$s3 = "redisBrute" ascii
		$s4 = "ActiveC2CUrl" ascii
		$s5 = "main.getKi" ascii
		$s6 = "main.getMu" ascii
		$s7 = "tryToRunMiner" ascii
		$s8 = "main.kiLoader" ascii
		$s9 = "main.downloadAndExecute" ascii

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule SIGNATURE_BASE_Crime_H2Miner_Kinsing : FILE
{
	meta:
		description = "Rule to find Kinsing malware"
		author = "Tony Lambert, Red Canary"
		id = "1cabca0d-7134-517e-b82e-f2b20b4d1c34"
		date = "2020-06-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/crime_h2miner_kinsing.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "8795f01f4ce85ca37a4e4667a4ee9756dae6af42884cf79830877a5c35a3bd3b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "-iL $INPUT --rate $RATE -p$PORT -oL $OUTPUT"
		$s2 = "libpcap"
		$s3 = "main.backconnect"
		$s4 = "main.masscan"
		$s5 = "main.checkHealth"
		$s6 = "main.redisBrute"
		$s7 = "ActiveC2CUrl"
		$s8 = "main.RC4"
		$s9 = "main.runTask"

	condition:
		( uint32( 0 ) == 0x464C457F ) and filesize > 1MB and all of them
}

rule WITHSECURELABS_GREYVIBE_Phantomrelay_Watchdog : FILE
{
	meta:
		description = "Detects GREYVIBE's watchdog script for PhantomRelay"
		author = "WithSecure"
		id = "c59eef2e-22c8-5df2-aa81-111cce4d20c8"
		date = "2026-05-28"
		modified = "2026-05-28"
		reference = "https://github.com/WithSecureLabs/iocs"
		source_url = "https://github.com/WithSecureLabs/iocs/blob/1a8384468dd292c6d2c5114c32e42dc0da1f5ae1/GREYVIBE/greyvibe.yara#L91-L103"
		license_url = "https://github.com/WithSecureLabs/iocs/blob/1a8384468dd292c6d2c5114c32e42dc0da1f5ae1/LICENSE"
		logic_hash = "19d5fdaf2e2c98637971427761e316fd405a0f6d8e7f539dc9f72d20313ba43c"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$a1 = "--headless"
		$a2 = "/watchdog"
		$a3 = "Register-ScheduledTask"
		$a4 = "DownloadFile"

	condition:
		filesize < 50KB and all of them
}

rule SIGNATURE_BASE_Coinhive_Javascript_Monerominer : HIGHVOL FILE
{
	meta:
		description = "Detects CoinHive - JavaScript Crypto Miner"
		author = "Florian Roth (Nextron Systems)"
		id = "4f40c342-fcdc-5c73-a3cf-7b2ed438eaaf"
		date = "2018-01-04"
		modified = "2023-12-05"
		reference = "https://coinhive.com/documentation/miner"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_cryptocoin_miner.yar#L20-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "4146b034a9785f1bb7c60db62db0e478d960f2ac9adb7c5b74b365186578ca47"
		score = 50
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii

	condition:
		filesize < 65KB and 1 of them
}

rule SIGNATURE_BASE_Coinminer_Strings : SCRIPT HIGHVOL FILE
{
	meta:
		description = "Detects mining pool protocol string in Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "ac045f83-5f32-57a9-8011-99a2658a0e05"
		date = "2018-01-04"
		modified = "2021-10-26"
		reference = "https://minergate.com/faq/what-pool-address"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_cryptocoin_miner.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "2d63bf90560c83ab6c09e0c82b6a6449bca6e7e7d0945d3782c2fa9a726b2ca1"
		score = 60
		quality = 85
		tags = "SCRIPT, HIGHVOL, FILE"
		nodeepdive = 1

	strings:
		$sa1 = "stratum+tcp://" ascii
		$sa2 = "stratum+udp://" ascii
		$sb1 = "\"normalHashing\": true,"

	condition:
		filesize < 3000KB and 1 of them
}

rule SIGNATURE_BASE_PUA_Cryptominer_Jan19_1 : FILE
{
	meta:
		description = "Detects Crypto Miner strings"
		author = "Florian Roth (Nextron Systems)"
		id = "aebfdce9-c2dd-5f24-aa25-071e1a961239"
		date = "2019-01-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_cryptocoin_miner.yar#L35-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
		logic_hash = "7097d404e0317230a5f60fc66fbcb2a2a5315f8fd348a7e689aaf75c26684f9e"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Stratum notify: invalid Merkle branch" fullword ascii
		$s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
		$s3 = "User-Agent: cpuminer/" ascii
		$s4 = "hash > target (false positive)" fullword ascii
		$s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii

	condition:
		filesize < 1000KB and 1 of them
}

rule SIGNATURE_BASE_PUA_LNX_XMRIG_Cryptominer : FILE
{
	meta:
		description = "Detects XMRIG CryptoMiner software"
		author = "Florian Roth (Nextron Systems)"
		id = "bbdeff2e-68cc-5bbe-b843-3cba9c8c7ea8"
		date = "2018-06-28"
		modified = "2023-01-06"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_xmrig_monero_miner.yar#L53-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
		logic_hash = "501bc5b2d38882f48d1ef972dbbd379afb89f2e7c9bf69192c7bee2e19384816"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
		$s2 = "'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
		$s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
		$s4 = ".nicehash.com" ascii

	condition:
		uint16( 0 ) == 0x457f and filesize < 8000KB and ( 1 of ( $x* ) or 2 of them )
}

rule SIGNATURE_BASE_XMRIG_Monero_Miner : HIGHVOL FILE
{
	meta:
		description = "Detects Monero mining software"
		author = "Florian Roth (Nextron Systems)"
		id = "71bf1b9c-c806-5737-83a9-d6013872b11d"
		date = "2018-01-04"
		modified = "2022-11-10"
		reference = "https://github.com/xmrig/xmrig/releases"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_xmrig_monero_miner.yar#L11-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
		hash = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
		hash = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
		hash = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"
		logic_hash = "532e602dfc8e44326e381d0e2a189b60bc4d4f2b310169767b2326e01606a542"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$s2 = "--cpu-affinity" ascii
		$s3 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" ascii
		$s4 = "password for mining server" fullword ascii
		$s5 = "XMRig/%s libuv/%s%s" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d or uint16( 0 ) == 0x457f ) and filesize < 10MB and 2 of them
}

rule SIGNATURE_BASE_XMRIG_Monero_Miner_Config : FILE
{
	meta:
		description = "Auto-generated rule - from files config.json, config.json"
		author = "Florian Roth (Nextron Systems)"
		id = "374efe7f-9ef2-5974-8e24-f749183ab2d0"
		date = "2018-01-04"
		modified = "2023-12-05"
		reference = "https://github.com/xmrig/xmrig/releases"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_xmrig_monero_miner.yar#L35-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "031333d44a3a917f9654d7e7257e00c9d961ada3bee707de94b7c7d06234909a"
		hash = "409b6ec82c3bdac724dae702e20cb7f80ca1e79efa4ff91212960525af016c41"
		logic_hash = "5df14af366cdb0a5bf6fd88b50876fd78abfe0b795cf10af8fab0d23a54f700f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "\"cpu-affinity\": null,   // set process affinity to CPU core(s), mask \"0x3\" for cores 0 and 1" fullword ascii
		$s5 = "\"nicehash\": false                  // enable nicehash/xmrig-proxy support" fullword ascii
		$s8 = "\"algo\": \"cryptonight\",  // cryptonight (default) or cryptonight-lite" fullword ascii

	condition:
		( uint16( 0 ) == 0x0a7b or uint16( 0 ) == 0x0d7b ) and filesize < 5KB and 1 of them
}

rule TRELLIX_ARC_MINER_Monero_Mining_Detection : MINER FILE
{
	meta:
		description = "Monero mining software"
		author = "Trellix ATR team"
		id = "98ee7711-16ee-58e1-b52f-c68dd5f2b8a3"
		date = "2018-04-05"
		modified = "2022-01-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/miners/MINER_Monero.yar#L1-L43"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "4c1815186b0eb9e6be5fb0fcad02fd981ac9cf79c485fe12ce4a73054ef9fda2"
		score = 75
		quality = 70
		tags = "MINER, FILE"
		rule_version = "v1"
		malware_type = "miner"
		malware_family = "Ransom:W32/MoneroMiner"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
		$3 = "* THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
		$4 = "--user-agent         set custom user-agent string for pool" fullword ascii
		$5 = "-O, --userpass=U:P       username:password pair for mining server" fullword ascii
		$6 = "--cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
		$7 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
		$8 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
		$9 = "-k, --keepalive          send keepalived for prevent timeout (need pool support)" fullword ascii
		$10 = "--max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
		$11 = "--nicehash           enable nicehash/xmrig-proxy support" fullword ascii
		$12 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$13 = "* CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
		$14 = "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" fullword ascii
		$15 = "-B, --background         run the miner in the background" fullword ascii
		$16 = "* API PORT:     %d" fullword ascii
		$17 = "--api-access-token=T access token for API" fullword ascii
		$18 = "-t, --threads=N          number of miner threads" fullword ascii
		$19 = "--print-time=N       print hashrate report every N seconds" fullword ascii
		$20 = "-u, --user=USERNAME      username for mining server" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 4000KB and ( 8 of them ) ) or ( all of them )
}

rule SIGNATURE_BASE_SUSP_LNX_SH_Cryptominer_Indicators_Dec20_1 : FILE
{
	meta:
		description = "Detects helper script used in a crypto miner campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "e376e0e1-1490-5ad4-8ca2-d28ca1c0b51a"
		date = "2020-12-31"
		modified = "2023-12-05"
		reference = "https://www.intezer.com/blog/research/new-golang-worm-drops-xmrig-miner-on-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/crime_crypto_miner.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "3298dbd985c341d57e3219e80839ec5028585d0b0a737c994363443f4439d7a5"
		logic_hash = "4acd1b77307dbf23f95f7a2024209bee714c6931182aff16455ea6b7e4a6f287"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "miner running" fullword ascii
		$x2 = "miner runing" fullword ascii
		$x3 = " --donate-level 1 "
		$x4 = " -o pool.minexmr.com:5555 " ascii

	condition:
		filesize < 20KB and 1 of them
}

rule SIGNATURE_BASE_SUSP_XMRIG_Reference : FILE
{
	meta:
		description = "Detects an executable with a suspicious XMRIG crypto miner reference"
		author = "Florian Roth (Nextron Systems)"
		id = "0a7324ce-90dc-5e6a-b22a-c29eccf324e9"
		date = "2019-06-20"
		modified = "2025-03-21"
		reference = "https://twitter.com/itaitevet/status/1141677424045953024"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/gen_suspicious_strings.yar#L338-L350"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "c1e6f5fc390a8ada0688885bba7ed90372915deba5a5e7e5b0cd17ec450ce240"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "\\xmrig\\" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SIGNATURE_BASE_SUSP_XMRIG_String : FILE
{
	meta:
		description = "Detects a suspicious XMRIG crypto miner executable string in filr"
		author = "Florian Roth (Nextron Systems)"
		id = "8c6f3e6e-df2a-51b7-81b8-21cd33b3c603"
		date = "2018-12-28"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/pua_xmrig_monero_miner.yar#L72-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "eb18ae69f1511eeb4ed9d4d7bcdf3391a06768f384e94427f4fc3bd21b383127"
		logic_hash = "d2c3145c50939e7f407125f7b9312161724b7b1a6fcbf7e27d049e49e982c7e9"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "xmrig.exe" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Ransomwareexx
{
	meta:
		description = "Detects files referencing identities associated with RansomwareEXX Linux ransomware"
		author = "ditekShen"
		id = "dfcff8cb-c50c-559e-b5b9-8c2cdac7a3dc"
		date = "2021-01-21"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_knownbad_id.yar#L142-L150"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "a83ada5d29c6d62a292c4b3a1379558cddcaf63d97dbdfc6afd27cc52f6f656d"
		score = 75
		quality = 73

	strings:
		$s1 = "france.eigs@protonmail.com" ascii wide nocase

	condition:
		any of them
}

rule DITEKSHEN_MALWARE_Linux_Akira : FILE
{
	meta:
		description = "Detects Akira Ransomware Linux"
		author = "ditekSHen"
		id = "3ac144b3-c747-58e5-bc75-b3f90786f404"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L10245-L10264"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "3a00154e1cfc442718e753641d3706ffd4dd8465525d0bb2854f74dfb1cf5dd0"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "https://akira" ascii
		$x2 = ":\\akira\\" ascii
		$x3 = ".akira" ascii
		$x4 = "akira_readme.txt" ascii
		$s1 = "--encryption_" ascii
		$s2 = "--share_file" ascii
		$s3 = { 00 24 52 65 63 79 63 6c 65 2e 42 69 6e 00 24 52 45 43 59 43 4c 45 2e 42 49 4e 00 }
		$s4 = " PUBLIC KEY-----" ascii
		$s5 = ".onion" ascii
		$s6 = "/Esxi_Build_Esxi6/./" ascii nocase
		$s7 = "No path to encrypt" ascii
		$s8 = "-fork" fullword ascii

	condition:
		uint16( 0 ) == 0x457f and ( 3 of ( $x* ) or ( 1 of ( $x* ) and 4 of ( $s* ) ) or 6 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Linux_Buhti : FILE
{
	meta:
		description = "Detects Buhti Ransomware"
		author = "ditekSHen"
		id = "a50b8c34-e9e2-5466-80a1-b0ab805c68be"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L9630-L9643"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "1bab3202dbeaf088b233c3ab1056c357d156b7eef3111bea997b1c610a27f561"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "buhtiRansom" ascii
		$x2 = "://satoshidisk.com/pay/" ascii
		$s1 = "main.encrypt_file" fullword ascii
		$s2 = "/path/to/be/encrypted" ascii
		$s3 = "Restore-My-Files.txt" ascii
		$s4 = ".buhti390625" ascii

	condition:
		uint16( 0 ) == 0x457f and ( all of ( $x* ) or ( 1 of ( $x* ) and 3 of ( $s* ) ) or 5 of them )
}

rule DITEKSHEN_MALWARE_Linux_Chachaddos : FILE
{
	meta:
		description = "ChaChaDDoS variant of XorDDoS payload"
		author = "ditekSHen"
		id = "78a5cf3a-0e84-59bd-a936-bd335647e3d0"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L403-L418"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "2bf99771046650820f02a24d5bd825afeacd03d1e865b05d8563a3ef74d521fb"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "[kworker/1:1]" ascii
		$x2 = "-- LuaSocket toolkit." ascii
		$x3 = "/etc/resolv.conf" ascii
		$x4 = "\"macaddress=\" .. DEVICE_MAC .. \"&device=\" .." ascii
		$x5 = "easy_attack_dns" ascii
		$x6 = "easy_attack_udp" ascii
		$x7 = "easy_attack_syn" ascii
		$x8 = "syn_probe" ascii

	condition:
		uint16( 0 ) == 0x457f and 6 of them
}

rule DITEKSHEN_MALWARE_Linux_Getshell : FILE
{
	meta:
		description = "Detect GetShell Linux backdoor"
		author = "ditekSHen"
		id = "cccad93d-cd49-5237-96ac-66c9ac6ef532"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L10705-L10725"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "9d44ad2a3c270eed0e905402e8c32dcca54da90f4229d9d59874ee09b3b47277"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "MALWARE.Linux.Trojan.GetShell"

	strings:
		$x1 = "cat <(echo '@reboot echo socks5_backconnect" ascii
		$x2 = "(cd  && )') <(sed '/socks5_backconnect" ascii
		$s1 = "cat <(echo '@" ascii
		$s2 = "(cd  && )') <(sed '" ascii
		$s3 = "PORT1:" ascii
		$s4 = "HOST1:" ascii
		$s5 = "queryheader" ascii
		$s6 = "qsectionpost" ascii
		$s7 = "packedip" ascii
		$s8 = "copydata" ascii
		$s9 = "synsend" ascii
		$s10 = "bc_connect" ascii

	condition:
		uint16( 0 ) == 0x457f and ( ( all of ( $x* ) and 1 of ( $s* ) ) or 5 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Linux_Gobrat : FILE
{
	meta:
		description = "Detects GobRAT"
		author = "ditekSHen"
		id = "0561fa99-24ee-5e02-ba54-17a1dd81daa4"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L10044-L10062"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "070687c909b066e38f72b6421b77670e87476d7e1eb1ed8d41d027836629eb71"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "BotList" ascii
		$x2 = "BotCount" ascii
		$x3 = "/etc/services/zone/bot.log" ascii
		$x4 = "aaa.com/bbb/me" ascii
		$s1 = "encoding/gob." ascii
		$s2 = ".GetMacAddress" ascii
		$s3 = ".IpString2Uint32" ascii
		$s4 = ".RegisterLogFile" ascii
		$s5 = ".UniqueAppendString" ascii
		$s6 = ".NewDaemon" ascii
		$s7 = ".SimpleCommand" ascii

	condition:
		uint16( 0 ) == 0x457f and ( 3 of ( $x* ) or ( 2 of ( $x* ) and 3 of ( $s* ) ) or ( 1 of ( $x* ) and 5 of ( $s* ) ) or all of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Linux_Hellokitty : FILE
{
	meta:
		description = "Detects Linux version of HelloKitty ransomware"
		author = "ditekSHen"
		id = "bb228937-8cd8-5fb8-aaed-3bd539ae96f2"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L7722-L7746"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "bcb1188d616b29fa535e757a37476435a3061d27e143339413f6829876701868"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$s1 = "exec_pipe:%s" ascii
		$s2 = "Error InitAPI !!!" fullword ascii
		$s3 = "No Files Found !!!" fullword ascii
		$s4 = "Error open log File:%s" fullword ascii
		$s5 = "%ld - Files Found  " fullword ascii
		$s6 = "Total VM run on host:" fullword ascii
		$s7 = "error:%d open:%s" fullword ascii
		$s8 = "work.log" fullword ascii
		$s9 = "esxcli vm process kill" ascii
		$s10 = "readdir64" fullword ascii
		$s11 = "%s_%d.block" fullword ascii
		$s12 = "EVP_EncryptFinal_ex" fullword ascii
		$s13 = ".README_TO_RESTORE" fullword ascii
		$m1 = "COMPROMISED AND YOUR SENSITIVE PRIVATE INFORMATION WAS STOLEN" ascii nocase
		$m2 = "damage them without special software" ascii nocase
		$m3 = "leaking or being sold" ascii nocase
		$m4 = "Data will be Published and/or Sold" ascii nocase

	condition:
		uint16( 0 ) == 0x457f and ( 6 of ( $s* ) or ( 2 of ( $m* ) and 2 of ( $s* ) ) or 8 of them )
}

rule DITEKSHEN_MALWARE_Linux_Hiddenwasp : FILE
{
	meta:
		description = "HiddenWasp backdoor payload"
		author = "ditekSHen"
		id = "220e5e6e-7c5c-5f70-b3eb-50d9c5ec636d"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L461-L486"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "a2aad022de41ba2633fc92a7dc5a5fa2efde9da2211cfc01fb2999e33365d6c9"
		score = 75
		quality = 71
		tags = "FILE"
		clamav_sig1 = "MALWARE_Linux.Trojan.HiddenWasp-ELF"
		clamav_sig2 = "MALWARE_Linux.Trojan.HiddenWasp-Script"

	strings:
		$x1 = "I_AM_HIDDEN" fullword ascii
		$x2 = "HIDE_THIS_SHELL" fullword ascii
		$x3 = "NewUploadFile" ascii
		$x4 = "fake_processname" ascii
		$x5 = "swapPayload" ascii
		$x6 = /Trojan-(Platform|Machine|Hostname|OSersion)/ fullword ascii
		$s1 = "FileOpration::GetFileData" fullword ascii
		$s2 = "FileOpration::NewUploadFile" fullword ascii
		$s3 = "Connection::writeBlock" fullword ascii
		$s4 = /hiding_(hidefile|enable_logging|hideproc|makeroot)/ fullword ascii
		$s5 = "Reverse-Port" fullword ascii
		$s6 = "hidden_services" fullword ascii
		$s7 = "check_config" fullword ascii
		$s8 = "__data_start" fullword ascii
		$s9 = /patch_(suger_lib|ld|lib)/ fullword ascii
		$s10 = "hexdump -ve '1/1 \"%%.2X\"' %s | sed \"s/%s/%s/g\" | xxd -r -p > %s.tmp"

	condition:
		uint16( 0 ) == 0x457f and ( 4 of ( $x* ) or all of ( $s* ) or ( 3 of ( $x* ) and 5 of ( $s* ) ) )
}

rule DITEKSHEN_MALWARE_Linux_PLEAD : FILE
{
	meta:
		description = "PLEAD Linux payload"
		author = "ditekSHen"
		id = "07aa0561-d6d9-53b6-97ac-670cdf04335d"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L1896-L1920"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "539998248ded0eb8ea1702c527804f89cfd55412f17ec699bd0af801f4fba673"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "MALWARE.Linux.Trojan.PLEAD"

	strings:
		$x1 = "CFileTransfer" ascii
		$x2 = "CFileManager" ascii
		$x3 = "CPortForward" ascii
		$x4 = "CPortForwardManager" ascii
		$x5 = "CRemoteShell" ascii
		$x6 = "CSockClient" ascii
		$s1 = "/proc/self/exe" fullword ascii
		$s2 = "/bin/sh" fullword ascii
		$s3 = "echo -e '" ascii
		$s4 = "%s    <DIR>    %s" ascii
		$s5 = "%s    %lld    %s" ascii
		$s6 = "Files: %d        Size: %lld" ascii
		$s7 = "Dirs: %d" ascii
		$s8 = "%s(%s)/" ascii
		$s9 = "%s %s %s %s" ascii

	condition:
		uint16( 0 ) == 0x457f and ( all of ( $x* ) or all of ( $s* ) or 12 of them )
}

rule DITEKSHEN_MALWARE_Linux_Ransomexx : FILE
{
	meta:
		description = "Detects RansomEXX ransomware"
		author = "ditekshen"
		id = "b449afc7-9055-55ed-a876-316d1aea8fee"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3834-L3858"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "c233ccc3e741cb2c53f182c48093e41595a82a3f4e5bdb1dc0204f1f57b96c2a"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "MALWARE.Linux.Ransomware.RansomEXX"

	strings:
		$c1 = "crtstuff.c" fullword ascii
		$c2 = "cryptor.c" fullword ascii
		$c3 = "ransomware.c" fullword ascii
		$c4 = "logic.c" fullword ascii
		$c5 = "enum_files.c" fullword ascii
		$c6 = "readme.c" fullword ascii
		$c7 = "ctr_drbg.c" fullword ascii
		$s1 = "regenerate_pre_data" fullword ascii
		$s2 = "g_RansomHeader" fullword ascii
		$s3 = "CryptOneBlock" fullword ascii
		$s4 = "RansomLogic" fullword ascii
		$s5 = "CryptOneFile" fullword ascii
		$s6 = "encrypt_worker" fullword ascii
		$s7 = "list_dir" fullword ascii
		$s8 = "ctr_drbg_update_internal" fullword ascii

	condition:
		uint16( 0 ) == 0x457f and ( 5 of ( $c* ) or 6 of ( $s* ) or ( 3 of ( $c* ) and 3 of ( $s* ) ) )
}

rule DITEKSHEN_MALWARE_Linux_UNK01 : FILE
{
	meta:
		description = "Detects unknown/unidentified Linux malware"
		author = "ditekSHen"
		id = "24c6ff35-9378-5a6b-90d1-9740917b1b72"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L2815-L2836"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "8bb4822c1c7e0f52726ecafafa696d83c741257587f351360c5295163c245450"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$f1 = "%sresponse.php?status" ascii
		$f2 = "%supstream.php?mid=%s&os=%s" ascii fullword
		$f3 = "%supstream.php?tid=%" ascii
		$f4 = "%sindex.php?token=%.32s&flag=%d&name=%s" ascii fullword
		$f5 = "%sactive_off.php?id=%d&uniqu=%d" ascii fullword
		$s1 = "lock:%i usable num:%i n:%i" fullword ascii
		$s2 = "tid:%.*s tNumber:%i" fullword ascii
		$s3 = "init.php" fullword ascii
		$s4 = "mod_drone" fullword ascii
		$s5 = "new_mid" fullword ascii
		$s6 = "&exists[]=" fullword ascii
		$s7 = "&mod[]=" fullword ascii
		$s8 = "shutdown" fullword ascii
		$s9 = "&mac[]=%02X%02X%02X%02X%02X%02X" fullword ascii

	condition:
		uint16( 0 ) == 0x457f and ( 3 of ( $f* ) or 6 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Linux_UNK02 : FILE
{
	meta:
		description = "Detects unknown/unidentified Linux malware"
		author = "ditekSHen"
		id = "6e62df0d-d329-5e52-af74-2a1f19dc4cca"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L2838-L2852"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "4cde21932c27fe3c08495f557b5e086b1fb668d8b5508249891828b9ed48edd4"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$rf1 = "[]A\\A]A^A_" ascii
		$rf2 = "[A\\A]A^A_]" ascii
		$f1 = "/bin/basH" ascii fullword
		$f2 = "/proc/seH" ascii fullword
		$f3 = "/dev/ptsH" ascii fullword
		$f4 = "pqrstuvwxyzabcde" ascii fullword
		$f5 = "libnss_%s.so.%d.%d" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and ( all of ( $f* ) and #rf1 > 3 and #rf2 > 3 )
}

rule DITEKSHEN_MALWARE_Linux_Xorddos : FILE
{
	meta:
		description = "Detects XORDDoS"
		author = "ditekSHen"
		id = "0ca581c3-bce2-5b4f-8146-9aeb49b88813"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L2209-L2220"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "192378d903316c1d80b064e78feb6ed9d2ffc9e6c7dc0c8df223d83d17e4e8d9"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done" fullword ascii
		$s2 = "cp /lib/libudev.so /lib/libudev.so.6" fullword ascii
		$s3 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii
		$s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii

	condition:
		uint32( 0 ) == 0x464c457f and 3 of them
}

rule DITEKSHEN_MALWARE_Multi_Exaramel : FILE
{
	meta:
		description = "Exaramel Windows/Linux backdoor payload"
		author = "ditekSHen"
		id = "014f10f3-4502-5719-93f6-4b2940f53876"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L420-L459"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "e64383304bc913b07a2e63d61c81354b996c01171357005f4a28957d4d889599"
		score = 75
		quality = 73
		tags = "FILE"
		clamav_sig1 = "MALWARE_Linux.Backdoor.Exaramel"
		clamav_sig2 = "MALWARE_Win.Backdoor.Exaramel"

	strings:
		$s1 = "vendor/golang_org/x/crypto/" ascii
		$s2 = "vendor/golang_org/x/net/http2" ascii
		$s3 = "vendor/golang_org/x/text/unicode" ascii
		$s4 = "vendor/golang_org/x/text/transform" ascii
		$s5 = "config.json" ascii
		$cmd1 = "App.Update" ascii
		$cmd2 = "App.Delete" ascii
		$cmd3 = "App.SetProxy" ascii
		$cmd4 = "App.SetServer" ascii
		$cmd5 = "App.SetTimeout" ascii
		$cmd6 = "IO.WriteFile" ascii
		$cmd7 = "IO.ReadFile" ascii
		$cmd8 = "OS.ShellExecute" ascii
		$cmd9 = "awk 'match($0, /(upstart|systemd|sysvinit)/){ print substr($0, RSTART, RLENGTH);exit;" ascii
		$ws1 = "/commands/@slp" wide
		$ws2 = "/commands/cmd" wide
		$ws3 = "/settings/proxy/@password" wide
		$ws4 = "/settings/servers/server[@current='true']" wide
		$ws5 = "/settings/servers/server/@current[text()='true']" wide
		$ws6 = "/settings/servers/server[text()='%s']/@current" wide
		$ws7 = "/settings/servers/server[%d]" wide
		$ws8 = "/settings/storage" wide
		$ws9 = "/settings/check" wide
		$ws10 = "/settings/interval" wide
		$ws11 = "report.txt" wide
		$ws12 = "stg%02d.cab" ascii
		$ws13 = "urlmon.dll" ascii
		$ws14 = "ReportDir" ascii

	condition:
		( uint16( 0 ) == 0x457f and ( all of ( $s* ) and 6 of ( $cmd* ) ) ) or ( uint16( 0 ) == 0x5a4d and 12 of ( $ws* ) )
}

rule DITEKSHEN_MALWARE_Multi_Wellmess : FILE
{
	meta:
		description = "WellMess Windows/Linux backdoor payload"
		author = "ditekSHen"
		id = "cfa0f077-9d45-5796-b888-66fb397e74f8"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L488-L510"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "9cbbca609fd289d7406d9073237688d250dc68c450676b9b755509540d8f76a5"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig1 = "MALWARE_Win.Trojan.WellMess_DotNet"
		clamav_sig2 = "MALWARE_Win.Trojan.WellMess_Golang"
		clamav_sig3 = "MALWARE_Linux.Trojan.WellMess_Golang"

	strings:
		$s1 = "-----BEGIN PUBLIC KEY-----" ascii
		$s2 = "-----END PUBLIC KEY-----" ascii
		$s3 = "net/http.(*persistConn).readResponse" ascii
		$s4 = "net/http/cookiejar.(*Jar).SetCookies" ascii
		$s5 = "_/home/ubuntu/GoProject/src/bot/botlib" ascii
		$s6 = "<;head;><;title;>" ascii
		$s7 = "<;title;><;service;>" ascii
		$s8 = "http://invalidlookup" ascii
		$s9 = "<autogenerated>" ascii wide

	condition:
		( uint16( 0 ) == 0x457f or uint16( 0 ) == 0x5a4d ) and all of them
}

rule ESET_Kobalos_Ssh_Credential_Stealer
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Léveillé"
		id = "b1fc5163-de48-57fc-8ae7-1f2be6c64d8a"
		date = "2020-11-02"
		modified = "2021-02-01"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/705ead5a0a86fefae3c2390f91a339852384f438/kobalos/kobalos.yar#L58-L73"
		license_url = "https://github.com/eset/malware-ioc/blob/705ead5a0a86fefae3c2390f91a339852384f438/LICENSE"
		logic_hash = "be238f5c2cc976a5638584a8c0fc580f2076735aadfe374e8d4162ba723bce10"
		score = 75
		quality = 80
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		any of them
}

rule FIREEYE_RT_APT_Controller_Linux_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "79a69740-7209-5c56-ad6f-eb4d0b29beaf"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Controller_Linux_REDFLARE_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		logic_hash = "d6b0cc5f386da9bff8a8293f2b3857406044ab42f7c1bb23d5096052a3c42ce4"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "/RedFlare/gorat_server"
		$2 = "RedFlare/sandals"
		$3 = "goratsvr.CommandResponse" fullword
		$4 = "goratsvr.CommandRequest" fullword

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Linux_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "220302bc-4ed3-5e10-9bd2-a8ed2bdaef73"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/supplemental/yara/APT_Trojan_Linux_REDFLARE_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		logic_hash = "282f11c4c86d88d05f11e92f5483701d9a54c2dd39f21316cd271aa78a338d0f"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "find_applet_by_name" fullword
		$s2 = "bb_basename" fullword
		$s3 = "hk_printf_chk" fullword
		$s4 = "runCommand" fullword
		$s5 = "initialize" fullword

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule SEKOIA_Backdoor_Lin_Bpfdoor : FILE
{
	meta:
		description = "Detect the BPFDoor backdoor used by the Chinese TA Red Menshen"
		author = "Sekoia.io"
		id = "1776ff6f-6fbb-4a81-bcad-c43b5117c67c"
		date = "2022-05-05"
		modified = "2024-12-19"
		reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/mal_lnx_implant_may22.yar"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/backdoor_lin_bpfdoor.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "c917bd12731d761645adea72bc68c50927a0c2b0c31b2109f7065a992d338329"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
		$op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
		$op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
		$op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }

	condition:
		uint32( 0 ) == 0x464c457f and filesize > 10KB and filesize < 50KB and ( all of ( $op* ) )
}

rule SEKOIA_Bot_Lin_Xorddos_Strings : FILE
{
	meta:
		description = "Catch XORDDoS strings"
		author = "Sekoia.io"
		id = "2f5c70a3-fe3f-4091-905d-d779bd0cb2cd"
		date = "2023-11-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/bot_lin_xorddos_strings.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "b91cfeeaddffe98ac1649c5d88a2091cf7ab8ff65b232f09c323d23684cb2a2d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" ascii fullword
		$s2 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" ascii fullword
		$s3 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done"

	condition:
		uint32( 0 ) == 0x464c457f and filesize > 600KB and filesize < 700KB and 3 of them
}

rule SEKOIA_Bot_Lin_Zerobot_Dec22 : FILE
{
	meta:
		description = "Detect the linux Zerobot implant using specific strings"
		author = "Sekoia.io"
		id = "ce028297-a526-4a6a-95db-8762fb5895f6"
		date = "2022-08-05"
		modified = "2024-12-19"
		reference = "https://www.fortinet.com/blog/threat-research/zerobot-new-go-based-botnet-campaign-targets-multiple-vulnerabilities"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/bot_lin_zerobot_dec22.yar#L1-L30"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "0f4faba9873fa360615b20bc637ecb40f56e6c7f65153f61a762e378320f94c1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "rm -rf "
		$str02 = "wget http://"
		$str03 = "curl -O http://"
		$str04 = "tftp"
		$str05 = "-c get"
		$str06 = "ftpget -v -u anonymous -P"
		$str07 = "chmod 777"
		$str08 = "nohup"
		$str09 = "/dev/null 2>&1 &"
		$str10 = "zero."
		$str11 = "ppc64le"
		$str12 = "riscv64"
		$str13 = "s390x"
		$str14 = "rm -rf ~/.bash_history"
		$str15 = "history -c"

	condition:
		11 of ( $str* ) and filesize < 10KB
}

rule SEKOIA_Ransomware_Lin_Avoslocker_Strings : FILE
{
	meta:
		description = "Detect AvosLocker ransomware for Linux by using strings from its ransom note and the onion domains"
		author = "Sekoia.io"
		id = "6056e15c-d656-41cb-bea0-704776c52c92"
		date = "2022-02-21"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/ransomware_lin_avoslocker_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		hash = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
		hash = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
		hash = "10ab76cd6d6b50d26fde5fe54e8d80fceeb744de8dbafddff470939fac6a98c4"
		logic_hash = "b65cf6713027644de281f17a4c5c170fc09a154e7119d04a92aceed0e2d7e4fd"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "The corporations whom don't pay or fail to respond in a swift manner can be found in our blog, accessible at" ascii
		$s2 = "http://avosqxh72b5ia23dl5fgwcpndkctuzqvh2iefk5imp3pi5gfhel5klad.onion" ascii
		$s3 = "http://avosjon4pfh3y7ew3jdwz6ofw7lljcxlbk7hcxxmnxlh5kvf2akcqjad.onion" ascii

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule SIGNATURE_BASE_APT_APT41_CN_ELF_Speculoos_Backdoor : FILE
{
	meta:
		description = "Detects Speculoos Backdoor used by APT41"
		author = "Florian Roth (Nextron Systems)"
		id = "efe2b368-33af-5382-a5f0-0e7dd7f4dea4"
		date = "2020-04-14"
		modified = "2023-12-05"
		reference = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_apt41.yar#L233-L267"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167"
		hash = "99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28"
		logic_hash = "ee4cbbc5fc51fb24cbf6017dfb4763ac72a0b23a3b6e794b909e678ebfbabc03"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$xc1 = { 2F 70 72 69 76 61 74 65 2F 76 61 72 00 68 77 2E
               70 68 79 73 6D 65 6D 00 68 77 2E 75 73 65 72 6D
               65 6D 00 4E 41 2D 4E 41 2D 4E 41 2D 4E 41 2D 4E
               41 2D 4E 41 00 6C 6F 30 00 00 00 00 25 30 32 78
               2D 25 30 32 78 2D 25 30 32 78 2D 25 30 32 78 2D
               25 30 32 78 2D 25 30 32 78 0A 00 72 00 4E 41 00
               75 6E 61 6D 65 20 2D 76 }
		$s1 = "badshell" ascii fullword
		$s2 = "hw.physmem" ascii fullword
		$s3 = "uname -v" ascii fullword
		$s4 = "uname -s" ascii fullword
		$s5 = "machdep.tsc_freq" ascii fullword
		$s6 = "/usr/sbin/config.bak" ascii fullword
		$s7 = "enter MessageLoop..." ascii fullword
		$s8 = "exit StartCBProcess..." ascii fullword
		$sc1 = { 72 6D 20 2D 72 66 20 22 25 73 22 00 2F 70 72 6F
               63 2F }

	condition:
		uint16( 0 ) == 0x457f and filesize < 600KB and 1 of ( $x* ) or 4 of them
}

rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Eraser_1 : FILE
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		id = "36d17887-9844-5fa4-8a0d-89cc41b2d876"
		date = "2020-05-16"
		modified = "2023-12-05"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/crime_academic_data_centers_camp_may20.yar#L1-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"
		logic_hash = "9a0410e86fa8fb8b599e5b8a6508d6889eb6e26600f0ecf222561ac4a169676d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sc2 = { E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE
               00 00 00 00 89 C7 E8 }
		$sc3 = { E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01
               00 00 00 48 89 C7 E8 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 60KB and all of them
}

rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Loader_1 : FILE
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		id = "cda65abd-d918-5ee6-8f4a-554d47532d76"
		date = "2020-05-16"
		modified = "2023-12-05"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/crime_academic_data_centers_camp_may20.yar#L20-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"
		logic_hash = "a73883f9fdf3d53694d9f9efec5f8f15994c5fd80c5f2a87b1741db6b954a023"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sc1 = { C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A 
               C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01 }
		$sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D }

	condition:
		uint16( 0 ) == 0x457f and filesize < 10KB and all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos : FILE
{
	meta:
		description = "Kobalos malware"
		author = "Marc-Etienne M.Leveille"
		id = "dfa47e30-c093-57f6-af01-72a2534cc6f4"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_lnx_kobalos.yar#L32-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "48aec47b70633d4c8cb55d90a2e168f3c2027ef27cfe1cd5d30dcdc08a2ff717"
		score = 75
		quality = 85
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
		$password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
		$rsa_512_mod_header = { 10 11 02 00 09 02 00 }
		$strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

	condition:
		uint16( 0 ) == 0x457f and any of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos_SSH_Credential_Stealer : FILE
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Leveille"
		id = "0f923f92-c5d8-500d-9a2e-634ca7945c5c"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_lnx_kobalos.yar#L59-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "fdabaea0c838e43b8716bcd102bdeebf2f08fc041b0b909333e3d9d6f94391fc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		uint16( 0 ) == 0x457f and any of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_1 : FILE
{
	meta:
		description = "Detects unknown Linux implants (uploads from KR and MO)"
		author = "Florian Roth (Nextron Systems)"
		id = "1438c3bf-3c42-59d5-9f3f-2d72bdaaac42"
		date = "2022-05-05"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_lnx_implant_may22.yar#L45-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
		hash = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
		hash = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
		hash = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
		hash = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
		hash = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
		hash = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
		hash = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
		hash = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
		hash = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
		logic_hash = "8de10beea4ef2e059b16d38fb015d6f091cc517b6f0c06b6ef6868518349994d"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "[-] Connect failed." ascii fullword
		$s2 = "export MYSQL_HISTFILE=" ascii fullword
		$s3 = "udpcmd" ascii fullword
		$s4 = "getshell" ascii fullword
		$op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
		$op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
		$op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
		$op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }

	condition:
		uint16( 0 ) == 0x457f and filesize < 80KB and 2 of them or 5 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_2 : FILE
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		id = "d5c3d530-ed6f-563e-a3b0-55d4c82e4899"
		date = "2022-05-07"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_lnx_implant_may22.yar#L78-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
		logic_hash = "7525c675dbba6eb480f1d28fc6db05bd9907725c291e64ee6dc2453fd42892a0"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
		$opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }
		$op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
		$op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
		$op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 100KB and 2 of ( $opx* ) or 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_3 : FILE
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		id = "91c2153a-a6e0-529e-852c-61f799838798"
		date = "2022-05-08"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_lnx_implant_may22.yar#L102-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
		hash = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
		logic_hash = "afec0bfeddf5c5c2abc1a3173f636c385437e5d7c0b68665f6274011113a6a9c"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$s2 = "/sbin/mingetty /dev" ascii fullword
		$s3 = "pickup -l -t fifo -u" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them or all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1 : FILE
{
	meta:
		description = "Detects Turla Linux malware x64 x32"
		author = "Leonardo S.p.A."
		id = "2da75433-b1c1-51b3-8f7a-a4442ca3de96"
		date = "2020-04-24"
		modified = "2023-12-05"
		reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_turla_penquin.yar#L2-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		hash = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
		hash = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
		hash = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
		hash = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
		hash = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
		logic_hash = "1e07963c492f1e6264f01ee292e40b188ca325b76005d9d48e6dc198cb9bdcf4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "/root/.hsperfdata" ascii fullword
		$ = "Desc| Filename | size |state|" ascii fullword
		$ = "VS filesystem: %s" ascii fullword
		$ = "File already exist on remote filesystem !" ascii fullword
		$ = "/tmp/.sync.pid" ascii fullword
		$ = "rem_fd: ssl " ascii fullword
		$ = "TREX_PID=%u" ascii fullword
		$ = "/tmp/.xdfg" ascii fullword
		$ = "__we_are_happy__" ascii
		$ = "/root/.sess" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1_Opcode : FILE
{
	meta:
		description = "Detects Turla Linux malware x64 x32"
		author = "Leonardo S.p.A."
		id = "03043f59-c81a-5423-bec1-6cd88f6e3c52"
		date = "2020-04-24"
		modified = "2023-12-05"
		reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_turla_penquin.yar#L35-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		hash = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
		hash = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
		hash = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
		hash = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
		hash = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
		logic_hash = "19524e6ec3b0d49ff9c85ce361ef1922b92e4f7876ddb7d6c9b209b5357080e3"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 }
		$op1 = { 48FFC14883F94975E9 }
		$op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
		$op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0}
		$op4 = { 88D380C305329AC1D60C08889A60A10F084283FA0876E9 }
		$op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 }
		$op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB }
		$op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB}

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 2 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr20_1 : FILE
{
	meta:
		description = "Detects Turla Linux malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f21e7793-a7dd-5195-805d-963827b35808"
		date = "2020-04-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/Int2e_/status/1246115636331319309"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_turla.yar#L252-L272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		logic_hash = "d463f5a151bb0c3440d719b4c7c0d1ca34de1e0bed7fb9167ecf396607abd3ff"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "/root/.hsperfdata" ascii fullword
		$s2 = "Desc|     Filename     |  size  |state|" ascii fullword
		$s3 = "IPv6 address %s not supported" ascii fullword
		$s4 = "File already exist on remote filesystem !" ascii fullword
		$s5 = "/tmp/.sync.pid" ascii fullword
		$s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Socket_Path
{
	meta:
		description = "Detects path of the unix socket created to prevent concurrent executions in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "3aab84c9-9748-5d11-9cd7-efa9151036cf"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_centreon.yar#L134-L146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "8c049b5a7b508ca0f160d166f3c726e4a23a2c5b3105d075d7bf7a301a1c58f6"
		score = 80
		quality = 85

	strings:
		$ = "/tmp/.applocktx"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_Sandworm_SSHD_Config_Modification_May20_1 : FILE
{
	meta:
		description = "Detects ssh config entry inserted by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "dd60eeb7-3d4b-5a6a-8054-50c617ee8c73"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_exim_expl.yar#L33-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		logic_hash = "5775588b3a9d44e9eb2c8ef0f50351d7e3b06f1005f669775fae7187900d5999"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "AllowUsers mysql_db" ascii
		$a1 = "ListenAddress" ascii fullword

	condition:
		filesize < 10KB and all of them
}

rule SIGNATURE_BASE_EXPL_LNX_CUPS_CVE_2024_47177_Sep24 : CVE_2024_47177 FILE
{
	meta:
		description = "Detects exploit code for CUPS CVE-2024-47177"
		author = "Florian Roth"
		id = "a7b986ad-e943-5350-a6e0-34c40f07874c"
		date = "2024-09-27"
		modified = "2024-12-12"
		reference = "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_cups_sep24.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "633314dea5e3cbdf3cef6e4f18c2efca261dfc600bb9c11d0834fdae102ac9e6"
		score = 75
		quality = 85
		tags = "CVE-2024-47177, FILE"

	strings:
		$s1 = "FoomaticRIPCommandLine: " ascii
		$s2 = "cupsFilter2 : " ascii

	condition:
		filesize < 400KB and all of them
}

rule SIGNATURE_BASE_EXPL_LNX_Dirtyfrag_Forensicartefacts_May26 : FILE
{
	meta:
		description = "Detects DirtyFrag exploit code POC usage in Linux environments"
		author = "Florian Roth"
		id = "bda5e087-8eb7-55bd-a5ff-0eef91d63bcf"
		date = "2026-05-08"
		modified = "2026-05-15"
		reference = "https://github.com/V4bel/dirtyfrag/tree/master"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_lnx_dirtyfrag.yar#L62-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "3790a19c180d1fcdcaf91c13b858d63adf126e9282999ccd424a0e6b9ae0e094"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$xa1 = "/V4bel/dirtyfrag.git" ascii
		$xa2 = "static const uint8_t shell_elf[PAYLOAD_LEN] = {" ascii
		$xa3 = "/usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii

	condition:
		filesize < 800KB and 1 of ( $xa* )
}

rule SIGNATURE_BASE_EXT_HKTL_MAL_Tinyshell_Backdoor : FILE
{
	meta:
		description = "Detects Tiny Shell - an open-source UNIX backdoor"
		author = "Mandiant"
		id = "4ad5d334-98e4-577f-89c9-86626e8feb58"
		date = "2022-03-17"
		modified = "2026-05-15"
		reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_unc2891_tinyshell_slapstick.yar#L1-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "1f889871263bd6cdad8f3d4d5fc58b4a32669b944d3ed0860730374bb87d730a"
		logic_hash = "1fe9def11dced638ad38236652877427b61d7138fc8c6ce3fe7f1403c367468f"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$sb1 = { C6 00 48 C6 4? ?? 49 C6 4? ?? 49 C6 4? ?? 4C C6 4? ?? 53 C6 4? ?? 45 C6 4? ?? 54 C6 4? ?? 3D C6 4? ?? 46 C6 4? ?? 00 }
		$sb2 = { C6 00 54 C6 4? ?? 4D C6 4? ?? 45 C6 4? ?? 3D C6 4? ?? 52 }
		$ss1 = "fork" ascii fullword wide
		$ss2 = "socket" ascii fullword wide
		$ss3 = "bind" ascii fullword wide
		$ss4 = "listen" ascii fullword wide
		$ss5 = "accept" ascii fullword wide
		$ss6 = "alarm" ascii fullword wide
		$ss7 = "shutdown" ascii fullword wide
		$ss8 = "creat" ascii fullword wide
		$ss9 = "write" ascii fullword wide
		$ss10 = "open" ascii fullword wide
		$ss11 = "read" ascii fullword wide
		$ss12 = "execl" ascii fullword wide
		$ss13 = "gethostbyname" ascii fullword wide
		$ss14 = "connect" ascii fullword wide

	condition:
		uint32( 0 ) == 0x464c457f and 1 of ( $sb* ) and 10 of ( $ss* )
}

rule SIGNATURE_BASE_EXT_HKTL_MAL_Tinyshell_Backdoor_SPARC : FILE
{
	meta:
		description = "Detects Tiny Shell variant for SPARC - an open-source UNIX backdoor"
		author = "Mandiant"
		id = "0a05a316-65b7-5cdf-849b-820ab60afbbd"
		date = "2022-03-17"
		modified = "2026-05-15"
		reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_unc2891_tinyshell_slapstick.yar#L31-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "cda78e26c2e274d24d1e4656fcd09af2930f43af7fac01a3f410a5692d79a5ae"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$sb_xor_1 = { DA 0A 80 0C 82 18 40 0D C2 2A 00 0B 96 02 E0 01 98 03 20 01 82 1B 20 04 80 A0 00 01 82 60 20 00 98 0B 00 01 C2 4A 00 0B 80 A0 60 00 32 BF FF F5 C2 0A 00 0B 81 C3 E0 08 }
		$sb_xor_2 = { C6 4A 00 00 80 A0 E0 00 02 40 00 0B C8 0A 00 00 85 38 60 00 C4 09 40 02 84 18 80 04 C4 2A 00 00 82 00 60 01 80 A0 60 04 83 64 60 00 10 6F FF F5 90 02 20 01 81 C3 E0 08 }

	condition:
		uint32( 0 ) == 0x464C457F and ( uint16( 0x10 ) & 0x0200 == 0x0200 ) and ( uint16( 0x12 ) & 0x0200 == 0x0200 ) and 1 of them
}

rule SIGNATURE_BASE_FE_APT_Trojan_Linux_PACEMAKER : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "5a20260a-5389-57da-956c-97063fed5015"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_pulsesecure.yar#L99-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "d7881c4de4d57828f7e1cab15687274b"
		logic_hash = "cf83024cbbd500a301ac3c859b680cd79acabc232ea6f42c23fe9f8918a8d914"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00"
		$s2 = "\x00/proc/%d/mem\x00"
		$s3 = "\x00/proc/%s/maps\x00"
		$s4 = "\x00/proc/%s/cmdline\x00"

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_ELF_Backdoor_Fipps : FILE
{
	meta:
		description = "Detects a Linux backdoor named Fipps used by Andariel"
		author = "CISA.gov"
		id = "040bca78-8b7e-5397-8a2b-1ddeed59eea3"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_nk_andariel_jul24.yar#L291-L307"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "3b57eb6c6b89e93863b9600c4a1384f3e064f236e827ef9ffc37b1e5dcff7d24"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$a = "found mac address"
		$b = "RecvThread"
		$c = "OpenSSL-1.0.0-fipps"
		$d = "Disconnected!"

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule SIGNATURE_BASE_MAL_ARM_LNX_Mirai_Mar13_2022 : FILE
{
	meta:
		description = "Detects new ARM Mirai variant"
		author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
		id = "54d8860e-fc45-5571-b68c-66590c67a705"
		date = "2022-03-16"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/crime_mirai.yar#L159-L181"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"
		logic_hash = "a44a6174a198a658c8a5e2da50192da20bae7f8ed4e4f212c9eebb29fa4b0dd0"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
		$str2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
		$str3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
		$str4 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
		$attck1 = "attack.c"
		$attck2 = "attacks.c"
		$attck3 = "anti_gdb_entry"
		$attck4 = "resolve_cnc_addr"
		$attck5 = "attack_gre_eth"
		$attck6 = "attack_udp_generic"
		$attck7 = "attack_get_opt_ip"
		$attck8 = "attack_icmpecho"

	condition:
		uint16( 0 ) == 0x457f and ( 3 of ( $str* ) or 4 of ( $attck* ) )
}

rule SIGNATURE_BASE_MAL_Cisco_Rayinitiator_Stage_2
{
	meta:
		description = "Detects RayInitiator GRUB bootkit stage 2 code that identifies the Linux kernel syscall table."
		author = "NCSC"
		id = "c49bdbe7-eba6-562c-8388-5e638887b405"
		date = "2025-09-25"
		modified = "2026-05-15"
		reference = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_cisco_asa_lineviper_rayinitiator_sep25.yar#L22-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "27f040bc14caec745f04fa32de08955a09857a801e5f2f04936fffca991c9d19"
		score = 85
		quality = 85

	strings:
		$xc1 = {
         49 89 E0 48 83 F8 30 0F 84 70 00 00 00 49 01 C0 49 8B
         10 48 83 C0 08 66 85 D2 75 E4 BF ?? ?? 60 00 48 8B 3C 17 48 BE 6E
         6D 69 5F 6D 61 78 5F
      }

	condition:
		$xc1
}

rule SIGNATURE_BASE_MAL_ELF_SALTWATER_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
		author = "Florian Roth"
		id = "10a038f6-6096-5d3a-aaf5-db441685102b"
		date = "2023-06-07"
		modified = "2023-12-05"
		reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_lnx_barracuda_cve_2023_2868.yar#L21-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"
		logic_hash = "cb35898c0ee726170da93b4364920ac065f083f9f02db8eb5d293b1ce127cb78"
		score = 80
		quality = 85
		tags = "CVE-2023-2868, FILE"

	strings:
		$x1 = "libbindshell.so"
		$s1 = "ShellChannel"
		$s2 = "MyWriteAll"
		$s3 = "CheckRemoteIp"
		$s4 = "run_cmd"
		$s5 = "DownloadByProxyChannel"
		$s6 = "[-] error: popen failed"
		$s7 = "/home/product/code/config/ssl_engine_cert.pem"

	condition:
		uint16( 0 ) == 0x457f and filesize < 6000KB and ( ( 1 of ( $x* ) and 2 of them ) or 3 of them ) or all of them
}

rule SIGNATURE_BASE_MAL_ELF_Torchtriton : FILE
{
	meta:
		description = "Detection for backdoor (TorchTriton) distributed with a nightly build of PyTorch"
		author = "Silas Cutler"
		id = "85e98ee7-30bf-554f-a0ac-9df263e6dfe4"
		date = "2023-01-02"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/news/security/pytorch-discloses-malicious-dependency-chain-compromise-over-holidays/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/gen_100days_of_yara_2023.yar#L88-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "2385b29489cd9e35f92c072780f903ae2e517ed422eae67246ae50a5cc738a0e"
		logic_hash = "12de3c3785aaf3623097db58abfe8ee2cbd9a0e712bf752165952de9a5fdb07d"
		score = 75
		quality = 85
		tags = "FILE"
		version = "1.0"
		DaysofYARA = "2/100"

	strings:
		$error = "failed to send packet"
		$aes_key = "gIdk8tzrHLOM)mPY-R)QgG[;yRXYCZFU"
		$aes_iv = "?BVsNqL]S.Ni"
		$func01 = "splitIntoDomains("
		$func02 = "packageForTransport"
		$func03 = "gatherFiles"
		$func04 = "void sendFile("
		$domain = "&z-%`-(*"

	condition:
		uint32( 0 ) == 0x464c457f and ( ( all of ( $aes_* ) ) or ( all of ( $func* ) and $error ) or ( $domain and 2 of them ) )
}

rule SIGNATURE_BASE_MAL_ELF_Xlogin_Nov24_1 : FILE
{
	meta:
		description = "Detects xlogin backdoor samples"
		author = "Florian Roth"
		id = "e8940660-ecf8-5616-9cb1-fc0a02d35689"
		date = "2024-11-11"
		modified = "2024-12-12"
		reference = "https://blog.sekoia.io/solving-the-7777-botnet-enigma-a-cybersecurity-quest/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_xlogin_nov24.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "2b09a6811a9d0447f8c6480430eb0f7e3ff64fa933d0b2e8cd6117f38382cc6a"
		hash = "d1cbf80786b1ca1ba2e5c31ec09159be276ad3d10fc0a8a0dbff229d8263ca0a"
		hash = "ff17e9bcc1ed16985713405b95745e47674ec98e3c6c889df797600718a35b2c"
		logic_hash = "42fe8a32022592ff976d6d2839d949e28f60c8958f64a20c1c3c9091fb64d31e"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$xc1 = { 6C 6F 67 69 6E 3A 00 25 73 00 00 2F 62 69 6E 2F 73 68 00 2F 74 6D 70 2F 6C 6F 67 69 6E }
		$s1 = "/tmp/login" ascii fullword
		$s2 = "npxXoudifFeEgGaACSnmcs[" ascii fullword
		$sc1 = { 28 6E 69 6C 29 00 00 00 28 6E 75 6C 6C 29 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 500KB and ( 1 of ( $x* ) or 2 of them )
}

rule SIGNATURE_BASE_MAL_LNX_Camarodragon_Horseshell_Oct23 : FILE
{
	meta:
		description = "Detects CamaroDragon's HorseShell implant for routers"
		author = "Florian Roth"
		id = "9e54745f-146f-50a6-b30f-53aaaa6907b5"
		date = "2023-10-06"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_camaro_dragon_oct23.yar#L27-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "998788472cb1502c03675a15a9f09b12f3877a5aeb687f891458a414b8e0d66c"
		logic_hash = "73adaa286b345cffd35e6ba017b3204d8818dcaeea8a48ca93959566461ac3ca"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "echo \"start shell '%s' failed!\" > .remote_shell.log" ascii fullword
		$x2 = "*****recv NET_REQ_HORSE_SHELL REQ_CONNECT_PORT*****" ascii fullword
		$s1 = "m.cremessage.com" ascii fullword
		$s2 = "POST http://%s/index.php HTTP/1.1" ascii fullword
		$s3 = "wzsw_encrypt_buf" ascii fullword
		$s4 = "body:%d-%s" ascii fullword
		$s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident" ascii fullword
		$s6 = "process_http_read_events" ascii fullword
		$op1 = { c4 34 42 00 02 30 63 00 40 10 60 00 09 ae 62 00 48 8e 62 00 cc }
		$op2 = { 27 f4 8c 46 27 f0 03 20 f8 09 00 60 28 21 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 600KB and ( 1 of ( $x* ) or 3 of them ) or 5 of them
}

rule SIGNATURE_BASE_MAL_LNX_Camarodragon_Sheel_Oct23 : FILE
{
	meta:
		description = "Detects CamaroDragon's tool named sheel"
		author = "Florian Roth"
		id = "f6f08c0e-236c-5194-9369-da8fdef4aa21"
		date = "2023-10-06"
		modified = "2023-12-05"
		reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_camaro_dragon_oct23.yar#L2-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"
		logic_hash = "b06f645b766a099adb71c144bdced70c130735e75d5be6451f71077c7d3a5d19"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword
		$s1 = "read_ip" ascii fullword
		$s2 = "open fail.%m" ascii fullword
		$s3 = "ri:h:p:" ascii fullword
		$s4 = "update server list success!" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 30KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

rule SIGNATURE_BASE_MAL_LNX_Linadoor_Rootkit_May22 : FILE
{
	meta:
		description = "Detects LinaDoor Linux Rootkit"
		author = "Florian Roth"
		id = "e2f250b4-9a8a-5d70-83d7-5d12ad3763fb"
		date = "2022-05-19"
		modified = "2023-05-16"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_lnx_linadoor_rootkit.yar#L2-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "25ff1efe36eb15f8e19411886217d4c9ec30b42dca072b1bf22f041a04049cd9"
		hash = "4792e22d4c9996af1cb58ed54fee921a7a9fdd19f7a5e7f268b6793cdd1ab4e7"
		hash = "9067230a0be61347c0cf5c676580fc4f7c8580fc87c932078ad0c3f425300fb7"
		hash = "940b79dc25d1988dabd643e879d18e5e47e25d0bb61c1f382f9c7a6c545bfcff"
		hash = "a1df5b7e4181c8c1c39de976bbf6601a91cde23134deda25703bc6d9cb499044"
		hash = "c4eea99658cd82d48aaddaec4781ce0c893de42b33376b6c60a949008a3efb27"
		hash = "c5651add0c7db3bbfe0bbffe4eafe9cd5aa254d99be7e3404a2054d6e07d20e7"
		logic_hash = "546c34d4c204c7266884bb3b5b6ada418e83029ab88f72e5ffb094f50d9ed28e"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "/dev/net/.../rootkit_/" ascii
		$s2 = "did_exec" ascii fullword
		$s3 = "rh_reserved_tp_target" ascii fullword
		$s4 = "HIDDEN_SERVICES" ascii fullword
		$s5 = "bypass_udp_ports" ascii fullword
		$s6 = "DoBypassIP" ascii fullword
		$op1 = { 74 2a 4c 89 ef e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 4c 39 f2 }
		$op2 = { e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 4c 39 f2 48 0f 46 c3 5b }
		$op3 = { 48 89 c3 74 2a 4c 89 ef e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 }
		$op4 = { 4c 29 e2 48 01 c2 31 c0 4c 39 f2 48 0f 46 c3 5b 41 5c 41 5d }
		$fp1 = "/wgsyncdaemon.pid"

	condition:
		uint16( 0 ) == 0x457f and filesize < 2000KB and 2 of them and not 1 of ( $fp* ) or 4 of them
}

rule SIGNATURE_BASE_MAL_LNX_Perfctl_Oct24 : FILE
{
	meta:
		description = "Detects Perfctl malware samples"
		author = "Florian Roth"
		id = "391513ae-3348-5297-a22a-6f06e50f06d2"
		date = "2024-10-09"
		modified = "2024-12-12"
		reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_perfctl_oct24.yar#L23-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "a6d3c6b6359ae660d855f978057aab1115b418ed277bb9047cd488f9c7850747"
		hash = "ca3f246d635bfa560f6c839111be554a14735513e90b3e6784bedfe1930bdfd6"
		logic_hash = "d47df34240f59124542acc41484e8935327490c04c4e15a558b2ffc6f9c52ea8"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$op1 = { 83 45 f8 01 8b 45 f8 48 3b 45 98 0f 82 1b ff ff ff 90 c9 c3 55 }
		$op2 = { 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f }
		$op3 = { 88 4c 10 58 83 45 f8 01 83 7d f8 03 0f 86 68 ff ff ff 90 c9 c3 55 }
		$op4 = { 48 83 ec 68 48 89 7d a8 48 89 75 a0 48 89 55 98 48 8b 45 a8 48 8b 00 83 e0 3f 89 45 fc }

	condition:
		uint16( 0 ) == 0x457f and filesize < 300KB and 2 of them
}

rule SIGNATURE_BASE_MAL_LNX_Redmenshen_Bpfdoor_May23_1 : FILE
{
	meta:
		description = "Detects BPFDoor malware"
		author = "Florian Roth"
		id = "25df4dba-ec6e-5999-b6be-56fe933cb0d0"
		date = "2023-05-11"
		modified = "2023-12-05"
		reference = "https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_lnx_implant_may22.yar#L3-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"
		logic_hash = "c58971a43443800256e791b4f9fe7c3221518b0050e5f2964b6c843ddb4549ac"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "[-] Execute command failed" ascii fullword
		$x2 = "/var/run/initd.lock" ascii fullword
		$xc1 = { 2F 00 3E 3E 00 65 78 69 74 00 72 00 }
		$sc1 = { 9F CD 30 44 }
		$sc2 = { 66 27 14 5E }
		$sa1 = "TLS-CHACHA20-POLY1305-SHA256" ascii fullword
		$sop1 = { 48 83 c0 01 4c 39 f8 75 ea 4c 89 7c 24 68 48 69 c3 d0 00 00 00 48 8b 5c 24 50 48 8b 54 24 78 48 c7 44 24 38 00 00 00 00 }
		$sop2 = { 48 89 de f3 a5 89 03 8b 44 24 2c 39 44 24 28 44 89 4b 04 48 89 53 10 0f 95 c0 }
		$sop3 = { 49 d3 cd 4d 31 cd b1 29 49 89 e9 49 d3 c8 4d 31 c5 4c 03 68 10 48 89 f9 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 900KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or 4 of them or ( all of ( $sc* ) and $sc1 in ( @sc2 [ 1 ] -50 .. @sc2 [ 1 ] + 50 ) ) ) or ( 2 of ( $x* ) or 5 of them )
}

rule SIGNATURE_BASE_MAL_Netfilter_Dropper_Jun_2021_1_1 : FILE
{
	meta:
		description = "Detects the dropper of Netfilter rootkit"
		author = "Arkbird_SOLG"
		id = "d91f48aa-9580-572d-a72c-19b80624cdbe"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/struppigel/status/1405483373280235520"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_cn_netfilter.yar#L4-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "a5c873085f36f69f29bb8895eb199d42ce86b16da62c56680917149b97e6dac"
		hash = "659e0d1b2405cadfa560fe648cbf6866720dd40bb6f4081d3dce2dffe20595d9"
		hash = "d0a03a8905c4f695843bc4e9f2dd062b8fd7b0b00103236b5187ff3730750540"
		logic_hash = "b70eb5d2d234d0f523c41fa146f315cf7239bbe7a988b393e75ea6cf6aa438d3"
		score = 75
		quality = 85
		tags = "FILE"
		tlp = "White"
		adversary = "Chinese APT Group"

	strings:
		$seq1 = { b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fe ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 00 00 88 85 dc fd ff ff b8 ff 00 00 00 50 b8 00 00 00 00 50 8d 85 dd fd ff ff 50 e8 ?? 0d 00 00 83 c4 0c b8 00 00 50 00 50 e8 ?? 0d 00 00 83 c4 04 89 85 d8 fd ff ff 8b 85 d8 fd ff ff 89 85 d4 fd ff ff b8 00 00 50 00 50 b8 00 00 00 00 50 8b 85 d8 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c 8b 45 0c 8b 8d d8 fd ff ff 89 08 b8 3c 00 00 00 50 b8 00 00 00 00 50 8d 85 98 fd ff ff 50 e8 ?? 0c 00 00 83 c4 0c b8 3c 00 00 00 89 85 98 fd ff ff 8d 85 98 fd ff ff 83 c0 10 8d 8d dc fe ff ff 89 08 8d 85 98 fd ff ff 83 c0 14 b9 00 01 00 00 89 08 8d 85 98 fd ff ff 83 c0 2c 8d 8d dc fd ff ff 89 08 8d 85 98 fd ff ff 83 c0 30 b9 00 01 00 00 89 08 b8 0a 31 40 00 50 e8 ?? 0c 00 00 89 85 94 fd ff ff b8 16 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 fc b8 28 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0c 00 00 89 45 f8 b8 36 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f4 b8 47 31 40 00 50 8b 85 94 fd ff ff 50 e8 [2] 00 00 89 45 f0 b8 58 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 ec b8 69 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e8 b8 7a 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e4 b8 8e 31 40 00 50 8b 85 94 fd ff ff 50 e8 ?? 0b 00 00 89 45 e0 8b 45 08 50 e8 ?? 0b 00 00 83 c4 04 8d 8d 98 fd ff ff 51 b9 00 00 00 00 51 50 8b 45 08 50 8b 45 fc ff d0 85 }
		$seq2 = { b8 00 00 00 00 89 85 90 fd ff ff b8 00 00 00 00 89 85 8c fd ff ff b8 00 00 00 00 89 85 88 fd ff ff b8 00 00 00 00 89 85 84 fd ff ff b8 04 00 00 00 89 85 80 fd ff ff b8 00 00 00 00 88 85 7f f5 ff ff b8 00 08 00 00 50 b8 00 00 00 00 50 8d 85 80 f5 ff ff 50 e8 ?? 0b 00 00 83 c4 0c b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 00 00 00 00 50 b8 9d 31 40 00 50 8b 45 f8 ff d0 89 85 90 fd ff ff 8b 85 }
		$s1 = "%s\\netfilter.sys" fullword ascii
		$s2 = "SYSTEM\\CurrentControlSet\\Services\\netfilter" fullword ascii
		$s3 = "\\\\.\\netfilter" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 6KB and filesize < 1000KB and ( all of ( $seq* ) or 2 of ( $s* ) )
}

rule SIGNATURE_BASE_MAL_Netfilter_May_2021_1_1 : FILE
{
	meta:
		description = "Detects Netfilter rootkit"
		author = "Arkbird_SOLG"
		id = "0ac01eb3-435b-52b0-b8e8-ace2ebb34f60"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/struppigel/status/1405483373280235520"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_cn_netfilter.yar#L28-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "63d61549030fcf46ff1dc138122580b4364f0fe99e6b068bc6a3d6903656aff0"
		hash = "8249e9c0ac0840a36d9a5b9ff3e217198a2f533159acd4bf3d9b0132cc079870"
		hash = "d64f906376f21677d0585e93dae8b36248f94be7091b01fd1d4381916a326afe"
		logic_hash = "ba72bbc38c27d0c8d6eea7d513c3ca40276edd929c93abae4098639f7d7649a5"
		score = 75
		quality = 83
		tags = "FILE"
		tlp = "White"
		adversary = "Chinese APT Group"

	strings:
		$seq1 = { 48 8b 05 a9 57 ff ff 45 33 c9 49 b8 32 a2 df 2d 99 2b 00 00 48 85 c0 74 05 49 3b c0 75 38 0f 31 48 c1 e2 20 48 8d 0d 85 57 ff ff 48 0b c2 48 33 c1 48 89 05 78 57 ff ff 66 44 89 0d 76 57 ff ff 48 8b 05 69 57 ff ff 48 85 c0 75 0a 49 8b c0 48 89 05 5a 57 ff ff 48 f7 d0 48 89 05 58 57 }
		$seq2 = { 48 83 ec 38 48 83 64 24 20 00 48 8d 05 83 4c 00 00 48 8d 15 24 d1 00 00 48 89 44 24 28 48 8d 4c 24 20 e8 4d 05 00 00 85 c0 78 16 4c 8d 05 22 d1 00 00 83 ca ff 48 8d 0d 00 d1 00 00 e8 39 05 00 00 48 83 c4 }
		$seq3 = { 45 33 c0 48 8d 4c 24 40 41 8d 50 01 ff 15 5d 62 00 00 c6 84 24 88 00 00 00 01 48 8d 84 24 88 00 00 00 48 89 46 18 48 8d 0d e2 fe ff ff 48 89 9e c0 00 00 00 48 8d 44 24 40 48 89 46 50 48 8d 44 24 30 48 89 46 48 65 48 8b 04 25 88 01 00 00 48 89 86 98 00 00 00 48 8b 86 b8 00 00 00 40 88 7e 40 c6 40 b8 06 4c 89 78 e0 48 89 58 e8 c7 40 c0 01 00 00 00 c7 40 c8 0d 00 00 00 48 89 58 d0 48 8b 86 b8 00 00 00 48 89 48 f0 48 8d 4c 24 40 48 89 48 f8 c6 40 bb e0 48 8b 43 28 48 85 c0 74 2f 48 8b 48 10 48 85 c9 74 07 48 21 78 10 4c 8b f1 48 8b 08 48 85 c9 74 06 48 21 38 48 8b e9 48 8b 48 08 48 85 c9 74 08 48 83 60 08 00 48 8b f9 48 8b d6 49 8b cf ff 15 74 61 00 00 3d 03 01 00 00 75 19 48 83 64 24 20 00 48 8d 4c 24 40 41 b1 01 45 33 c0 33 d2 ff 15 64 61 00 00 48 8b 43 28 48 85 c0 74 1a 4d }
		$seq4 = { 8b 84 24 80 00 00 00 48 8d 54 24 38 48 8b 4c 24 30 44 8b ce 89 44 24 28 45 33 c0 48 89 7c 24 20 ff 15 66 2e 00 00 48 8b 4c 24 30 8b d8 ff 15 49 2e 00 00 48 8b 4c 24 30 ff 15 26 2d 00 00 8b }
		$s1 = "%sc=%s" fullword ascii
		$s2 = { 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 }
		$s3 = "NETIO.SYS" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and filesize < 1000KB and ( 3 of ( $seq* ) or 2 of ( $s* ) )
}

rule SIGNATURE_BASE_MAL_RANSOM_ELF_Esxi_Attacks_Feb23_1 : FILE
{
	meta:
		description = "Detects ransomware exploiting and encrypting ESXi servers"
		author = "Florian Roth"
		id = "d0a813aa-41f8-57df-b708-18ccb0d7a3e5"
		date = "2023-02-04"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_ransom_esxi_attacks_feb23.yar#L30-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
		logic_hash = "27ff018574323c10821993c30cf74de15121caa92a308fbcae4eceae954e63b6"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]" ascii fullword
		$x2 = "[ %s ] - FAIL { Errno: %d }" ascii fullword
		$s1 = "lPEM_read_bio_RSAPrivateKey" ascii fullword
		$s2 = "lERR_get_error" ascii fullword
		$s3 = "get_pk_data: key file is empty!" ascii fullword
		$op1 = { 8b 45 a8 03 45 d0 89 45 d4 8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 }
		$op2 = { 48 89 95 40 fd ff ff 48 83 bd 40 fd ff ff 00 0f 85 2e 01 00 00 48 8b 9d 50 ff ff ff 48 89 9d 30 fd ff ff 48 83 bd 30 fd ff ff 00 78 13 f2 48 0f 2a 85 30 fd ff ff }
		$op3 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d }

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

rule SIGNATURE_BASE_MAL_WIPER_Bibi_Oct23 : FILE
{
	meta:
		description = "Detects BiBi wiper samples for Windows and Linux"
		author = "Florian Roth"
		id = "e1ea8016-e074-5208-8c98-54922bbcc407"
		date = "2023-11-01"
		modified = "2023-12-05"
		reference = "https://x.com/ESETresearch/status/1719437301900595444?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_bibi_wiper_oct23.yar#L24-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "23bae09b5699c2d5c4cb1b8aa908a3af898b00f88f06e021edcb16d7d558efad"
		hash = "40417e937cd244b2f928150cae6fa0eff5551fdb401ea072f6ecdda67a747e17"
		logic_hash = "c22dc994005f91f81d0e8e5f8d400b12ecd28336866bc62b8527e104f6339372"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "send attempt while closed" ascii fullword
		$s2 = "[+] CPU cores: %d, Threads: %d" ascii fullword
		$s3 = "[+] Stats: %d | %d" ascii fullword
		$opw1 = { 33 c0 88 45 48 b8 01 00 00 00 86 45 48 45 8b f5 48 8d 3d de f5 ff ff 0f 57 c9 f3 0f 7f 4d b8 }
		$opw2 = { 2d ce b5 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 26 b4 00 00 44 8b 05 5f b6 00 00 e8 ca 0d 00 00 }
		$opl1 = { 4c 8d 44 24 08 48 89 f7 48 ff c2 48 83 c6 04 e8 c7 fb ff ff 41 89 c1 0f b6 42 ff 41 0f af c1 }
		$opl2 = { e8 6f fb ff ff 49 8d 78 f8 89 c0 48 01 c2 48 89 15 09 fb 24 00 e8 5a fb ff ff 49 8d 78 fc 6b f0 06 }

	condition:
		( uint16( 0 ) == 0x5a4d or uint16( 0 ) == 0x457f ) and filesize < 4000KB and 2 of them
}

rule TRELLIX_ARC_Mirai_Casper_Variant : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the Mirai Casper variant"
		author = "Marc Rivero | McAfee ATR Team"
		id = "0f3a028c-9514-51cd-ad82-415e8ac2dee7"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_decade_of_RATs.yar#L163-L193"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "57cc422a6a90c571198a2d1c3db13c31fbdb48ba2f0f4356846d6d636d0f9300"
		logic_hash = "5449d1ef0c4977c6151fc194ad5f526b6be414c1efb7fd4bacb77d4bcd89c703"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4601??01??000000000000000002??03??01??0000E0??04??34??000088??????????000034??20??05????????????????000000000000000080??????80??????15????????0C??05????????10??????0000??????0C??40A510??40A510??80??????904A0000060000000010????????0000D4??0000D4??04??D4??04??440000??????????????000004??0000070000??????0C??40A510??40A510??14??000030??000004??000004??000051E5??64????000000000000000000000000000000000000060000??????000004??000010??000001??0000474E5500000000????0000????0000????0000??????000014??000003??0000474E55??????3A??87????529723????2C??08??????AB35????????2A??0000BC????????0000????A510??2A??0000C4??????????0000C8??????2A??0000CCA510??2A??00005589??5383????E8????????5B81??????????8B??????????85??74??E8????????E8????????E8????????585BC9C3FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????000000000000000031??5E89??83????50545268????????68????????515668????????E8????????F490909090909090909090909090905589??538D??????80????????????75??BB????????A1????????81??????????C1????83????39??73??908D??????83????A3????????FF????????????A1????????39??72??B8????????85??74??C7????????????E8????????C6????????????8D??????5B5DC3908D??????55B8????????89??8D??????E8????????5A81??????????85??74??89??????C7??????????????C7??????????????C7????????????E8????????A1????????85??74??B8????????85??74??C7????????????FF??C9C39090905589??83????8B????88????A1????????85??74??A1????????0FB6????88??83????A3????????EB??C7??????????????8D????89??????C7????????????E8????????C9C35589??83????EB??8B????0FB6??0FBE??83??????89????E8????????8B????0FB6??84??75??C9C35589??83????8B????0FB6??88????83??????80??????0F84????????80??????74??0FBE????89????E8????????E9????????C7????????????8B????0FB6??88????83??????80??????75??C7????????????8B????0FB6??88????83??????EB??80??????75??C7????????????8B????0FB6??88????83??????C7????????????EB??8B????89??C1????01??01??89??0FBE????8D????83????89????8B????0FB6??88????83??????80??????7E??80??????7E??80??????74??80??????75??83??????8B????0FB6??88????83??????80??????0F84????????0FB6????88????80??????7E??0FB6????83????88????0FBE????83????83????0F87????????8B????????????FF??8B????8D????89????8B??89????C7????????????EB??83??????8B????8B????8D????0FB6??84??75??EB??C7????????????E8????????8B????83????85??75??8B????3B????0F92??83??????84??75??8B????89????E8????????EB??C7????????????E8????????8B????3B????0F92??83??????84??75??E9????????8B????8D????89????8B??0FBE??89????E8????????E9????????C7????????????EB??C7????????????EB??C7????????????EB??C7????????????EB??0FBE????89????E8????????E9????????8B????83????85??74??8B????8D????89????8B??EB??80??????75??8B????8D????89????8B??EB??8B????8D????89????8B??89????80??????75??8B????85??79??F7????83??????C7????????????8B????BA????????F7????89??88????8B????BA????????F7????89????80??????7E??80??????75??B8????????EB??B8????????0FB6????01??88????8B????0FB6????83????88??????83??????83??????74??83??????76??8B????83????85??74??8B????C6????????83??????8B????89????8B????83????84??74??B8????????EB??B8????????88????EB??0FBE????89????E8????????8B????83????85??75??8B????3B????0F92??83??????84??75??83??????8B????0FB6??????0FBE??89????E8????????83??????75??EB??C7????????????E8????????8B????3B????0F92??83??????84??75??E9????????E9????????90EB??90C9C35589??83????8D????89????8B????89??????8B????89????E8????????C9C35589??83????8B????8B????88????88????C9C35589??57565381??????????8B????8B????88??????????88??????????C7??????????????????C7??????????????????0FB6??????????C7??????????????C7??????????????8B????89??????89????E8????????89??????????0FB6??????????C7??????????????C7??????????????8B????89??????89????E8????????89??????????0FB6??????????C7??????????????C7??????????????8B????89??????89????E8????????89??????????0FB6??????????C7??????????????C7??????????????8B????89??????89????E8????????89??????????0FB6??????????C7??????????????C7??????????????8B????89??????89????E8????????89??????????0FB6??????????C7??????????????C7??????????????8B????89??????89????E8????????66????????????8D??????????BA????????89??????C7??????????????89????E8????????83????????????0F84????????83????????????0F84????????8B??????????89????E8????????3D????????0F8F????????8B??????????89????E8????????83????0F8F????????8B??????????89????E8????????83????0F8F????????C7??????????????????EB??8B??????????03??????????0FB6??3C??7E??8B??????????03??????????0FB6??3C??7F??8B??????????03??????????8B??????????03??????????0FB6??83????88??8B??????????83????89??????????8B??????????89????E8????????8B??????????39??7F??81??????????????????7E??C7??????????????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????C7????????????E8????????8B??????????C7??????????????89????E8????????89??????????C7??????????????????E9????????8B??????????69??????????03??????????C6??????8B??????????69??????????03??????????C7??????????8B??????????69??????????89??03??????????0FB6??????????8B??????????89??C1????F7??89??89??89??01??01??C1????03????8B????89????8B??????????69??????????03??????????8D??????????8B??????????89??????89????E8????????8B??????????69??????????03??????????0FB6??????????3C??74??8B??????????69??????????03??????????05????????89????E8????????8B??????????69??????????03??????????8D??????????8B??????????69??????????03??????????81??????????83????89??????89??????89????E8????????8B??????????69??????????03??????????C6????????????8B??????????69??????????03??????????8D??????????8B??????????89??????89????E8????????8B??????????69??????????03??????????8D??????????8B??????????89??????89????E8????????8B??????????69??????????03??????????8D??????????8B??????????89??????89????E8????????0FB6??????????8B??????????89??C1????F7??89??89??89??01??01??C1????03????0FB6????3C??0F87????????8B??????????69??????????89??03??????????0FB6??????????8B??????????89??C1????F7??89??89??89??01??01??C1????03????8B????89????E8????????89??E8????????89??0FB6??????????8B??????????89??C1????F7??89??89??89??01??01??C1????03????0FB6????0FB6??89??89??D3??89??8D????89????E8????????89????E8????????89??BA????????89??F7??89??C1????89??C1????01??89??29??83????0F87????????8B????????????FF??C7????????????E8????????C7??????????????C7????????????E8????????8B??????????69??????????03??????????83????89??????89????E8????????C7????????????E8????????E9????????C7????????????E8????????C7??????????????C7????????????E8????????8B??????????69??????????03??????????83????89??????89????E8????????C7????????????E8????????E9????????C7????????????E8????????C7??????????????C7????????????E8????????8B??????????69??????????03??????????83????89??????89????E8????????C7???????????? }

	condition:
		uint16( 0 ) == 0x457f and filesize < 3000KB and all of them
}

rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_1 : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the backdoor pwnlnx variant 1"
		author = "Marc Rivero | McAfee ATR Team"
		id = "5b76ca62-460c-5c36-a239-700cc509f2b0"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_decade_of_RATs.yar#L3-L33"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "0f6033d6f82ce758b576e2d8c483815e908e323d0b700040fbdab5593fb5282b"
		logic_hash = "1487890494dde891a6dbe7dff7ebd5660ee01fe10220215e680115f168c2ae4a"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4602??01??000000000000000002??3E????0000????1A????0000000040000000000000??????0000000000000000000040??????????????1D????????0000????????????000000000000??????4000000000??????4000000000????01??00000000????01??00000000????000000000000????0000??????0000????000000000000????4000000000000002????000000001C??0000000000001C??00000000000001??00000000000001??000005????????0000000000000000??????0000000000004000000000????76??00000000????76??000000000000????00000000????0000????0000000080????00000000????????????0000????????????000038??00000000000080??????00000000000020??0000000002??0000060000????80????0000000028??????????000028??????????0000A0????????0000????????????0000????000000000000??????000004??00001C??0000000000001C??4000000000??????4000000000????000000000000????000000000000??????00000000000050E5??6404??00009C6D0000000000009C6D4000000000??????????????0000DC??000000000000DC??00000000000004??00000000000051E5??64??000000000000000000000000000000000000000000000000000000000000000000000000000000000000????000000000000????6C69????????????2D????????78??78??362D????????6F2E32??04??000010??000001??0000474E5500000000????0000????0000????000000000000????0000??????000001??000006000000000000????000020??0000??????00007D??5A580000000000000000000000000000000000000000000000000000000015????????00000000000000000000??????00000000000082????????00000000000000000000????????????0000????????????00000000000000000000????????????0000??????000012??0000000000000000000062??0000000000006A??000012??000000000000000000001B??0000000000007E??000012??000000000000000000008B??0000000000004902??????00000000000000000000????????????0000????????????00000000000000000000????????00000000??????000012??000000000000000000008E??000000000000F401??????00000000000000000000????????????0000????????????00000000000000000000????000000000000????01??????00000000000000000000????????????0000????0000????000000000000000000000000000000000000????0000????000000000000000000000000000000000000??????000012??0000000000000000000025????????0000????????????00000000000000000000????000000000000????0000????00000000000000000000????000000000000????01??????00000000000000000000????????????0000????0000????00000000000000000000????000000000000????02??????00000000000000000000????????????0000????01??????00000000000000000000??????0000000000006602??????00000000000000000000????????????0000??????000012??0000000000000000000025????????0000????01??????00000000000000000000????000000000000????????????00000000000000000000????000000000000????01??????00000000000000000000????000000000000????0000????00000000000000000000????01??00000000????????????00000000000000000000????????????0000????????????00000000000000000000??????000000000000EC01??????00000000000000000000??????0000000000004B01??????00000000000000000000????????????0000??????000012??0000000000000000000025????????0000????01??????00000000000000000000????????????0000??????000012??0000000000000000000008??0000000000004302??????00000000000000000000????????????0000??????????????000000000000000000000A??0000000000003F01??????00000000000000000000????????????0000??????000012??00000000000000000000F0????00000000????01??????00000000000000000000??????????????00002F02??????00000000000000000000????01??00000000????????????00000000000000000000????000000000000??????????????0000000000000000000080????00000000????02??????00000000000000000000????000000000000??????000012??0000000000000000000074??000000000000BF????????00000000000000000000????????????0000????02??????00000000000000000000??????000000000000FA0000????00000000000000000000????????????0000??????000012??0000000000000000000011??000000000000A8??000012??0000000000000000000044000000000000??????000012??000000000000000000005A000000000000??????000012??0000000000000000000029??000000000000C6????????00000000000000000000????000000000000????????????00000000000000000000????000000000000????0000????00000000000000000000????????00000000????????????00000000000000000000??????000000000000BC????????00000000000000000000????02??00000000????01??????00000000000000000000??????00000000000034??000012??00000000000000000000A1????????0000????????????00000000000000000000????????????0000??????????????000000000000000000004B000000000000????0000????00000000000000000000????000000000000??????000012??0000000000000000000005????????0000??????000012??0000000000000000000031??00000000000074??000012??00000000000000000000FF??0000000000005E02??????00000000000000000000????000000000000????????????00000000000000000000????????????0000??????000012??0000000000000000000025????????0000????02??????00000000000000000000??????000000000000DE??000012??000000000000000000007B??00000000000030??000012??0000000000000000000075??000000000000D9??000012??000000000000000000000E000000000000????????????00000000000000000000????000000000000????02??????00000000000000000000????????????0000????????????00000000000000000000????????????0000????????????00000000000000000000????000000000000????02??????00000000000000000000????000000000000????01??????00000000000000000000????????????0000????????????00000000000000000000????000000000000????????????00000000000000000000??????0000000000005201??????0000????174000000000????00000000000000005F5F676D6F6E5F73??6172??5F5F??????76??52656769????????????6173??6573??6C69????????????61642E????2E30??72??63????72??6D??????68????????5F63????6174????????6E6474????????75??65??????69??????????????6E6F5F6C6F63????69????????????6B????74??72??6164??73??676D6173????????6E6E6563??????74??72??6164??73??6C66??????63????74??70??68????????5F6465????63????6663????6C????????63??73??2E????????63????74??73??72??70????????69????????????????????616E64??????6574??6174??6E??????74??77??69??????????????6469????????????5F6E74??61??????74??72??69??????????????70??????????6D6F6E????????74??6E??????6C6563??????6B????????72??616C6C6F63??676574??69??????????????73??72??6F6B????63????77????????70??6173??72??3634??73??67656D70??79??6574??6D656D73??74??72??6469??????????????????6565??????68????????6173??74??6D65??????74??6F63????70????????616E74??74??6475??32??73??67616464????74??69????????????6472??6663??????65??????74??6F63????70????????6C6C6F63??73??72??6174??72??616C70??74????????6D6F76????????656E6469????????????6C??????74??6F73??62????616D65??????6563??????????72??74????????656164??????6C6F63????74??6C6F63????74??6D65??????616E6469????????????616464??????????????6565????73??74??69????????????????????6D6D6F76????????70??6E3634??5F5F6C69????????????72??5F6D6169????????????73??73??70??69????????????65????????78??74??74??34??474C4942435F32??32??35????????42435F32??33??000002??02??02??03??02??02??02??03??03??02??02??02??0000000002??02??02??02??02??03??02??02??02??02??02??02??02??02??03??02??02??02??04??02??02??03??02??03??02??02??02??03??02??02??02??02??02??03??02??02??02??02??02??02??03??02??02??03??02??02??02??03??02??03??02??03??02??02??02??02??02??02??03??03??03??02??02??02??02??02??000001??01??24??000010??000020??000075??69??????????9602??00000000????????????????????000000000000????69????????????A2????????0000??????69??????????9602??00000000????81????????????060000????????????000000000000????81????????????070000????00000000000000000000????81????????????070000????00000000000000000000????81????????????070000????00000000000000000000000082??????0000????0000??????0000000000000000000008??????????0000070000????????????000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000??????6000000000????0000??????000000000000000000004882??????0000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000?????? }

	condition:
		uint16( 0 ) == 0x457f and filesize < 100KB and all of them
}

rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_2 : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the backdoor pwnlnx variant 2"
		author = "Marc Rivero | McAfee ATR Team"
		id = "c4ee686b-49d9-5566-b749-1144a19c1fee"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_decade_of_RATs.yar#L35-L65"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "08cc67002782cbafd97a4bff549d25dd72d6976d2fdf79339aaf5a3ff7c3107e"
		logic_hash = "08ea40ba72677263a41f62097fc38040361ba595d67cb04979b66548c7f4d271"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4602??01??000000000000000002??3E????0000000004??00000000??????00000000000088????????????00000000??????38??05????????????????0000????????????0000000000000000??????0000000000004000000000??????0D??????????????0D????????0000????00000000????0000????0000????????????0000????????????0000????????????0000????12??00000000????????????00000000????00000000??????000004??00005801??00000000??????4000000000??????4000000000????????00000000????????00000000??????000000000000070000??????000080??????0000000080??????0000000080??????0000000028??00000000000070??00000000000008??00000000000051E5??64??000000000000000000000000000000000000000000000000000000000000000000000000000000000000????000000000000??????000010??000001??0000474E5500000000????0000????0000????0000??????000014??000003??0000474E55????????????CC78??78??83????????????CB371F0000000080??????0000000025????????0000????7E??00000000????????????0000????????????0000??????4200000000????????????0000????????????0000????????????0000????????????0000????????????0000????????????0000????????????0000????????????0000????????????0000????????????0000????????????0000??????4200000000????????????0000????????????0000??????4200000000????????????0000????????????0000????????????0000????76??00000000????????????0000????8B????00000000C8??????0000000025????????0000??????4200000000????76??00000000????????????0000????444200000000????76??00000000????????????0000??????4900000000????76??00000000????????????0000??????4600000000????76??00000000????????????0000????424200000000??????EC08??33??0000E8????????E8????????4883????C3FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????00000000000000000000000000000000000000000000000031??4989??5E4889??4883????505449C7??????????48C7??????????48C7??????????E8????????F490904883????488B??????????4885??74??FF??4883????C390909090909090909090909090554889??534883????80????????????75??BB????????488B??????????4881??????????48C1????4883????4839??73??660F1F??????4883????4889??????????FF????????????488B??????????4839??72??B8????????4885??74??BF????????E8????????C6????????????4883????5BC9C30F1F????????????55B8????????4885??4889??74??BE????????BF????????E8????????4883????????????74??B8????????4885??74??BF????????C9FF??0F1F??????????C9C39090554889??534881??????????89??????????48C7????????????8B????3D????????0F87????????8B????89??488D??????????8B??????????4889??89??E8????????85??0F84????????8B????89??488D??????????89??4889??E8????????BA????????488D??????????4889??4889??E8????????4889????4883??????0F84????????488D??????????488D??????????4889??4889??E8????????85??0F85????????488B??????????4889????C7????????????488B????89????488B????48C1????89????488B????4889????488B????4889??????488B????4889??????E8????????89????BE????????488D????E8????????488D????8B??????????BA????????4889??89??E8????????85??0F84????????488D????8B??????????BA????????4889??89??E8????????85??0F84????????BE????????488D????E8????????8B????488B????4889????488B????4889??????488B????4889??????E8????????39??0F85????????8B????89??4889??48C1????8B????89??488D????4889????488B????488B????BA????????4889??4889??E8????????488B????4889????EB??488B????488D??????????4889??BA????????BE????????4889??E8????????89????83??????7E??8B????488D??????????89??4889??E8????????8B????4863??488D??????????8B??????????4889??89??E8????????85??74??8B????48984801????488B????483B????7C??EB??90EB??90EB??90EB??90EB??90EB??90488B????4889??E8????????EB??90EB??90EB??90B8????????4881??????????5BC9C3554889??534881??????????4889??????????E8????????4889??E8????????C7????????????488B??????????8B????89????488B??????????8B??89????488B??????????8B????89????8B????8B????BA????????89??89??E8????????89????83??????0F84????????488D????BA????????BE????????4889??E8????????C7????????????C7????????????8B????89????488B????4889????488B????4889??????488B????4889??????E8????????89????488D????BE????????4889??E8????????488D????8B????BA????????4889??89??E8????????85??0F84????????488D??????????4889??E8????????488D??????????BE????????4889??E8????????488D??????????8B????BA????????4889??89??E8????????85??0F84????????488D????8B????BA????????4889??89??E8????????85??74??488D????BE????????4889??E8????????8B????488B????4889????488B????4889??????488B????4889??????E8????????39??75??8B????83????75??8B????488B????4889????488B????4889??????488B????4889??????89??E8????????EB??90EB??90EB??90EB??90EB??908B????89??E8????????B8????????4881??????????5BC9C390554889??4889????89????C7????????????488B????4889????C7????????????EB??488B????0FB6??8B????89??C1????F7????89??48980FB6??????????89??31??488B????88??83??????4883??????8B????3B????7C??488B????C9C3554889??4889????89????488B????4889????C7????????????EB??488B????0FB6??0FB6??????????31??488B????88??83??????4883??????8B????3B????7C??488B????C9C39090554889??534881??????????89??????????48C7????????????48C7????????????48C7????????????8B????89??488D??????????8B??????????4889??89??E8????????85??0F84????????8B????89??488D??????????89??4889??E8????????488D??????????488D??????????4889??4889??E8????????BA????????488D??????????488D??????????BE????????4889??B8????????E8????????488D??????????4889??E8????????4883????4889??E8????????4889????4883??????0F84????????488D??????????488B????4889??4889??E8????????488D??????????488D????B9????????BA????????4889??4889??E8????????89????83??????0F8E????????C7????????????E9????????488B????8B????4863??48C1????4801??488B??488D????BA????????488D??????????488D??????????4989??BE????????4889??B8????????E8????????488D??????????488D??????????4889??4889??E8????????85??0F85????????48C7????????????48C7????????????488D??????????4883????4889??E8????????4889??E8????????488B??????????8B??????????4189??4181??????????8B??????????89??81??????????488B????8B????4863??48C1????4801??488B??488D????BA????????488D??????????4889??????4889??????488B????4889??????488B????4889????4589??4189??4889??BE????????4889?? }

	condition:
		uint16( 0 ) == 0x457f and filesize < 1000KB and all of them
}

rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_3 : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the backdoor pwnlnx variant"
		author = "Marc Rivero | McAfee ATR Team"
		id = "02ea1eb2-7235-5ed5-86ba-19d52e8fb428"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_decade_of_RATs.yar#L67-L97"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "08f29e234f0ce3bded1771d702f8b5963b144141727e48b8a0594f58317aac75"
		logic_hash = "8a1405f430ce57810577f65ef43a1425601bf49b5adb4f6f935505427ad9dc94"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4602??01??000000000000000002??3E????0000000004??00000000??????000000000000B0??3A??000000000000000040??????????????????????01??000005????????0000000000000000??????0000000000004000000000????????????0000????????????00000000????00000000????0000????0000????A40C??00000000C0??????????????C0??????????????5013??00000000????????????00000000????00000000??????000004??00005801??00000000??????4000000000??????4000000000????000000000000????000000000000??????000000000000070000??????0000C0??????????????C0??????????????C0??????????????28??00000000000078??00000000000008??00000000000051E5??64??000000000000000000000000000000000000000000000000000000000000000000000000000000000000????000000000000??????000010??000001??0000474E5500000000????0000??????000000000000C0????????????????????????0000????84????00000000C8??????0000000025????????0000????374200000000????A56C00000000????????????0000????????????0000????A56C00000000????????????0000??????4200000000????A56C00000000????????????0000????24??00000000????A56C00000000????????????0000????????????0000????A56C00000000????????????0000????83??????0000????A56C00000000????????????0000????5E42000000000000A66C00000000????????????0000??????4200000000????A66C00000000????????????0000????914200000000????A66C00000000????????????0000??????4200000000????A66C00000000????????????0000????????????0000????A66C00000000????????????0000????????????0000????A66C00000000????????????0000??????4200000000????A66C00000000????????????0000??????4200000000??????EC08??4301??????62??0000E8????????4883????C3FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????00000000000000000000000000000000000000000000000031??4989??5E4889??4883????505449C7??????????48C7??????????48C7??????????E8????????F490904883????488B??????????4885??74??FF??4883????C390909090909090909090909090B8????????55482D????????4883????4889??76??B8????????4885??74??5DBF????????FF??660F1F????????????5DC366666666????????????????????BE????????554881??????????48C1????4889??4889??48C1????4801??48D1??74??B8????????4885??74??5DBF????????FF??0F1F??5DC3660F1F??????80????????????75??554889??53BB????????4881??????????4883????488B??????????48C1????4883????4839??73??660F1F??????4883????4889??????????FF????????????488B??????????4839??72??E8????????B8????????4885??74??BF????????E8????????C6????????????4883????5B5DF3??669055B8????????4885??4889??74??BE????????BF????????E8????????BF????????4883????75??5DE9????????6690B8????????4885??74??FF??EB??9090554889??534881??????????89??????????48C7????????????8B????3D????????76??E9????????8B????89??488D??????????8B??????????4889??89??E8????????85??75??E9????????8B????89??488D??????????89??4889??E8????????488D??????????BE????????4889??E8????????4889????4883??????75??E9????????488D??????????488D??????????4889??4889??E8????????85??74??E9????????488B??????????4889????C7????????????488B????89????488B????48C1????89????4883????FF????FF????FF????E8????????4883????89????BE????????488D????E8????????8B??????????BA????????488D????89??E8????????85??75??E9????????8B??????????BA????????488D????89??E8????????85??75??E9????????BE????????488D????E8????????8B????4883????FF????FF????FF????E8????????4883????39??74??E9????????8B????89??48C1????4889??8B????89??4801??4889????488B????488B????BA????????4889??4889??E8????????488B????4889????EB??488B????488D??????????4889??BA????????BE????????4889??E8????????89????83??????7F??EB??8B????488D??????????89??4889??E8????????8B????4863??488D??????????8B??????????4889??89??E8????????85??75??EB??8B????48984801????488B????483B????7C??488B????4889??E8????????B8????????488B????C9C3554889??534881??????????4889??????????E8????????4889??E8????????C7????????????488B??????????8B????89????488B??????????8B??89????488B??????????8B????89????8B????8B????BA????????89??89??E8????????89????83??????75??E9????????488D????BA????????BE????????4889??E8????????C7????????????C7????????????8B????89????4883????FF????FF????FF????E8????????4883????89????488D????BE????????4889??E8????????488D????8B????BA????????4889??89??E8????????85??75??E9????????488D??????????4889??E8????????488D??????????BE????????4889??E8????????488D??????????8B????BA????????4889??89??E8????????85??75??EB??488D????8B????BA????????4889??89??E8????????85??75??EB??488D????BE????????4889??E8????????8B????4883????FF????FF????FF????E8????????4883????39??74??EB??8B????83????74??EB??8B????4883????FF????FF????FF????89??E8????????4883????908B????89??E8????????B8????????488B????C9C3554889??4889????89????C7????????????488B????4889????C7????????????EB??488B????0FB6??8B????99F7????89??48980FB6??????????31??89??488B????88??83??????4883??????8B????3B????7C??488B????5DC3554889??4889????89????488B????4889????C7????????????EB??488B????0FB6??0FB6??????????31??488B????88??83??????4883??????8B????3B????7C??488B????5DC39090554889??534881??????????89??????????48C7????????????48C7????????????48C7????????????8B????89??488D??????????8B??????????4889??89??E8????????85??75??E9????????8B????89??488D??????????89??4889??E8????????488D??????????488D??????????4889??4889??E8????????488D??????????488D??????????4889??BA????????BE????????4889??B8????????E8????????488D??????????4889??E8????????4883????4889??E8????????4889????4883??????75??E9????????488D??????????488B????4889??4889??E8????????488D????488D??????????B9????????BA????????4889??E8????????89????83??????0F8E????????C7????????????E9????????488B????8B????4863??48C1????4801??488B??488D????488D??????????488D??????????4989??4889??BA????????BE????????4889??B8????????E8????????488D??????????488D??????????4889??4889??E8????????85??0F85????????48C7????????????48C7????????????488D??????????4883????4889??E8????????4889??E8????????4989??488B??????????8B??????????25????????89??8B??????????25????????89??488B????8B????4863??48C1????4801??488B??488D????488D??????????415052FF????FF????4189??4189??BA????????BE????????4889??B8????????E8????????4883????488B????4889??E8????????4889??488D?????????? }

	condition:
		uint16( 0 ) == 0x457f and filesize < 4000KB and all of them
}

rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_4 : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the backdoor pwnlnx variant 4"
		author = "Marc Rivero | McAfee ATR Team"
		id = "199bb534-f0f6-5b67-aedd-3eada5e45cc6"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_decade_of_RATs.yar#L99-L129"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "2590ab56d46ff344f2aa4998efd1db216850bdddfc146d5d37e4b7d07c7336fc"
		logic_hash = "11203beee446aaf0783d3a8d3839a88ef16c27d52be8670d650ebf6a1de2c3aa"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4602??01??000000000000000001??3E????000000000000000000000000000000000000????????????000000000000??????0000000040??????????????000014??000003??0000474E55????9FECFBE5??F973??EB??2A??????????71??BD????????0000000000000000554889??53E8????????FF????????????4889??4889??4881??????????FF????????????4889??5BC9C30F1F??????554889??E8????????FF????????????C9C366666666????????????????????554889??E8????????4885??74??4C8B????4D85??74??65??8B????????????8B??????????4889??????????48C7??????????89??C1????C1????01??25????????29??48984C89????????????FF??????????C9C3660F1F????????????31??C9C36666662E????????????????554889??E8????????4889??????????48C7??????????FF??????????C9C390554889??E8????????8B??????????488B??????????488D????0FB6????3C??400F94??3C??410F94??74??4084??75??B8????????C9C30F1F????????????8B??????????39????74??3B????74??4584??74??8B??????????4801??0FB7??????????66????74??66??????75??4889??41FF??B8????????C9C30F1F??4084??74??8B??????????4801??0FB7??????????66????75??EB??0F1F????554889??534883????E8????????31??4889??31??E8????????483D????????77??4885??74??488B????488B????488B????488B????4889??????????31??4889??E8????????31??4883????5BC9C383????EB??662E0F1F????????????554889??415453E8????????4989??4889??31??31??E8????????483D????????77??488B????31??4889??488B????488B????488B????488B??????????4989????4889??????????E8????????31??5B415CC9C383????EB??0F1F??????554889??534883????E8????????31??4889??31??E8????????483D????????77??4885??74??488B????488B????488B????488B????4889??????????31??4889??E8????????31??4883????5BC9C383????EB??662E0F1F????????????554889??415453E8????????4989??4889??31??31??E8????????483D????????77??488B????31??4889??488B????488B????488B????488B??????????4989????4889??????????E8????????31??5B415CC9C383????EB??0F1F??????554889??534883????E8????????31??4889??BE????????E8????????483D????????77??4885??74??488B????4889????31??4889??E8????????31??4883????5BC9C383????EB??660F1F??????554889??415453E8????????4989??4889??BE????????31??E8????????483D????????77??488B????31??4889??488B????4989????488B????4889????E8????????31??5B415CC9C383????EB??554889??4157415641554154534883????E8????????4889??488D????4989??4189??4889??BA????????4989??4489????4D89??E8????????488B??????????448B????4881??????????488D????75??EB??0F1F????488B????4881??????????488D????74??0FB7????4839??75??4883????31??5B415C415D415E415FC9C30F1F??????4D89??4C89??4489??4889??4C89??FF??????????4883????5B415C415D415E415FC9C30F1F????554889??4157415641554154534883????E8????????65??8B????????????4889????4889????4189??8B??????????4889??B9????????48C7??????????4889??4D89??4589??89??C1????C1????01??25????????29??F3A648984C8B????????????0F84????????B9????????48C7??????????4889??F3A60F84????????31??4585??4889??4889????4489????74??418D??????31??488D??????0FB6??4883????4889??48C1????48C1????4801??4801??4839??488D????488D????75??89????488D????4C89??E8????????4885??4889??0F84????????488B????4885??74??81????????????0F84????????488B??????????483D????????4C8D????75??EB??0F1F??????498B????483D????????4C8D????74??498B??4889??E8????????85??75??31??4883????5B415C415D415E415FC9C34589??4D89??488B????4489??4889??488B????FF??????????4883????5B415C415D415E415FC9C30F1F??????????81????????????0F85????????31??EB??488D????4C89??E8????????4885??4889??74??498B????488B??????????488B????4885??74??31??4889??4889????FF??4885??488B????0F84????????31??E9????????0F1F????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??41554154534883????E8????????4C8B??????????4989??4981??????????498D??????75??EB??0F1F????4C8B????4981??????????498D??????74??488B??4C89??E8????????85??75??4C89??E8????????488B??E8????????4889??E8????????4883????5B415C415DC9C36666662E????????????????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889?? }

	condition:
		uint16( 0 ) == 0x457f and filesize < 400KB and all of them
}

rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_6 : BACKDOOR FILE
{
	meta:
		description = "Rule to detect the backdoor pwnlnx variant 6"
		author = "Marc Rivero | McAfee ATR Team"
		id = "56bfe9c7-4cd4-51f6-a469-da8af52d64c2"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_decade_of_RATs.yar#L131-L161"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "d29254ab907c9ef54349de3ec0dd8b22b4692c58ed7a7b340afbc6e44363f96a"
		logic_hash = "29423135a46ee7b9aa1bd8f1e6f7ffad09725787ad6e75312e1d34b18e3917d4"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$bp = { 7F??4C4602??01??000000000000000001??3E????000000000000000000000000000000000000??????09??00000000000000004000000000??????2B??28??04??000014??000003??0000474E55????4D9585????AB6522????52AD3B??EC9B4BE8????????0000000000000000????00000000554889??????????4889??41544989??534889??488B??????????E8????????4C89??4889??48C7??????????FF??????????488B??????????89??E8????????89??5B415C5DC30F1F??E8????????554889??????????4889??41544989??534889??488B??????????E8????????4C89??4889??48C7??????????FF??????????488B??????????89??E8????????89??5B415C5DC30F1F??E8????????554889??415541544989??534889??4883????488B??????????65??8B????????????4889????31??E8????????4889??4C89??FF??????????488B??????????4189??E8????????488B??????????483D????????488D????75??EB??0F1F??????488B????4881??????????488D????74??0FB7??488D????48C7??????????31??E8????????498B????498B??????488D????488D????????????BA????????E8????????4885??74??4981??????????????488B????65??33????????????4489??75??4883????5B415C415D5DC3E8????????0F1F??E8????????554889??415541544989??534889??4883????488B??????????65??8B????????????4889????31??E8????????4889??4C89??FF??????????488B??????????4189??E8????????488B??????????483D????????488D????75??EB??0F1F??????488B????4881??????????488D????74??0FB7??488D????48C7??????????31??E8????????498B????498B??????488D????488D????????????BA????????E8????????4885??74??4981??????????????488B????65??33????????????4489??75??4883????5B415C415D5DC3E8????????0F1F??E8????????554889??415541544989??534889??4883????488B??????????65??8B????????????4889????31??E8????????4889??4C89??FF??????????488B??????????4189??E8????????488B??????????483D????????488D????75??EB??0F1F??????488B????4881??????????488D????74??0FB7??488D????48C7??????????31??E8????????498B????498B??????488D????488D????????????BA????????E8????????4885??74??4981??????????????488B????65??33????????????4489??75??4883????5B415C415D5DC3E8????????0F1F??E8????????554889??415541544989??534889??4883????488B??????????65??8B????????????4889????31??E8????????4889??4C89??FF??????????488B??????????4189??E8????????488B??????????483D????????488D????75??EB??0F1F??????488B????4881??????????488D????74??0FB7??488D????48C7??????????31??E8????????498B????498B??????488D????488D????????????BA????????E8????????4885??74??4981??????????????488B????65??33????????????4489??75??4883????5B415C415D5DC3E8????????0F1F??E8????????554889??41574589??415641554189??4154534889??4883????488B??????????4889????4889????4C89????483D????????4C8D????74??4C63??EB??0F1F??????498B????483D????????4C8D????74??498B??4C89??4889??E8????????85??75??4883????5B415C415D415E415F5DC30F1F??????????4589??4C8B????488B????4489??4889??488B????FF??????????4883????5B415C415D415E415F5DC3660F1F??????E8????????554889??41574589??41564D89??41554989??41544189??BA????????534889??488D????4883????4889????4889??65??8B????????????4889????31??E8????????488B??????????4881??????????488D????74??0FB7????4839??75??EB??0F1F????????????410FB7????4839??74??4C8B????4981??????????498D????75??4589??4D89??4C89??4489??4889??488B????FF??????????488B????65??33????????????75??4883????5B415C415D415E415F5DC3660F1F??????31??EB??E8????????0F1F??????662E0F1F????????????E8????????55BF????????4889??4881??????????65??8B????????????4889????31??488D??????????FF????????????B9????????4889??488D??????????F3??A5488D??????????48C7??????????BE????????B1??E8????????4885??74??48BA???????? }

	condition:
		uint16( 0 ) == 0x457f and filesize < 700KB and all of them
}

rule TRELLIX_ARC_Ransom_Linux_Hellokitty_0721 : RANSOMWARE FILE
{
	meta:
		description = "rule to detect Linux variant of the Hello Kitty Ransomware"
		author = "Christiaan @ ATR"
		id = "097b02e7-93d8-5d4f-9964-7b660b3cd7b9"
		date = "2021-07-19"
		modified = "2021-07-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/ransomware/RANSOM_Linux_HelloKitty0721.yar#L1-L28"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
		hash = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
		logic_hash = "77a3809df4c7c591a855aaecd702af62935952937bb81661aa7f68e64dcf4fb4"
		score = 75
		quality = 70
		tags = "RANSOMWARE, FILE"
		Rule_Version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:Linux/HelloKitty"

	strings:
		$v1 = "esxcli vm process kill -t=force -w=%d" fullword ascii
		$v2 = "esxcli vm process kill -t=hard -w=%d" fullword ascii
		$v3 = "esxcli vm process kill -t=soft -w=%d" fullword ascii
		$v4 = "error encrypt: %s rename back:%s" fullword ascii
		$v5 = "esxcli vm process list" fullword ascii
		$v6 = "Total VM run on host:" fullword ascii
		$v7 = "error lock_exclusively:%s owner pid:%d" fullword ascii
		$v8 = "Error open %s in try_lock_exclusively" fullword ascii
		$v9 = "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d " fullword ascii
		$v10 = "pthread_cond_signal() error" fullword ascii
		$v11 = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii

	condition:
		( uint16( 0 ) == 0x457f and filesize < 200KB and ( 8 of them ) ) or ( all of them )
}

rule VOLEXITY_Apt_Malware_Elf_Verdantbamboo_Paths : VERDANTBAMBOO FILE MEMORY
{
	meta:
		description = "Detection for VerdantBamboo related malware based on paths from local machines observed in binaries."
		author = "threatintel@volexity.com"
		id = "256f6bdc-1067-52e8-81b9-c7be1b802947"
		date = "2025-09-22"
		modified = "2026-01-27"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2026/2026-06-04 VerdantBamboo/rules.yar#L32-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e"
		logic_hash = "aac17908a9d5e71d5db3fbdf9bb3307c74f5911bd253bb2060b05fbf238b2c3f"
		score = 75
		quality = 80
		tags = "VERDANTBAMBOO, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20251104"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 12361
		version = 3

	strings:
		$s1 = "bin/Release/net8.0/linux-x64/native/server" ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_1 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects GOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "f6643e9a-ca41-57e0-9fce-571d340f1cfe"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L104-L131"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "dd3535079881ae9cfe25c129803668cb595be89b7f62eb82af19cc3839f92b6d"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10265
		version = 7

	strings:
		$s1 = "Session *%s* opened!" wide ascii
		$s2 = "uevent_seqnum.sh" wide ascii
		$s3 = "Error downloading shell script: %v" wide ascii
		$s4 = "Error setting execute permissions: %v" wide ascii
		$s5 = "Error executing shell script: %v" wide ascii
		$s6 = "Error creating Discord session" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_2 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "609beb47-5e93-5f69-b89d-2cf62f20851a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L72-L103"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "e03a774cca2946c1becdbd775ef465033dae089d578ea18a4f43fd7bdae9168e"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10266
		version = 9

	strings:
		$s1 = "downloadFileFromURL" wide ascii
		$s2 = "createCronJob" wide ascii
		$s3 = "findAndSendFiles" wide ascii
		$s4 = "updateLogFile" wide ascii
		$s5 = "handleZipFile" wide ascii
		$s6 = "takeScreenshot" wide ascii
		$s7 = "zipFirefoxProfile" wide ascii
		$s8 = "zipDirectoryWithParts" wide ascii
		$s9 = "uploadAndSendToOshi" wide ascii
		$s10 = "uploadAndSendToLeft" wide ascii

	condition:
		7 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Bogus_Strings : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects the DISGOMOJI malware using bogus strings introduced in the newer version."
		author = "threatintel@volexity.com"
		id = "ecff8d3c-d4fe-5b6d-a227-6ff531cf8e2b"
		date = "2024-03-14"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L132-L159"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "8c8ef2d850bd9c987604e82571706e11612946122c6ab089bd54440c0113968e"
		logic_hash = "0d8a2b371ffb182e60a8cc0cc500d1a9f906718a55f23f35f6c12f7faabbe971"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10341
		version = 5

	strings:
		$s1 = "Graphics Display Rendering" wide ascii
		$s2 = "Error fetching Repository Key: %v" wide ascii
		$s3 = "Error reading Repository Key: %v" wide ascii
		$s4 = "Error fetching dpkg: %v" wide ascii
		$s5 = "GNU Drivers Latest version v1.4.2" wide ascii
		$s6 = "ps_output.txt" wide ascii

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Debug_String : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "eed2468f-7e50-5f3e-946a-277c10984823"
		date = "2024-02-22"
		modified = "2024-11-27"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L48-L71"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		logic_hash = "6bb130eead39bd8128983e0f2e76cfeff8865ce8ed3cb73b132ed32d68fc0db0"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10268
		version = 9

	strings:
		$s1 = "discord-c2/test/main/payload.go" wide ascii
		$s2 = "Desktop/Golang_Dev/Discord"

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Loader : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI loader using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "6d7848db-f1a5-5ccc-977a-7597b966a31c"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L25-L47"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "51a372fee89f885741515fa6fdf0ebce860f98145c9883f2e3e35c0fe4432885"
		logic_hash = "d9be4846bab5fffcfd60eaec377443819404f30ec088905c2ee26bd3b7525832"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10269
		version = 7

	strings:
		$s1 = "discord-c2/test/main/delievery.go" wide ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Modules : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI modules using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "b9e4ecdc-9b02-546f-9b79-947cb6b1f99a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L1-L24"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "2abaae4f6794131108adf5b42e09ee5ce24769431a0e154feabe6052cfe70bf3"
		logic_hash = "7880288e3230b688b780bdfbac2b0761fd7831b7df233672c2242c21a86e1297"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10270
		version = 6

	strings:
		$s1 = "discord-c2/test/main/finalizing/Deliveries/ob_Delivery.go" wide ascii
		$s2 = "discord-c2/test/main/finalizing/WAN_Conf.go" wide ascii

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Script_Lan_Conf : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects a script deployed as part of DISGOMOJI malware chain."
		author = "threatintel@volexity.com"
		id = "b338b3cf-22ce-5767-bdea-503e883bc84b"
		date = "2024-03-07"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L188-L215"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "0b5cf9bd917f0af03dd694ff4ce39b0b34a97c9f41b87feac1dc884a684f60ef"
		logic_hash = "2a19d5cff7adc9b1b92538a5df4e3cadea694f925f65080f5093fc5425e840f4"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10312
		version = 7

	strings:
		$s1 = "add_lan_conf_cron_if_not_exists" wide ascii
		$s2 = "download_if_not_exists" wide ascii
		$s3 = "add_cron_if_not_exists" wide ascii
		$s4 = "uevent_seqnum.sh" wide ascii
		$s5 = "$HOME/.x86_64-linux-gnu" wide ascii
		$s6 = "lanConfScriptPath" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Script_Uevent_Seqnum : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects a script deployed as part of DISGOMOJI malware chain."
		author = "threatintel@volexity.com"
		id = "9df61164-6a92-5042-ba4f-64dc7e998283"
		date = "2024-03-07"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L160-L187"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "98b24fb7aaaece7556aea2269b4e908dd79ff332ddaa5111caec49123840f364"
		logic_hash = "e390e83d9fc15499c9f32ad47d1c526273105602bda7b3532720b0a3f6abc835"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10314
		version = 6

	strings:
		$s1 = "USB_DIR=\"/media/$USER\"" wide ascii
		$s2 = "RECORD_FILE=\"record.txt\"" wide ascii
		$s3 = "copy_files()" wide ascii
		$s4 = "Check for connected USB drives" wide ascii
		$s5 = "Check if filename already exists in record.txt" wide ascii
		$s6 = "Function to copy files from USB drive to destination folder" wide ascii

	condition:
		3 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Hunting_Linux_WHIRLPOOL_1 : FILE
{
	meta:
		description = "Hunting rule looking for strings observed in WHIRLPOOL samples."
		author = "Mandiant"
		id = "a997bd65-c502-53a0-8bb8-62daaa916f0d"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_barracuda_esg_unc4841_jun23.yar#L154-L173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "177add288b289d43236d2dba33e65956"
		logic_hash = "d03c0e292b9b97bbf76585fc74208e4263d753807b8e4a445be80d41264d5432"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "error -1 exit" fullword
		$s2 = "create socket error: %s(error: %d)\n" fullword
		$s3 = "connect error: %s(error: %d)\n" fullword
		$s4 = {C7 00 20 32 3E 26 66 C7 40 04 31 00}
		$c1 = "plain_connect" fullword
		$c2 = "ssl_connect" fullword
		$c3 = "SSLShell.c" fullword

	condition:
		uint32( 0 ) == 0x464c457f and filesize < 15MB and ( all of ( $s* ) or all of ( $c* ) )
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_Generic_May22_1 : FILE
{
	meta:
		description = "Detects BPFDoor malware"
		author = "Florian Roth (Nextron Systems)"
		id = "d30df2ae-7008-53c0-9a61-8346a9c9f465"
		date = "2022-05-09"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_lnx_implant_may22.yar#L121-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
		hash = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
		hash = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
		hash = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		hash = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
		hash = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
		hash = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
		hash = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
		hash = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
		hash = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
		hash = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
		hash = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
		hash = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
		hash = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
		logic_hash = "57ae5f7dc1d202fe66d6626ef2bf2278b92bec0310449ce049bdaeaec5657c77"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$op1 = { c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 ?? 88 45 }
		$op2 = { 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 }
		$op3 = { 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 88 45 f? c7 45 f8 00 00 00 00 }
		$op4 = { 48 89 7d d8 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? }
		$op5 = { 48 8b 45 ?8 c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 }
		$op6 = { 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them or 4 of them
}

rule SIGNATURE_BASE_SUSP_EXPL_LNX_CUPS_CVE_2024_47177_Sep24 : CVE_2024_47177
{
	meta:
		description = "Detects suspicious FoomaticRIPCommandLine command in printer config, which could be used to exploit CUPS CVE-2024-47177"
		author = "Florian Roth"
		id = "cb76f1c7-6dc0-5fed-a970-2a4890db46d3"
		date = "2024-09-27"
		modified = "2024-12-12"
		reference = "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_cups_sep24.yar#L17-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "2158ca8a08cb7552e2a437de025e3aad63ddc5417245e6ede7283d3bd0fc159b"
		score = 65
		quality = 85
		tags = "CVE-2024-47177"

	strings:
		$ = "FoomaticRIPCommandLine: \"bash " ascii
		$ = "FoomaticRIPCommandLine: \"sh " ascii
		$ = "FoomaticRIPCommandLine: \"python " ascii
		$ = "FoomaticRIPCommandLine: \"perl " ascii
		$ = "FoomaticRIPCommandLine: \"echo " ascii
		$ = "FoomaticRIPCommandLine: \\\"bash " ascii
		$ = "FoomaticRIPCommandLine: \\\"sh " ascii
		$ = "FoomaticRIPCommandLine: \\\"python " ascii
		$ = "FoomaticRIPCommandLine: \\\"perl " ascii
		$ = "FoomaticRIPCommandLine: \\\"echo " ascii

	condition:
		1 of them
}

rule SIGNATURE_BASE_SUSP_LNX_Linux_Malware_Indicators_Aug20_1 : FILE
{
	meta:
		description = "Detects indicators often found in linux malware samples. Note: This detection is based on common characteristics typically associated with the mentioned threats, must be considered a clue and does not conclusively prove maliciousness."
		author = "Florian Roth (Nextron Systems)"
		id = "9a1093a6-0239-5d1c-aa30-1ca725941583"
		date = "2020-08-03"
		modified = "2026-01-04"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/gen_lnx_malware_indicators.yar#L1-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "1d07d424f2a66b60e55d21dff6d4c4f9f2591c3ab622dcfbc1cd989d28b44017"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "&& chmod +x" ascii
		$s2 = "|base64 -" ascii
		$s3 = " /tmp" ascii
		$s4 = "|curl " ascii
		$s5 = "whoami" ascii fullword
		$fp1 = "WITHOUT ANY WARRANTY" ascii
		$fp2 = "postinst" ascii fullword
		$fp3 = "THIS SOFTWARE IS PROVIDED" ascii fullword
		$fp4 = "Free Software Foundation" ascii fullword
		$fp5 = "Too many sessions open! Use ssh_channel.close() or 'with'!"

	condition:
		filesize < 400KB and 3 of ( $s* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_SUSP_LNX_SH_Disk_Wiper_Script_Jun25 : FILE
{
	meta:
		description = "Detects unknown disk wiper script for Linux systems"
		author = "Florian Roth"
		id = "aad68277-4889-512d-b8b3-a4c4706fbc9e"
		date = "2025-06-19"
		modified = "2026-05-15"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/mal_wipers_jun25.yar#L24-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "f662f69fc7f4240cd8c00661db9484e76b5d02f903590140b4086fefcf9d9331"
		logic_hash = "99a0a393c2a636c10195c7ad85f3b282a30ba05fbc0f0db7fc04b0f79fbc6760"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "THIS SCRIPT IS LIVE AND ARMED!" ascii fullword
		$s2 = "FAIR WARNING!" ascii fullword
		$s3 = "lists devices" ascii fullword

	condition:
		uint16( 0 ) == 0x2123 and filesize < 2KB and all of them
}

rule SIGNATURE_BASE_SUSP_LNX_Sindoor_Desktopfile_Aug25 : FILE
{
	meta:
		description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
		author = "Pezier Pierre-Henri"
		id = "16719116-0cb2-5c70-a86f-f65f9ea32153"
		date = "2025-08-29"
		modified = "2026-05-15"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_apt36_operation_sindoor.yar#L19-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59"
		logic_hash = "1549aac3132c5f3e73d984c3404a5530507e967df4ab6d5ccd408abc874a5306"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$hdr = "[Desktop Entry]"
		$s1 = "printf '\\\\x7FELF' | dd of"
		$s2 = "Future_Note_Warfare_OpSindoor.pdf"

	condition:
		filesize < 100KB and $hdr and any of ( $s* )
}

rule SIGNATURE_BASE_SUSP_LNX_Sindoor_ELF_Obfuscation_Aug25 : FILE
{
	meta:
		description = "Detects ELF obfuscation technique used by Sindoor dropper related to APT 36"
		author = "Pezier Pierre-Henri"
		id = "97802224-0d8b-5691-a6f1-f031626cda53"
		date = "2025-08-29"
		modified = "2026-05-15"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_apt36_operation_sindoor.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "6879a2b730e391964afe4dbbc29667844ba0c29239be5503b7c86e59e7052443"
		logic_hash = "c1258c1f6d4b49104bedf3fbef932f1775ede7d32191df2e5479ca9b291add9e"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "UPX!"

	condition:
		filesize < 10MB and uint16( 0 ) == 0 and uint16( 4 ) > 0 and $s1 in ( 0xc0 .. 0x100 )
}

rule SEKOIA_Apt_Oilrig_Webshell : FILE
{
	meta:
		description = "Detects a webshell used by OilRig"
		author = "Sekoia.io"
		id = "53955117-5176-4682-89ad-1503faba42aa"
		date = "2024-10-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/apt_oilrig_webshell.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "0e0879bafa1becf7e4aef008229a79ab8e0c50eda03232abd5cbb8fc59f482d3"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "string d = com;"
		$ = "string p = fu;"
		$ = "#@rt12!@$$$nnMF##"
		$ = "messi(d)))"

	condition:
		2 of them and filesize < 80KB
}

rule SEKOIA_Tool_Bypassgodzilla : FILE
{
	meta:
		description = "Detects payload of BypassGodzilla"
		author = "Sekoia.io"
		id = "fa492f97-a46c-422d-a617-c503744ee22e"
		date = "2024-09-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/tool_bypassgodzilla.yar#L1-L38"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		hash = "571c9042c627abba19ba1d591e2083eb"
		hash = "56cfc5a876f8f55bf184be9f368b6d8a"
		hash = "d4f7ca537701aee8849c474bc4df19d1"
		hash = "e4be04331c5f447b3ca03aa637d16c85"
		hash = "905fa3b692577a086ac654ef89e8b83d"
		logic_hash = "47e52267c73209c6191910ac21bca44acac2100be96250fd5dda1f889fb03b07"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$jsp_1a = "response.getWriter().write(\""
		$jsp_1b = "\".substring("
		$jsp_2a = "response.getWriter().write(java.util.Base64/*"
		$jsp_2b = "*/.getEncoder()/*"
		$jsp_2c = ".toByteArray(),true)));"
		$asp_1 = "[\"payload\"]).CreateInstance(\"LY\");"
		$asp_2 = "\\U00000045\\U00000071\\U00000075\\U00000061\\U0000006C\\U00000073(Context);"
		$php_1 = "=(\"!\"^\"@\").'ss'.Chr(\"101\").'rs';"
		$php_2 = "*/md5/*"
		$php_3 = "*/isset($_SESSION/*"
		$php_4 = "@set_time_limit(Chr(\"48\"))"

	condition:
		(( all of ( $jsp_* ) and ( @jsp_1b- @jsp_1a < 70 ) and ( @jsp_2b- @jsp_2a < 70 ) and ( @jsp_2c - @jsp_2a < 160 ) ) or ( all of ( $asp_* ) and ( @asp_2 > @asp_1 ) ) or ( all of ( $php_* ) ) ) and filesize < 30KB and true
}

rule SEKOIA_Tool_Pivotnacci_Webshell : FILE
{
	meta:
		description = "Detects pivotnacci webshell"
		author = "Sekoia.io"
		id = "729b6381-b59d-46fe-9ad4-b8b68fb0ceea"
		date = "2024-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/tool_pivotnacci_webshell.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "a57792915b4c888547ebe0b08b928e4bc32b3526c98a3ccc9fca0193cedee20a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "if (cmd == SEND_OPERATION) {"
		$ = "Response.BinaryWrite(newBuff)"
		$ = "Request.Headers.Get(ID_HEADER)"
		$ = "[$READ_BUFFER_SESSION_KEY . $connection_id]"
		$ = "extract_session_readbuf($conn_id"
		$ = "Failed connecting to target $addr:$port : $errstr"
		$ = "void handle_post(String cmd)"
		$ = "SocketChannel socketChannel = this.get_socket(socket_id"
		$ = "this.get_svc().compareTo(this.get_hostname())"

	condition:
		3 of them and filesize < 10KB
}

rule SEKOIA_Tool_Webshell_B374K_Strings : FILE
{
	meta:
		description = "Detects b374k webshell"
		author = "Sekoia.io"
		id = "f53fc668-e1fc-4b85-b850-59aceefb6418"
		date = "2024-09-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/tool_webshell_b374k_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		hash = "1d27b23fceecbb9e854c41f6a8fb878e"
		hash = "71fd853a3f3efc3dc2846e866187ee59"
		hash = "187e001c32487d0d68197ddb7e7796c3"
		hash = "6eac497dfc1020a8475e95542fad197e"
		hash = "61c6a0bc15efa442853f04bb276ac96e"
		logic_hash = "b085a50d50fc1fd06d6f75397cf1fa6fa1bc4a0d18b56ed3458990f4abde0632"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$func('$x','ev'.'al'.'("
		$ = "(ba'.'se'.'64'.'_de'.'co'.'de($x)))"

	condition:
		2 of them and filesize < 1MB
}

rule SEKOIA_Webshell_Icesword_Strings : FILE
{
	meta:
		description = "Detects icesword webshell"
		author = "Sekoia.io"
		id = "2c6b3cec-4200-4386-8cd5-4004c9b5b96a"
		date = "2024-11-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/webshell_icesword_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		hash = "0447352827e61696304a8e3d34e1d270"
		hash = "f49cfcda0abdefa385eda7ec7e7a5411"
		hash = "e1518388375ba772ed20503ec6dc6c8a"
		hash = "ecf08cd6af127e01f913354529174a23"
		logic_hash = "25ea8c1f4756595e63f09dfdfd1cb0e9bbf1d05e46150e22993de95d9f758385"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "&fsAction=rename&newName="
		$ = "&fsAction=copyto&dstPath="

	condition:
		2 of them and filesize < 100KB
}

rule SEKOIA_Webshell_Wso_Webshell_Strings
{
	meta:
		description = "Detects the WSO webshells"
		author = "Sekoia.io"
		id = "84340792-73a4-4d61-9957-6cfa1f6444a7"
		date = "2022-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/webshell_wso_webshell_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "4d6966a34dc8e7390913857144da106affea14668d1c2c11a05be62a6e625c8f"
		score = 75
		quality = 80
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "decrypt($str,$pwd){$pwd=base64_encode($pwd);"
		$ = "prototype(md5($_SERVER['HTTP_HOST'])"
		$ = "$_COOKIE[md5($_SERVER['HTTP_HOST'])."
		$ = "set(a,c,p1,p2,p3,charset)"
		$ = "(($p & 0x0008) ? (($p & 0x0400)"
		$ = "gcc','lcc','cc','ld','make','php"

	condition:
		3 of them
}

rule SEKOIA_Weevely_Webshell_Payload : FILE
{
	meta:
		description = "Detects weevely webshell"
		author = "Sekoia.io"
		id = "f2879c6e-3d1b-41be-8b1d-4f0503fd4b29"
		date = "2024-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/weevely_webshell_payload.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "bb02ec519d77526cc81ebd7743336b333b9498f79079f7008970cf1bb51c4948"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "<?php include \""
		$s2 = ".basename(__FILE__).\""
		$s3 = ";__HALT_COMPILER(); ?>"

	condition:
		all of them and filesize < 1MB and @s1 == 0 and @s2 < @s3
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Console_Jsp
{
	meta:
		description = "Strings from the console.jsp webshell"
		author = "Fox-IT SRT"
		id = "1afdfc34-d2e3-58c7-80ea-ee5632e42469"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_op_wocao.yar#L318-L335"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "e70c15ef10b63a011edbcedc773a8e2917fd915c3ecc273c3bf2b78eb10fc570"
		score = 75
		quality = 85

	strings:
		$a = "String strLogo = request.getParameter(\"image\")"
		$b = "!strLogo.equals(\"web.gif\")"
		$c = "<font color=red>Save Failed!</font>"
		$d = "<font color=red>Save Success!</font>"
		$e = "Save path:<br><input type=text"
		$f = "if (newfile.exists() && newfile.length()>0) { out.println"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Index_Jsp
{
	meta:
		description = "Strings from the index.jsp socket tunnel"
		author = "Fox-IT SRT"
		id = "9c226ccd-6c69-523c-bca4-371e55274667"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_op_wocao.yar#L337-L353"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "870dad9fb5456f8edbd9f3c2d0b8764cf1143399626ce4df53c93919bcb1a0cb"
		score = 75
		quality = 85

	strings:
		$x1 = "X-CMD"
		$x2 = "X-STATUS"
		$x3 = "X-TARGET"
		$x4 = "X-ERROR"
		$a = "out.print(\"All seems fine.\");"

	condition:
		all of ( $x* ) and $a
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Ver_Jsp
{
	meta:
		description = "Strings from the ver.jsp webshell"
		author = "Fox-IT SRT"
		id = "b2828b84-8934-5111-9345-683a07025070"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_op_wocao.yar#L355-L372"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "ada6de4b07a76e79bb17793cda2b51f96554a35992a73f59c360487638ae3be3"
		score = 75
		quality = 85

	strings:
		$a = "String strLogo = request.getParameter(\"id\")"
		$b = "!strLogo.equals(\"256\")"
		$c = "boolean chkos = msg.startsWith"
		$d = "while((c = er.read()) != -1)"
		$e = "out.print((char)c);}in.close()"
		$f = "out.print((char)c);}er.close()"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Webinfo
{
	meta:
		description = "Generic strings from webinfo.war webshells"
		author = "Fox-IT SRT"
		id = "b8477f62-f3f6-5526-b0e3-9b794fefaa1f"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_op_wocao.yar#L374-L394"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "711737a56067f24f422cc7d5aeba4389741fe18a0e66f2715fce626c3b6aef19"
		score = 75
		quality = 85

	strings:
		$var1 = "String strLogo = request.getParameter"
		$var2 = "String content = request.getParameter(\"content\");"
		$var3 = "String basePath=request.getScheme()"
		$var4 = "!strLogo.equals("
		$var5 = "if(path!=null && !path.equals(\"\") && content!=null"
		$var6 = "File newfile=new File(path);"
		$str1 = "Save Success!"
		$str2 = "Save Failed!"

	condition:
		2 of ( $var* ) or ( all of ( $str* ) and 1 of ( $var* ) )
}

rule SIGNATURE_BASE_APT_WEBSHELL_HAFNIUM_Chopper_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
		author = "Markus Neis,Swisscom"
		id = "25dcf166-4aea-5680-b161-c5fc8d74b987"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_hafnium.yar#L50-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "c185a8da2a18fa59a8eeb36dbd95ba12c9c61717efc5f2d19d2d5b27ee243f2b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "runat=\"server\">" nocase
		$s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
		$s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
		$s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase

	condition:
		filesize < 10KB and $x1 and 1 of ( $s* )
}

rule SIGNATURE_BASE_APT_WEBSHELL_HAFNIUM_Secchecker_Mar21_1 : FILE
{
	meta:
		description = "Detects HAFNIUM SecChecker webshell"
		author = "Florian Roth (Nextron Systems)"
		id = "73db3d78-7ece-53be-9efb-d19801993d5e"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/markus_neis/status/1367794681237667840"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_hafnium.yar#L18-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
		logic_hash = "e0e4df860bdde7d5c277f596535c493d926095be6f46f6ba41b6177afbfc5cd9"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
		$x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword

	condition:
		uint16( 0 ) == 0x253c and filesize < 1KB and 1 of them or 2 of them
}

rule SIGNATURE_BASE_APT_WEBSHELL_PHP_Sandworm_May20_1 : FILE
{
	meta:
		description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "b9ec02c2-fa83-5f21-95cf-3528047b2d01"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_exim_expl.yar#L86-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
		logic_hash = "0d10f618c7b465c7691d6054e994a76f56c12eb0a36d2d98b5accd2c1e2c1da7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$h1 = "GIF89a <?php $" ascii
		$s1 = "str_replace(" ascii

	condition:
		filesize < 10KB and $h1 at 0 and $s1
}

rule SIGNATURE_BASE_APT_WEBSHELL_Tiny_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_hafnium.yar#L67-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		logic_hash = "9309f9b57353b6fe292048d00794699a8637a3e6e429c562fb36c7e459003a3b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"
		$s1 = "=Request.Form(\""
		$s2 = "eval("

	condition:
		filesize < 300 and all of ( $s* ) and $x1
}

rule SIGNATURE_BASE_EXPL_JSP_Commvault_CVE_2025_57791_Aug25_1 : FILE
{
	meta:
		description = "Detects potential exploit for WT-2025-0049, Post-Auth RCE with QCommand Path Traversal"
		author = "X__Junior"
		id = "6fdfa207-6361-5dfb-b313-623d7cfa95f1"
		date = "2025-08-21"
		modified = "2026-05-15"
		reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_commvault_cve_2025_57791.yar#L50-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "359b35ced874244901f64bc09456cfec7079421ef6bab58ea95a3b1887ecc858"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "<App_GetUserPropertiesResponse>" ascii
		$s2 = "getMethod('getRuntime').invoke(null).exec(param.cmd)" ascii

	condition:
		filesize < 50KB and all of them
}

rule SIGNATURE_BASE_EXPL_JSP_Commvault_CVE_2025_57791_Aug25_2 : FILE
{
	meta:
		description = "Detects potential exploit for WT-2025-0049, Post-Auth RCE with QCommand Path Traversal"
		author = "X__Junior"
		id = "068e1598-bcde-579d-910a-449a7ad903d6"
		date = "2025-08-21"
		modified = "2026-05-15"
		reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_commvault_cve_2025_57791.yar#L65-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "3375a33556a9b479f0c170de6e06c80ab0277f1356e4ac44bfe51d6a65a578fe"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "<App_UpdateUserPropertiesRequest>" ascii
		$s2 = "<description>" ascii
		$s3 = "getMethod('getRuntime').invoke(null).exec(param.cmd)" ascii

	condition:
		filesize < 50KB and all of them
}

rule SIGNATURE_BASE_EXPL_POC_Springcore_0Day_Webshell_Mar22_1 : FILE
{
	meta:
		description = "Detects webshell found after SpringCore exploitation attempts POC script"
		author = "Florian Roth (Nextron Systems)"
		id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"
		date = "2022-03-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_spring4shell.yar#L36-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "17282b66899356a6051f0b47a7a3f02265737283d760f2256e03a2b934bb63b8"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];"
		$x2 = "if(\"j\".equals(request.getParameter(\"pwd\")"
		$x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"

	condition:
		filesize < 200KB and 1 of them
}

rule SIGNATURE_BASE_EXPL_React_Server_CVE_2025_55182_POC_Dec25 : CVE_2025_55182
{
	meta:
		description = "Detects in-memory webshell indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182)"
		author = "Florian Roth"
		id = "1ad38541-1477-5c07-9975-318357bcb9b8"
		date = "2025-12-05"
		modified = "2026-05-15"
		reference = "https://x.com/pyn3rd/status/1996840827897954542/photo/1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/react_pocs_indicators_dec25.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "a4f27fc85807e8f94e6947523a09d87ceed0658334756a9724322181c3eecd20"
		score = 70
		quality = 85
		tags = "CVE-2025-55182"

	strings:
		$xs1 = "{const cmd=p.query.cmd;if(!cmd)(s.writeHead(400);"
		$s1 = ";if(p.pathname=="
		$s2 = ".writeHead(400);"
		$s3 = ".writeHead(200,{'Content-Type':"
		$s4 = ".execSync("
		$s5 = ",stdio:'pipe'})"

	condition:
		1 of ( $x* ) or all of ( $s* )
}

rule SIGNATURE_BASE_FE_APT_Webshell_PL_HARDPULSE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "f9a2922e-6b8e-5f92-a947-3215ee8883ac"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_pulsesecure.yar#L46-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "980cba9e82faf194edb6f3cc20dc73ff"
		logic_hash = "37fc40fd998d3294edb05707170bc2deec524fc6451bff212901f9ac3e34bb35"
		score = 75
		quality = 83

	strings:
		$r1 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}unless[\x09\x20]{0,32}\(open\(\$\w{1,64},[\x09\x20]{0,32}\$\w{1,64}\)\)\s{0,128}\{\s{1,128}goto[\x09\x20]{1,32}\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}return[\x09\x20]{1,32}0[\x09\x20]{0,32}\x3b\s{0,128}\}/
		$r2 = /open[\x09\x20]{0,32}\(\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>/
		$r3 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}print[\x09\x20]{0,32}[\x22\x27]Content-type/
		$s1 = "CGI::request_method()"
		$s2 = "CGI::param("
		$s3 = "syswrite("
		$s4 = "print $_"

	condition:
		all of them
}

rule SIGNATURE_BASE_FE_APT_Webshell_PL_PULSECHECK_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "f375fdd8-567b-569b-85f4-af54a35d2a93"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_pulsesecure.yar#L116-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "a1dcdf62aafc36dd8cf64774dea80d79fb4e24ba2a82adf4d944d9186acd1cc1"
		logic_hash = "aba457dd33232ef37ca145c5b7cd9c5fe809730339a55c5e90ac46b4a136f6cb"
		score = 75
		quality = 85

	strings:
		$r1 = /while[\x09\x20]{0,32}\(<\w{1,64}>\)[\x09\x20]{0,32}\{\s{1,256}\$\w{1,64}[\x09\x20]{0,32}\.=[\x09\x20]{0,32}\$_;\s{0,256}\}/
		$s1 = "use Crypt::RC4;"
		$s2 = "use MIME::Base64"
		$s3 = "MIME::Base64::decode("
		$s4 = "popen("
		$s5 = " .= $_;"
		$s6 = "print MIME::Base64::encode(RC4("
		$s7 = "HTTP_X_"

	condition:
		$s1 and $s2 and ( @s3 [ 1 ] < @s4 [ 1 ] ) and ( @s4 [ 1 ] < @s5 [ 1 ] ) and ( @s5 [ 1 ] < @s6 [ 1 ] ) and ( #s7 > 2 ) and $r1
}

rule SIGNATURE_BASE_FE_APT_Webshell_PL_STEADYPULSE_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "49457fbb-9288-565f-909d-e8228c21c1e4"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_pulsesecure.yar#L265-L284"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
		logic_hash = "a0e3ebdd02ccf5cc8fc0a83c1d0224aed45dc5094eb85bd855e5b74b34e3aaaf"
		score = 75
		quality = 85

	strings:
		$s1 = "parse_parameters"
		$s2 = "s/\\+/ /g"
		$s3 = "s/%(..)/pack("
		$s4 = "MIME::Base64::encode($"
		$s5 = "$|=1;"
		$s6 = "RC4("
		$s7 = "$FORM{'cmd'}"

	condition:
		all of them
}

rule SIGNATURE_BASE_FE_Webshell_PL_ATRIUM_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "b2663343-0bae-5215-a443-866ab8626bff"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_pulsesecure.yar#L12-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "ca0175d86049fa7c796ea06b413857a3"
		logic_hash = "869b397616495c644beb997602eac84ddcdbacce4c14755c555f5bda36663ca2"
		score = 75
		quality = 85

	strings:
		$s1 = "CGI::param("
		$s2 = "system("
		$s3 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)\)\s{0,128}\{[\x09\x20]{0,32}print [\x22\x27]Cache-Control: no-cache\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}print [\x22\x27]Content-type: text\/html\\n\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}my \$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32};\s{0,128}system\([\x22\x27]\$/

	condition:
		all of them
}

rule SIGNATURE_BASE_WEBSHELL_Cookie_Post_Obfuscation : FILE
{
	meta:
		description = "Detects webshell using cookie POST"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
		date = "2023-01-28"
		modified = "2023-04-05"
		reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/gen_webshells.yar#L6883-L6909"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
		hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
		hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
		hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
		hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
		hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
		hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
		hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
		hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"
		logic_hash = "87229859ca3ee8f8b79360603c421528cda2ecefcc46d4080236d09b2dd510fb"
		score = 75
		quality = 85
		tags = "FILE"
		importance = 70

	strings:
		$s1 = "]($_COOKIE, $_POST) as $"
		$s2 = "function"
		$s3 = "Array"

	condition:
		( uint16( 0 ) == 0x3f3c and filesize < 100KB and ( all of them ) )
}

rule SIGNATURE_BASE_WEBSHELL_G_APT_Backdoorwebshell_SLAYSTYLE_1 : FILE
{
	meta:
		description = "Detects webshell used by APT group UNC5221 (China Nexus)"
		author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
		id = "6d3dfb91-a14b-5420-b17b-c6d65c94fc53"
		date = "2025-09-25"
		modified = "2026-05-15"
		reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_cn_brickstorm_sep25.yar#L98-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "7a56238218e60a69049f5d9c756df4fb6f0de772fbc437a14c5db7192f971be6"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$str1_alt = "=request.getParameter(\""
		$str2 = "=new String(java.util.Base64.getDecoder().decode(" ascii wide nocase
		$str21_alt = "={\"/bin/sh\",\"-c\"," ascii
		$str3 = "= Runtime.getRuntime().exec(" ascii
		$str4 = "java.io.InputStream" ascii
		$str5 = "java.util.Base64.getEncoder().encodeToString(org.apache.commons.io.IOUtils.toByteArray(" ascii

	condition:
		filesize < 5MB and all of them
}

rule SIGNATURE_BASE_WEBSHELL_G_APT_Backdoorwebshell_SLAYSTYLE_2 : FILE
{
	meta:
		description = "Detects webshell used by APT group UNC5221 (China Nexus)"
		author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
		id = "5ab6791b-5043-5fa1-b73e-caba9e059eaa"
		date = "2025-09-25"
		modified = "2026-05-15"
		reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_cn_brickstorm_sep25.yar#L119-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "d2d1003f77a2066b48df1c27feab79c0a1951ebb62c3198de8366bcfee42e30a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str1 = "request.getParameter"
		$str2 = "/bin/sh"
		$str3 = "java.io.InputStream"
		$str4 = "Runtime.getRuntime().exec("
		$str5 = "2>&1"

	condition:
		( uint16( 0 ) != 0x5A4D and uint32( 0 ) != 0x464C457F ) and filesize < 7KB and all of them and @str4 > @str2
}

rule SIGNATURE_BASE_WEBSHELL_JAVA_Versamem_JAR_Aug24_1 : FILE
{
	meta:
		description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
		author = "blacklotuslabs (modified by Florian Roth and X__Junior)"
		id = "9b666e61-cfa8-58b3-a362-772cd907c57c"
		date = "2024-08-27"
		modified = "2024-08-29"
		reference = "https://x.com/ryanaraine/status/1828440883315999117"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_volttyphoon_versamem.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "d21558eb6c8e700b8a4cb86fdaa5487179828152af68828e878397859d6d3952"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sa1 = "com.versa.vnms.ui.TestMain"
		$sa2 = "captureLoginPasswordCode"
		$sa3 = "com/versa/vnms/ui/services/impl/VersaAuthenticationServiceImpl"
		$sa4 = "/tmp/.temp.data"
		$sa5 = "getInsertCode"
		$sa6 = "VersaMem"
		$sa7 = "Versa-Auth"
		$sb1 = "/tmp/.java_pid"
		$sb2 = {2f 75 73 72 2f 62 69 6e 2f 70 67 72 65 70 01 00 02 2d 66 01 00 25 6f 72 67 2e 61 70 61 63 68 65 2e 63 61 74 61 6c 69 6e 61 2e 73 74 61 72 74 75 70 2e 42 6f 6f 74 73 74 72 61 70 07}

	condition:
		filesize < 5MB and ( 3 of them or all of ( $sb* ) )
}

rule SIGNATURE_BASE_WEBSHELL_JSP_Nov21_1 : FILE
{
	meta:
		description = "Detects JSP webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "117eed28-c44e-5983-b4c7-b555fc06d923"
		date = "2021-11-23"
		modified = "2023-12-05"
		reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_spring4shell.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "1dac7706421961c71ba6f8d7a223b80e4b77bf206bfb64ee18c7cc894b062a3c"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "request.getParameter(\"pwd\")" ascii
		$x2 = "excuteCmd(request.getParameter(" ascii
		$x3 = "getRuntime().exec (request.getParameter(" ascii
		$x4 = "private static final String PW = \"whoami\"" ascii

	condition:
		filesize < 400KB and 1 of them
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell : FILE
{
	meta:
		description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		id = "862aab77-936e-524c-8669-4f48730f4ed5"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_centreon.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "977ee0fdf0e92ccea6b71fea7b2c7aed2965c6966d8af86230ccb0f95b286694"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$php = "<?php"
		$strreplace = "(str_replace("
		$md5 = ".substr(md5(strrev($"
		$gzinflate = "gzinflate"
		$cookie = "_COOKIE"
		$isset = "isset"

	condition:
		( filesize > 20KB and filesize < 200KB ) and all of them
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Perlnetworkscript : FILE
{
	meta:
		description = "Detects PERL scripts created by P.A.S. webshell"
		author = "FR/ANSSI/SDO"
		id = "1625b63f-ead7-5712-92b4-0ce6ecc49fd4"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_centreon.yar#L44-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "b170c07a005e737c8069f2cc63f869d4d3ff6593b3bfca5bcaf02d7808da6852"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
		$pl_status = "$o=\" [OK]\";$e=\" Error: \""
		$pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
		$msg1 = "print \"$l OK! I\\'m successful connected.$l\""
		$msg2 = "print \"$l OK! I\\'m accept connection.$l\""

	condition:
		filesize < 6000 and ( $pl_start at 0 and all of ( $pl* ) ) or any of ( $msg* )
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Sqldumpfile
{
	meta:
		description = "Detects SQL dump file created by P.A.S. webshell"
		author = "FR/ANSSI/SDO"
		id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_centreon.yar#L64-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "c34abcada22fdf462fd66cc2da18ab9e54215defc6f7a7a95b5a80d1155a2ffe"
		score = 90
		quality = 85

	strings:
		$ = "-- [ SQL Dump created by P.A.S. ] --"

	condition:
		1 of them
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Ziparchivefile
{
	meta:
		description = "Detects an archive file created by P.A.S. for download operation"
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_sandworm_centreon.yar#L30-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "c15e7022f45ec211ba635d6cd31bab16f4fb0d3038fb19d5765e0f751c14a826"
		score = 80
		quality = 85

	strings:
		$s1 = "Archive created by P.A.S. v."

	condition:
		$s1
}

rule SIGNATURE_BASE_WEBSHELL_PHP_In_Htaccess : FILE
{
	meta:
		description = "Use Apache .htaccess to execute php code inside .htaccess"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
		date = "2021-01-07"
		modified = "2023-07-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/gen_webshells.yar#L2756-L2778"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
		hash = "e1d1091fee6026829e037b2c70c228344955c263"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"
		logic_hash = "0652a4cb0cb6c61afece5c2e4cbf2f281714509f0d828047f2e3ccd411602115"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$hta = "AddType application/x-httpd-php .htaccess" wide ascii

	condition:
		filesize < 100KB and $hta
}

rule SIGNATURE_BASE_WEBSHELL_Proxyshell_Exploitation_Nov21_1
{
	meta:
		description = "Detects webshells dropped by DropHell malware"
		author = "Florian Roth (Nextron Systems)"
		id = "300eaadf-db0c-5591-84fc-abdf7cdd90c1"
		date = "2021-11-01"
		modified = "2025-11-03"
		reference = "https://www.deepinstinct.com/blog/do-not-exchange-it-has-a-shell-inside"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_proxyshell.yar#L257-L271"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "d9812d3f53c346c4e318609e0c7de66811b27ffa7528a6ddeb6ac8436da59ef5"
		score = 85
		quality = 85

	strings:
		$s01 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request[" ascii wide
		$s02 = "new System.IO.MemoryStream()" ascii wide
		$s03 = "Transform(" ascii wide

	condition:
		all of ( $s* )
}

rule SIGNATURE_BASE_WEBSHELL_SECRETSAUCE_Jul23_1 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects SECRETSAUCE PHP webshells (found after an exploitation of Citrix NetScaler ADC CVE-2023-3519)"
		author = "Florian Roth"
		id = "db0542e7-648e-5f60-9838-e07498f58b51"
		date = "2023-07-24"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L79-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		logic_hash = "c762d46ae43a3e10453c2ee17039812a06086ac85bdb000cf8308f5196a9dee2"
		score = 85
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$sa1 = "for ($x=0; $x<=1; $x++) {" ascii
		$sa2 = "$_REQUEST[" ascii
		$sa3 = "@eval" ascii
		$sb1 = "public $cmd;" ascii
		$sb2 = "return @eval($a);" ascii
		$sb3 = "$z->run($z->get('openssl_public_decrypt'));"

	condition:
		filesize < 100KB and ( all of ( $sa* ) or 2 of ( $sb* ) )
}

rule VOLEXITY_Apt_Malware_Py_Upstyle : UTA0218 FILE MEMORY
{
	meta:
		description = "Detect the UPSTYLE webshell."
		author = "threatintel@volexity.com"
		id = "45726f35-8b3e-5095-b145-9e7f6da6838b"
		date = "2024-04-11"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
		hash = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
		hash = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
		logic_hash = "51923600b23d23f4ce29eac7f5ab9f7e1ddb45bed5f6727ddec4dcb75872e473"
		score = 75
		quality = 80
		tags = "UTA0218, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10429
		version = 2

	strings:
		$stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
		$stage1_str2 = "exec(base64."
		$stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
		$stage2_str2 = "exec(base64."
		$stage3_str1 = "write(\"/*\"+output+\"*/\")"
		$stage3_str2 = "SHELL_PATTERN"

	condition:
		all of ( $stage1* ) or all of ( $stage2* ) or all of ( $stage3* )
}

rule VOLEXITY_Apt_Webshell_Java_Orangetail : UTA0533 ORANGETAIL FILE MEMORY
{
	meta:
		description = "Detection for ORANGETAIL, a custom Java webshell used by UTA0533."
		author = "threatintel@volexity.com"
		id = "5bbffb5f-0917-57e4-a7d4-f5c770b5d253"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2026/2026-07-17 SonicWall/rules.yar#L26-L53"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
		logic_hash = "1a495df2bc13b1c2c61315d76d66b150452b923afa5847121429fa8ae9788a7b"
		score = 75
		quality = 80
		tags = "UTA0533, ORANGETAIL, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20260714B"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13239
		version = 5

	strings:
		$s1 = "agentmain called args="
		$s2 = "tryInject="
		$s3 = "agentmain ex:"
		$s4 = "javassist="
		$s5 = "tryInject exception"
		$s6 = "found loaded class:"

	condition:
		4 of ( $s* )
}

rule VOLEXITY_Apt_Webshell_Java_Orangetail_B : UTA0533 ORANGETAIL FILE MEMORY
{
	meta:
		description = "Detection for the accept logic of ORANGETAIL, a custom Java webshell used by UTA0533."
		author = "threatintel@volexity.com"
		id = "e9f19175-ea33-5eea-8663-91fc805306bb"
		date = "2026-07-06"
		modified = "2026-07-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2026/2026-07-17 SonicWall/rules.yar#L1-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
		hash = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
		logic_hash = "e5ed25fb820dc4a18c374936c36d4321e2aba72d8b640cdb0d81abd764786918"
		score = 75
		quality = 80
		tags = "UTA0533, ORANGETAIL, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		report1 = "TIB-20260714B"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 13240
		version = 6

	strings:
		$s1 = ".equals($1.getHeader(\"User-Agent\"))) {  javax.servlet.jsp.JspFactory" ascii
		$s2 = " $2.setStatus(404);  $2.setContentLength(0);  $2.flushBuffer();  return;" ascii

	condition:
		all of them
}

rule VOLEXITY_Apt_Webshell_Pl_Complyshell : UTA0178 FILE MEMORY
{
	meta:
		description = "Detection for the COMPLYSHELL webshell."
		author = "threatintel@volexity.com"
		id = "6b44b5bc-a75f-573c-b9c3-562b7874e408"
		date = "2023-12-13"
		modified = "2024-01-12"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L3-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
		logic_hash = "ff46691f1add20cff30fe996e2fb199ce42408e86d5642a8a43c430f2245b1f5"
		score = 75
		quality = 80
		tags = "UTA0178, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9995
		version = 4

	strings:
		$s = "eval{my $c=Crypt::RC4->new("

	condition:
		$s
}

rule VOLEXITY_Webshell_Java_Realcmd : FILE MEMORY
{
	meta:
		description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
		author = "threatintel@volexity.com"
		id = "60b30ccc-bcfa-51e6-a3f5-88037d19213e"
		date = "2022-06-01"
		modified = "2024-07-30"
		reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L61-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
		logic_hash = "e09f2a23674fd73296dd4d1fabf1a2c812bfe69ff02abc96a4be35af6a18e512"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6786
		version = 4

	strings:
		$fn1 = "runCmd" wide ascii fullword
		$fn2 = "RealCMD" ascii wide fullword
		$fn3 = "buildJson" ascii wide fullword

	condition:
		all of ( $fn* )
}

rule VOLEXITY_Webshell_Jsp_Converge : FILE MEMORY CVE_2022_26134
{
	meta:
		description = "Detects CONVERGE - a file upload webshell observed in incident involving compromise of Confluence server via CVE-2022-26134."
		author = "threatintel@volexity.com"
		id = "2a74678e-cb00-567c-a2e0-2e095f3e5ee8"
		date = "2022-06-01"
		modified = "2024-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L1-L21"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		logic_hash = "bb48516342eddd48c35e6db0eb74f95e116dc723503552b99ba721b5bdb391e5"
		score = 75
		quality = 80
		tags = "FILE, MEMORY, CVE-2022-26134"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6788
		version = 5

	strings:
		$s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

	condition:
		$s1
}

rule VOLEXITY_Webshell_Jsp_Regeorg : FILE MEMORY
{
	meta:
		description = "Detects the reGeorg webshells' JSP version."
		author = "threatintel@volexity.com"
		id = "205ee383-4298-5469-a509-4ce3eaf9dd0e"
		date = "2022-03-08"
		modified = "2024-09-20"
		reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L57-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
		logic_hash = "cecb71605d9112d509823c26e40e1cf9cd6db581db448db5c9ffc63a2bfe529e"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6575
		version = 5

	strings:
		$magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii
		$a1 = ".connect(new InetSocketAddress" ascii
		$a2 = ".configureBlocking(false)" ascii
		$a3 = ".setHeader(" ascii
		$a4 = ".getHeader(" ascii
		$a5 = ".flip();" ascii

	condition:
		$magic or all of ( $a* )
}

rule SEKOIA_Generic_Php_Webshell : FILE
{
	meta:
		description = "Detects generic webshell"
		author = "Sekoia.io"
		id = "415a96bd-11a4-40e7-8335-ac1f1a99d17c"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/yara_rules/generic_php_webshell.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/06702882880251b045e1f047aaea455914a7cbcf/LICENSE.md"
		logic_hash = "617264a785b8e9e87a39e12d7b72963d94e0686a174716347369fe71ab7a78af"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "system($_POST['a']);"

	condition:
		all of them and filesize < 500
}

rule SIGNATURE_BASE_M_Hunting_Webshell_LIGHTWIRE_2 : FILE
{
	meta:
		description = "Detects LIGHTWIRE based on the RC4 decoding and execution 1-liner."
		author = "Mandiant (modified by Florian Roth)"
		id = "9451da63-c68e-51e8-b4b1-c3082d46fbf6"
		date = "2024-01-11"
		modified = "2024-01-12"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/apt_report_ivanti_mandiant_jan24.yar#L60-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "3d97f55a03ceb4f71671aa2ecf5b24e9"
		logic_hash = "37b22a6c45dd53bc7b3f0c75cc5072e990246fea24591d192176c0b496e92084"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "eval{my"
		$s2 = "Crypt::RC4->new(\""
		$s3 = "->RC4(decode_base64(CGI::param('"
		$s4 = ";eval $"
		$s5 = "\"Compatibility check: $@\";}"

	condition:
		filesize < 10KB and all of them
}

rule SIGNATURE_BASE_REGEORG_Tuneller_Generic : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Mandiant"
		id = "a87979b7-2732-5a32-b3f3-a815a58b6589"
		date = "2021-12-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/webshell_regeorg.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "ba22992ce835dadcd06bff4ab7b162f9"
		logic_hash = "1657928875c3cd2d5bf774929b0497d78f0211b321f8a4138cc9b8c80b9f99d6"
		score = 75
		quality = 85
		tags = "FILE"
		date_modified = "2021-12-20"

	strings:
		$s1 = "System.Net.IPEndPoint"
		$s2 = "Response.AddHeader"
		$s3 = "Request.InputStream.Read"
		$s4 = "Request.Headers.Get"
		$s5 = "Response.Write"
		$s6 = "System.Buffer.BlockCopy"
		$s7 = "Response.BinaryWrite"
		$s8 = "SocketException soex"

	condition:
		filesize < 1MB and 7 of them
}

rule SIGNATURE_BASE_WEBSHELL_JSP_Generic_Processbuilder : FILE
{
	meta:
		description = "Generic JSP webshell which uses processbuilder to execute user input"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
		date = "2021-01-07"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/yara/gen_webshells.yar#L5963-L6000"
		license_url = "https://github.com/Neo23x0/signature-base/blob/3ce6640c26046da8e6d8094af3eaaee3ee84e648/LICENSE"
		hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
		hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
		hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
		hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"
		logic_hash = "fffc173cc23e158e319e48097243a64da232151e441c39e4b6ecc2565a82d862"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$exec = "ProcessBuilder" fullword wide ascii
		$start = "start" fullword wide ascii
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide

	condition:
		filesize < 2000 and ( any of ( $input* ) and any of ( $req* ) ) and $exec and $start
}

rule VOLEXITY_Susp_Jsp_General_Runtime_Exec_Req : FILE MEMORY
{
	meta:
		description = "Looks for a common design pattern in webshells where a request attribute is passed as an argument to exec()."
		author = "threatintel@volexity.com"
		id = "7f1539bd-a2f0-50dd-b500-ada4e0971d13"
		date = "2022-02-02"
		modified = "2024-07-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L35-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
		logic_hash = "d3048aba80c1c39f1673931cd2d7c5ed83045603b0ad204073fd788d0103a6c8"
		score = 65
		quality = 80
		tags = "FILE, MEMORY"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6450
		version = 3

	strings:
		$s1 = "Runtime.getRuntime().exec(request." ascii

	condition:
		$s1
}

rule VOLEXITY_Susp_Php_Call_User_Func : FILE
{
	meta:
		description = "Webshells using call_user_func() function against an object from a file input or POST variable."
		author = "threatintel@volexity.com"
		id = "48c7857e-7dda-5e3f-b82c-7d34c251f083"
		date = "2021-06-16"
		modified = "2024-07-30"
		reference = "https://zhuanlan.zhihu.com/p/354906657"
		source_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L183-L205"
		license_url = "https://github.com/volexity/threat-intel/blob/683296427d8c7f08938ce6c587f618c938cf4c54/LICENSE.txt"
		hash = "40b053a2f3c8f47d252b960a9807b030b463ef793228b1670eda89f07b55b252"
		logic_hash = "46c999da97682023861e58f9cd2c8651480db990a0361c1985c6d5c35b5bf0ea"
		score = 65
		quality = 80
		tags = "FILE"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5582
		version = 4

	strings:
		$s1 = "@call_user_func(new C()" wide ascii

	condition:
		$s1
}
