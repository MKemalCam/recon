#!/bin/bash

#-u flag yokken cikis, o pipefail grep no result icin koruma
set -uo pipefail

#adim atlama flaglari (--skip-<adim> ile acilir, bkz. show_usage)
SKIP_KEYS=false
SKIP_SUBFINDER=false
SKIP_GAU=false
SKIP_API_SORT=false
SKIP_GITHUB=false
SKIP_BRUTE=false
SKIP_HTTPX_PROBE=false
SKIP_API_SECRETS=false
SKIP_RESOLVE=false
SKIP_MASSCAN=false
SKIP_NAABU=false
SKIP_NMAP=false

TARGET=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="$SCRIPT_DIR/subdomain_wordlist.txt"

show_usage(){
	cat << EOF
Kullanim: $0 (-d <domain> | <domain>) [--skip-<adim> ...]

Argumanlar:
  -d <domain>          Taranacak hedef domain (pozisyonel de olur: $0 hedef.com)
  -h, --help           Bu yardimi goster

Adim atlama flaglari (test icin):
  --skip-keys          api key setup (interaktif)
  --skip-subfinder     pasif subdomain enum
  --skip-gau           pasif endpoint (YAVAS)
  --skip-api-sort      api/swagger endpoint filtreleme
  --skip-github        metabigor github arama
  --skip-brute         dnsx subdomain bruteforce
  --skip-httpx-probe   canli subdomain probe
  --skip-api-secrets   api icerik indir + trufflehog
  --skip-resolve       dnsx ip resolve
  --skip-masscan       masscan port tarama
  --skip-naabu         naabu connect scan
  --skip-nmap          nmap + httpx banner grab

Ornek:
  $0 -d testfire.net --skip-gau --skip-github
  $0 testfire.net --skip-keys --skip-subfinder --skip-gau
EOF
}

parse_args(){
	while [[ $# -gt 0 ]]; do
		case $1 in
			-h|--help)          show_usage; exit 0 ;;
			-d)
				if [[ -n "${2:-}" ]]; then TARGET="$2"; shift 2
				else echo "[!] -d bir domain argumani ister"; exit 1; fi ;;
			--skip-keys)        SKIP_KEYS=true;        shift ;;
			--skip-subfinder)   SKIP_SUBFINDER=true;   shift ;;
			--skip-gau)         SKIP_GAU=true;         shift ;;
			--skip-api-sort)    SKIP_API_SORT=true;    shift ;;
			--skip-github)      SKIP_GITHUB=true;      shift ;;
			--skip-brute)       SKIP_BRUTE=true;       shift ;;
			--skip-httpx-probe) SKIP_HTTPX_PROBE=true; shift ;;
			--skip-api-secrets) SKIP_API_SECRETS=true; shift ;;
			--skip-resolve)     SKIP_RESOLVE=true;     shift ;;
			--skip-masscan)     SKIP_MASSCAN=true;     shift ;;
			--skip-naabu)       SKIP_NAABU=true;       shift ;;
			--skip-nmap)        SKIP_NMAP=true;        shift ;;
			*)
				if [[ -z "$TARGET" ]]; then TARGET="$1"; shift
				else echo "[!] Bilinmeyen arguman: $1"; show_usage; exit 1; fi ;;
		esac
	done

	if [[ -z "$TARGET" ]]; then
		echo "[!] Hedef domain gerekli."
		show_usage
		exit 1
	fi
}

setup_output(){
	# dnsx bruteforce wordlist dependency
	if [ "$SKIP_BRUTE" != true ] && [ ! -f "$WORDLIST" ]; then
		echo "[!] $WORDLIST bulunamadi. Devam etmeden once wordlist dosyanizi script ile ayni klasore 'subdomain_wordlist.txt' adiyla koyunuz."
		echo "    (veya bruteforce'u atlamak icin: --skip-brute)"
		exit 1
	fi

	SAFE_TARGET=$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
	OUTPUT_DIR="cammk_${SAFE_TARGET}"
	mkdir -p "$OUTPUT_DIR"
}


check_deps(){
	local missing=0
	for tool in subfinder gau httpx-toolkit dnsx masscan naabu nmap trufflehog metabigor; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			echo "[!] eksik arac: $tool"
			missing=1
		fi
	done
	[ "$missing" -eq 1 ] && echo "[!] Eksik araclar var, devam edilse de ilgili adimlar basarisiz olabilir."
}


############################################
###          PASSIVE RECON               ###
############################################
# hedefe dogrudan istek atmayan adimlar
# subfinder (pasif kaynaklar), gau (wayback/otx/commoncrawl), github/osint.

api_key_setup(){
    local config_file="$OUTPUT_DIR/keys.yaml"

    if [[ -f "$config_file" ]]; then
        read -p "[?] $config_file zaten mevcut. Üzerine yazmak ister misiniz? (y/N): " cevap
        if [[ "$cevap" != "y" && "$cevap" != "Y" ]]; then
            echo "[*] Mevcut key'ler ile devam ediliyor..."
            return 0
        fi
    fi

    echo "İstenilen api keyleri giriniz."
    echo "Boş bırakılması durumunda bu keyin servisi kullanılmayacaktır."

    read -s -p "Shodan API key: "     shodan_key; echo
    read -s -p "VirusTotal API key: " vt_key;     echo
    read -s -p "GitHub API key: "     github_key; echo

    > "$config_file"
    chmod 600 "$config_file" #keys file protection

    append_key_to_yaml(){
        local provider=$1
        local api_key=$2

        if [[ -n "$api_key" ]]; then
            echo "${provider}:" >> "$config_file"
            echo "  - ${api_key}" >> "$config_file"
            echo "[+] ${provider} key eklendi."
        fi
    }

    echo "-----------------------------------"
    append_key_to_yaml "shodan" "$shodan_key"
    append_key_to_yaml "virustotal" "$vt_key"
    append_key_to_yaml "github" "$github_key"
    echo "API key ayarlama islemi tamamlandi. dosya: $config_file"
}

#subdomain enumeration (passive sources)
run_subfinder(){
	echo "[cammk] subfinder baslatiliyor..."
	if [ -f "$OUTPUT_DIR/keys.yaml" ]; then
		subfinder -d "$TARGET" -pc "$OUTPUT_DIR/keys.yaml" -recursive -o "$OUTPUT_DIR/subfinder_results"
	else
		subfinder -d "$TARGET" -recursive -o "$OUTPUT_DIR/subfinder_results"
	fi
	echo "[cammk] subfinder tamamlandi. sonuclar $OUTPUT_DIR/subfinder_results dosyasina kaydedildi."
	[ -s "$OUTPUT_DIR/subfinder_results" ] || echo "[!] subfinder sonuc uretmedi, sonraki adimlar bos/eksik olabilir."
}

#GAU
run_gau(){
	echo "[cammk] gau baslatiliyor..."
	local blacklist="css|jpg|jpeg|png|svg|gif|woff|woff2|ttf|eot|ico"
	local archive="zip|rar|7z|tar|gz|bak|sql|db|txt|env"

	cat "$OUTPUT_DIR/subfinder_results" | gau > "$OUTPUT_DIR/gau_raw_results"
	[ -s "$OUTPUT_DIR/gau_raw_results" ] || echo "[!] gau sonuc uretmedi."

	# grep || true guarding against a no match
	grep -ivE "\.($blacklist)($|\?)" "$OUTPUT_DIR/gau_raw_results"  > "$OUTPUT_DIR/gau_withArchive" || true
	grep -iE  "\.($archive)($|\?)"   "$OUTPUT_DIR/gau_withArchive" > "$OUTPUT_DIR/gau_archive"     || true
	grep -ivE "\.($archive)($|\?)"   "$OUTPUT_DIR/gau_withArchive" > "$OUTPUT_DIR/gau_filtered"    || true

	echo "[cammk] gau tamamlandi. arsiv urlleri gau_withArchive, filtreli urller gau_filtered dosyasina kaydedildi."
}

#API leak sort
run_api_sort(){
	echo "[cammk] sonuclar postman ve swagger icin sortlaniyor..."
	grep -iE "api|swagger|docs|postman|graphql|wadl" "$OUTPUT_DIR/gau_filtered" > "$OUTPUT_DIR/api_endpoints" || true
}

#Trufflehog GitHub scan (passive: repo/commit gecmisi)
run_github(){
	echo "[cammk] domain ismini iceren github repolari taraniyor..."
	echo "$TARGET" | metabigor github -o "$OUTPUT_DIR/github_results"
	if [ -s "$OUTPUT_DIR/github_results" ]; then
		echo "[cammk] github repolari bulundu."
		# trufflehog github --repo ...   (placeholder: repo dongusu doldurulacak)
	else
		echo "[cammk] domaine bagli github reposu bulunamadi"
		rm -f "$OUTPUT_DIR/github_results"   # FIX: -f, dosya olmayabilir
	fi
}


############################################
###           ACTIVE RECON               ###
############################################
# hedefe dogrudan trafik gidiyor
# httpx probe, response indirme, dnsx->masscan, naabu, nmap vb.

#subdomain bruteforce dnsx
run_brute(){
	echo "[cammk] dnsx subdomain bruteforce baslatiliyor..."
	dnsx -d "$TARGET" -w "$WORDLIST" -silent -o "$OUTPUT_DIR/dnsx_brute_results"
	if [ -s "$OUTPUT_DIR/dnsx_brute_results" ]; then
		echo "[cammk] bruteforce ile $(wc -l < "$OUTPUT_DIR/dnsx_brute_results") yeni subdomain adayi bulundu."
	else
		echo "[cammk] bruteforce ile yeni subdomain bulunamadi."
	fi
	cat "$OUTPUT_DIR/subfinder_results" "$OUTPUT_DIR/dnsx_brute_results" 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains_list"
}

#live subdomain probe httpx-toolkit
run_httpx_probe(){
	echo "[cammk] canli subdomain testi (httpx)..."
	#Kaan hocanin portlari
	local COMMON_HTTP_PORTS="80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"
	httpx-toolkit -l "$OUTPUT_DIR/subdomains_list" -ports "$COMMON_HTTP_PORTS" -o "$OUTPUT_DIR/live_subdomains"
	[ -s "$OUTPUT_DIR/live_subdomains" ] || echo "[!] canli subdomain bulunamadi."
}

#API endpoint icerik indirme + trufflehog
run_api_secrets(){
	if [ -s "$OUTPUT_DIR/api_endpoints" ]; then
		echo "[cammk] api endpoint bulundu. sonuclar $OUTPUT_DIR/api_endpoints dosyasına kaydedildi."
		mkdir -p "$OUTPUT_DIR/api_responses"
		echo "[cammk] api endpoint icerikleri indiriliyor..."
		cat "$OUTPUT_DIR/api_endpoints" | httpx-toolkit -silent -rl 5 -t 2 -random-agent -sr -srd "$OUTPUT_DIR/api_responses"


		if [ -d "$OUTPUT_DIR/api_responses" ] && [ -n "$(ls -A "$OUTPUT_DIR/api_responses" 2>/dev/null)" ]; then
			echo "[cammk] api endpointlerde secret aramalari yapilacak. trufflehog baslatiliyor..."
			trufflehog filesystem "$OUTPUT_DIR/api_responses" --no-update > "$OUTPUT_DIR/thog_api_key"
			[ ! -s "$OUTPUT_DIR/thog_api_key" ] && rm -f "$OUTPUT_DIR/thog_api_key"
		else
			echo "[cammk] indirilmis api yaniti yok, trufflehog atlaniyor."
		fi
	else
		echo "[cammk] api endpoint bulunamadi."
		rm -f "$OUTPUT_DIR/api_endpoints"
	fi

	if [ -f "$OUTPUT_DIR/thog_api_key" ]; then
		echo "[cammk] key/secret bulundu. $OUTPUT_DIR icerisinde kontrol ediniz."
	else
		echo "[cammk] herhangi bir key/secret bulunamadi."
	fi
}

#dnsx (ACTIVE: DNS cozumleme)
run_resolve(){
	echo "[cammk] ipler resolvelaniyor..."
	cat "$OUTPUT_DIR/subdomains_list" | dnsx -a -resp-only | sort -u > "$OUTPUT_DIR/resolved_ips"
	[ -s "$OUTPUT_DIR/resolved_ips" ] || echo "[!] ip resolve edilemedi, masscan/naabu bos donebilir."
}

#masscan full port scan (tepeye flag eklenecek, belli portlara limitlemek icin)
#--retries 3: tek SYN dusunce port kacmasin (masscan default'ta tekrar atmaz)
run_masscan(){
	echo "[cammk] masscan taramasi yapiliyor..."
	sudo masscan -iL "$OUTPUT_DIR/resolved_ips" -p1-65535 --rate 1000 --retries 3 -oL "$OUTPUT_DIR/masscan_raw"
}

#verified_ports = masscan + naabu + httpx birlesimi (union).
#Hicbir aracin flaky olmasi digerlerinin buldugunu sifirlamasin; httpx'in
#zaten dogruladigi HTTP portlari her zaman taban olur.
run_naabu(){
	: > "$OUTPUT_DIR/verified_ports"

	# 1) masscan'in bulduklari (ip:port) - dogrudan korunur, atilmaz
	if [ -s "$OUTPUT_DIR/masscan_raw" ]; then
		grep "open" "$OUTPUT_DIR/masscan_raw" | awk '{print $4":"$3}' >> "$OUTPUT_DIR/verified_ports" || true
	fi

	# 2) naabu connect scan - masscan'in kacirdigi ekstra portlar icin
	if [ -s "$OUTPUT_DIR/resolved_ips" ]; then
		naabu -l "$OUTPUT_DIR/resolved_ips" -s c -silent >> "$OUTPUT_DIR/verified_ports" 2>/dev/null || true
		echo "[cammk] naabu tamamlandi."
	fi

	# 3) httpx'in zaten dogruladigi HTTP portlari (taban - asla bos kalmasin)
	#    live_subdomains: http://h -> h:80, https://h -> h:443, http://h:8080 -> h:8080
	if [ -s "$OUTPUT_DIR/live_subdomains" ]; then
		awk -F/ '
			/^https:\/\// { hp=$3; print (hp ~ /:/) ? hp : hp":443" }
			/^http:\/\//  { hp=$3; print (hp ~ /:/) ? hp : hp":80"  }
		' "$OUTPUT_DIR/live_subdomains" >> "$OUTPUT_DIR/verified_ports" || true
	fi

	sort -u "$OUTPUT_DIR/verified_ports" -o "$OUTPUT_DIR/verified_ports"
	[ -s "$OUTPUT_DIR/verified_ports" ] && echo "[cammk] $(wc -l < "$OUTPUT_DIR/verified_ports") host:port toplandi (masscan+naabu+httpx)."
}

run_nmap(){
	if [ -s "$OUTPUT_DIR/verified_ports" ]; then
		cut -d: -f1 "$OUTPUT_DIR/verified_ports" | sort -u > "$OUTPUT_DIR/nmap_hosts"
		local ports
		ports=$(cut -d: -f2 "$OUTPUT_DIR/verified_ports" | sort -un | paste -sd, -)
		nmap -sV --version-intensity 2 -p "$ports" -iL "$OUTPUT_DIR/nmap_hosts" -oN "$OUTPUT_DIR/nmap_results"

		httpx-toolkit -l "$OUTPUT_DIR/verified_ports" -title -server -status-code -o "$OUTPUT_DIR/httpx_banner_grab"
	else
		echo "[cammk] dogrulanmis port yok, nmap/httpx banner adimi atlaniyor."
	fi
}


#pipeline: her adim SKIP_* bayragina gore calisir
run_step(){
	local skip_flag="$1" func="$2"
	if [ "${!skip_flag}" != true ]; then
		"$func"
	else
		echo "[cammk] (atlandi) $func — $skip_flag=true"
	fi
}

main(){
	parse_args "$@"
	setup_output
	check_deps

	run_step SKIP_KEYS        api_key_setup
	run_step SKIP_SUBFINDER   run_subfinder
	run_step SKIP_GAU         run_gau
	run_step SKIP_API_SORT    run_api_sort
	run_step SKIP_GITHUB      run_github

	run_step SKIP_BRUTE       run_brute
	run_step SKIP_HTTPX_PROBE run_httpx_probe
	run_step SKIP_API_SECRETS run_api_secrets
	run_step SKIP_RESOLVE     run_resolve
	run_step SKIP_MASSCAN     run_masscan
	run_step SKIP_NAABU       run_naabu
	run_step SKIP_NMAP        run_nmap

	echo "[cammk] pipeline tamamlandi."
}

main "$@"
