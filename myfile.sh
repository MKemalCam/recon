#!/bin/bash

#-u flag yokken cikis, o pipefail grep no result icin koruma
set -uo pipefail

#adim atlama flaglari
SKIP_KEYS=false
SKIP_SUBFINDER=false
SKIP_GAU=false
SKIP_API_SORT=false
SKIP_SWAGGER_POSTMAN=false
SKIP_GITHUB=false
SKIP_BRUTE=false
SKIP_HTTPX_PROBE=false
SKIP_API_SECRETS=false
SKIP_RESOLVE=false
SKIP_MASSCAN=false
SKIP_NAABU=false
SKIP_NMAP=false
SKIP_WHATWEB=false
SKIP_KATANA=false
SKIP_KATANA_JS=false
SKIP_FUZZ=false
SKIP_DEDUPE=false
SKIP_NUCLEI=false
SKIP_WAFW00F=false
SKIP_ORIGIN=false
CF_BYPASS=true
JITTER=true
RATE=5          # saniyede istek siniri (--rate)

TARGET=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="$SCRIPT_DIR/subdomain_wordlist.txt"
FUZZ_WORDLIST="$SCRIPT_DIR/fuzz_wordlist.txt"

#Kaan hocanin port listesi
COMMON_HTTP_PORTS="80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"

NAABU_PORTS=common

#User-Agent havuzu (her calismada biri secilir)
UA_POOL=(
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
)
USER_AGENT=""   # setup_output icinde rastgele secilir

#Cloudflare IPv4 aralari (kaynak: cloudflare.com/ips-v4)
CF_CIDRS=(
	173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
	141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
	197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
	104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
)

show_usage(){
	cat << EOF
Kullanim: $0 (-d <domain> | <domain>) [--skip-<adim> ...]

Argumanlar:
  -d <domain>          Taranacak hedef domain (pozisyonel de olur: $0 hedef.com)
  -h, --help           Bu yardimi goster
  --naabu-ports <m>    naabu port kapsami: common (varsayilan) | all
                       common = ortak HTTP/panel portlari, all = 1-65535
  --rate <n>           tum aktif araclarda saniyede istek siniri (varsayilan 5; ban riskine karsi dusur, or. 2)

Adim atlama flaglari:
  --skip-keys          api key setup
  --skip-subfinder     pasif subdomain enum
  --skip-gau           pasif endpoint
  --skip-api-sort      api/swagger endpoint filtreleme
  --skip-swagger-postman  online swagger/postman leak arama (swaggerhub + postman)
  --skip-github        github code search repo secret arama
  --skip-brute         dnsx subdomain bruteforce
  --skip-httpx-probe   canli subdomain probe
  --skip-api-secrets   api icerik indir + trufflehog
  --skip-resolve       dnsx ip resolve
  --skip-masscan       masscan port tarama
  --skip-naabu         naabu connect scan
  --skip-nmap          nmap + httpx banner grab
  --skip-whatweb       whatweb teknoloji/surum tespiti
  --skip-katana        katana crawl
  --skip-katana-js     katana js dosyalarini indir + trufflehog
  --skip-fuzz          ffuf ile dizin/dosya fuzzing
  --skip-dedupe        tum url'leri birlestir + httpx 404/fp ayikla
  --skip-nuclei        nuclei ile exposure/CWE-200 taramasi (WAF korumali)
  --skip-wafw00f       wafw00f WAF vendor kimligi + gizli WAF tespiti (nuclei icinde)
  --skip-origin        Cloudflare arkasi origin IP tespiti (aktif recon sonu)
  --skip-cf-bypass     dogrulanmis origin IP'leri nuclei hedeflerine EKLEME (varsayilan: ekli — KAPSAM DISI riski!)
  --no-jitter          istekler arasi rastgele gecikmeyi kapat

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
			--naabu-ports)
				if [[ "${2:-}" =~ ^(common|all)$ ]]; then NAABU_PORTS="$2"; shift 2
				else echo "[!] --naabu-ports sadece 'common' veya 'all' kabul eder"; exit 1; fi ;;
			--rate)
				if [[ "${2:-}" =~ ^[0-9]+$ ]] && [ "${2:-0}" -ge 1 ]; then RATE="$2"; shift 2
				else echo "[!] --rate pozitif tam sayi ister (or. --rate 2)"; exit 1; fi ;;
			--skip-keys)        SKIP_KEYS=true;        shift ;;
			--skip-subfinder)   SKIP_SUBFINDER=true;   shift ;;
			--skip-gau)         SKIP_GAU=true;         shift ;;
			--skip-api-sort)    SKIP_API_SORT=true;    shift ;;
			--skip-swagger-postman) SKIP_SWAGGER_POSTMAN=true; shift ;;
			--skip-github)      SKIP_GITHUB=true;      shift ;;
			--skip-brute)       SKIP_BRUTE=true;       shift ;;
			--skip-httpx-probe) SKIP_HTTPX_PROBE=true; shift ;;
			--skip-api-secrets) SKIP_API_SECRETS=true; shift ;;
			--skip-resolve)     SKIP_RESOLVE=true;     shift ;;
			--skip-masscan)     SKIP_MASSCAN=true;     shift ;;
			--skip-naabu)       SKIP_NAABU=true;       shift ;;
			--skip-nmap)        SKIP_NMAP=true;        shift ;;
			--skip-whatweb)     SKIP_WHATWEB=true;     shift ;;
			--skip-katana)      SKIP_KATANA=true;      shift ;;
			--skip-katana-js)   SKIP_KATANA_JS=true;   shift ;;
			--skip-fuzz)        SKIP_FUZZ=true;        shift ;;
			--skip-dedupe)      SKIP_DEDUPE=true;      shift ;;
			--skip-nuclei)      SKIP_NUCLEI=true;      shift ;;
			--skip-wafw00f)     SKIP_WAFW00F=true;     shift ;;
			--skip-origin)      SKIP_ORIGIN=true;      shift ;;
			--skip-cf-bypass)   CF_BYPASS=false;       shift ;;
			--no-jitter)        JITTER=false;          shift ;;
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

	# bu calisma icin rastgele UA sec
	USER_AGENT="${UA_POOL[$((RANDOM % ${#UA_POOL[@]}))]}"
	echo "[cammk] bu calisma icin User-Agent: $USER_AGENT"
}


check_deps(){
	local missing=0
	for tool in subfinder gau httpx-toolkit dnsx masscan naabu nmap trufflehog whatweb katana ffuf nuclei wafw00f curl jq; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			echo "[!] eksik arac: $tool"
			missing=1
		fi
	done
	[ "$missing" -eq 1 ] && echo "[!] Eksik araclar var, devam edilse de ilgili adimlar basarisiz olabilir."
}


#--- stealth / CF yardimcilari ---
#istekler arasi rastgele gecikme (--no-jitter kapatir)
jitter(){
	[ "$JITTER" != true ] && return 0
	local ms=$(( (RANDOM % 1300) + 200 ))   # 0.2 - 1.5 sn
	sleep "$(awk "BEGIN{printf \"%.3f\", $ms/1000}")"
}

#nokta-notasyonlu IPv4 -> 32-bit tamsayi
ip_to_int(){
	local IFS=. a b c d
	read -r a b c d <<< "$1"
	echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

#IP bir Cloudflare CIDR'inde mi?
is_cf_ip(){
	local ip="$1" cidr base bits ipint baseint mask
	[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
	ipint=$(ip_to_int "$ip")
	for cidr in "${CF_CIDRS[@]}"; do
		base="${cidr%/*}"; bits="${cidr#*/}"
		baseint=$(ip_to_int "$base")
		mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
		(( (ipint & mask) == (baseint & mask) )) && return 0
	done
	return 1
}


############################################
###          PASSIVE RECON               ###
############################################
# hedefe dogrudan istek atmayan adimlar
# subfinder (pasif kaynaklar), gau (wayback/otx/commoncrawl), github/postman/swagger osint.

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
    read -s -p "Chaos API key: "      chaos_key;  echo
    read -s -p "Censys API key: "     censys_key; echo

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
    append_key_to_yaml "chaos" "$chaos_key"
    append_key_to_yaml "censys" "$censys_key"
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

#url listesini indir (httpx) + trufflehog ile secret tara.
sp_secret_scan(){
	local urls="$1" label="$2"
	[ -s "$urls" ] || return 0
	local respdir="$OUTPUT_DIR/${label}_responses"
	mkdir -p "$respdir"
	echo "[cammk] $label icerikleri indiriliyor..."
	# sadece cozulmus http(s) url'ler indirilir ({{baseUrl}} kalanlar atlanir)
	grep -iE '^https?://' "$urls" | httpx-toolkit -silent -rl "$RATE" -t 2 -random-agent -sr -srd "$respdir" || true
	if [ -n "$(ls -A "$respdir" 2>/dev/null)" ]; then
		echo "[cammk] $label icin trufflehog baslatiliyor..."
		trufflehog filesystem "$respdir" --no-update > "$OUTPUT_DIR/thog_$label"
		[ ! -s "$OUTPUT_DIR/thog_$label" ] && rm -f "$OUTPUT_DIR/thog_$label"
	else
		echo "[cammk] $label icin indirilmis yanit yok, trufflehog atlaniyor."
	fi
	if [ -f "$OUTPUT_DIR/thog_$label" ]; then
		echo "[cammk] $label icinde key/secret bulundu. $OUTPUT_DIR icerisinde kontrol ediniz."
	else
		echo "[cammk] $label icinde key/secret bulunamadi."
	fi
}

#online swagger/postman leak arama
run_swagger_postman(){
	echo "[cammk] online swagger/postman leak aramasi (swaggerhub + postman)..."
	# curl varsayilan UA bloklanabiliyor (bu calismanin UA'si)
	local ua="$USER_AGENT"
	local raw="$OUTPUT_DIR/.sp_raw"

	# 1) swaggerhub public spec arama -> spec (swagger.json) url'leri
	curl -s --max-time 30 -A "$ua" -H "accept: application/json" \
		"https://app.swaggerhub.com/apiproxy/specs?sort=BEST_MATCH&order=DESC&query=${TARGET}&page=0&limit=100" \
		> "$raw" 2>/dev/null || true
	jq -r '.apis[]?.properties[]? | select(.url != null) | .url' "$raw" 2>/dev/null \
		| sort -u > "$OUTPUT_DIR/swagger_results" || true
	if [ -s "$OUTPUT_DIR/swagger_results" ]; then
		echo "[cammk] swaggerhub: $(wc -l < "$OUTPUT_DIR/swagger_results") spec url bulundu."
	else
		echo "[cammk] swaggerhub sonuc uretmedi."
		rm -f "$OUTPUT_DIR/swagger_results"
	fi

	# 2) postman public arama -> request url'leri ({{baseUrl}} varsa cozulur)
	local body="{\"service\":\"search\",\"method\":\"POST\",\"path\":\"/search-all\",\"body\":{\"queryIndices\":[\"runtime.request\"],\"queryText\":\"${TARGET}\",\"size\":100,\"from\":0,\"requestOrigin\":\"srp\",\"mergeEntities\":\"true\",\"nonNestedRequests\":\"true\"}}"
	curl -s --max-time 30 -A "$ua" -H "Content-Type: application/json" \
		-X POST "https://www.postman.com/_api/ws/proxy" -d "$body" \
		> "$raw" 2>/dev/null || true
	jq -r '.data[]?.document? | select(.url != null) | .baseUrl as $b | .url | gsub("\\{\\{baseUrl\\}\\}"; ($b // ""))' "$raw" 2>/dev/null \
		| sort -u > "$OUTPUT_DIR/postman_results" || true
	if [ -s "$OUTPUT_DIR/postman_results" ]; then
		echo "[cammk] postman: $(wc -l < "$OUTPUT_DIR/postman_results") request url bulundu."
	else
		echo "[cammk] postman sonuc uretmedi."
		rm -f "$OUTPUT_DIR/postman_results"
	fi
	rm -f "$raw"

	# her sonuc dosyasi ayri ayri indirilip trufflehog ile taranir (gau'dan bagimsiz)
	sp_secret_scan "$OUTPUT_DIR/swagger_results" swagger
	sp_secret_scan "$OUTPUT_DIR/postman_results" postman
}

#github secret leak
#github token required
run_github(){
	echo "[cammk] github code search ile domaini iceren repolar araniyor..."

	# code search auth ister: keys.yaml'daki github token (yoksa adim atlanir)
	local gh_token=""
	[ -f "$OUTPUT_DIR/keys.yaml" ] && gh_token=$(grep -A1 '^github:' "$OUTPUT_DIR/keys.yaml" 2>/dev/null | sed -n 's/^ *- *//p' | head -1)
	if [ -z "$gh_token" ]; then
		echo "[!] github token yok (keys.yaml). code search icin gerekli, adim atlaniyor. (--skip-keys kullandiysaniz once key girin)"
		return 0
	fi

	local raw="$OUTPUT_DIR/.gh_raw"
	# -G + --data-urlencode: q dogru sekilde url-encode edilir
	curl -s --max-time 30 -G \
		-H "Authorization: Bearer $gh_token" \
		-H "Accept: application/vnd.github+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		--data-urlencode "q=$TARGET" \
		--data-urlencode "per_page=100" \
		"https://api.github.com/search/code" > "$raw" 2>/dev/null || true
	jq -r '.items[]?.repository.full_name' "$raw" 2>/dev/null | sort -u > "$OUTPUT_DIR/github_results" || true
	rm -f "$raw"

	if [ ! -s "$OUTPUT_DIR/github_results" ]; then
		echo "[cammk] domaine bagli github reposu bulunamadi."
		rm -f "$OUTPUT_DIR/github_results"
		return 0
	fi
	echo "[cammk] $(wc -l < "$OUTPUT_DIR/github_results") repo bulundu, trufflehog ile taraniyor..."

	: > "$OUTPUT_DIR/thog_github"
	while IFS= read -r repo; do
		[ -z "$repo" ] && continue
		echo "[cammk] trufflehog: $repo"
		# </dev/null: trufflehog loop stdin'ini (repo listesi) yemesin
		trufflehog github --repo "https://github.com/$repo" --token "$gh_token" --no-update </dev/null 2>/dev/null >> "$OUTPUT_DIR/thog_github" || true
	done < "$OUTPUT_DIR/github_results"

	if [ -s "$OUTPUT_DIR/thog_github" ]; then
		echo "[cammk] github repolarinda key/secret bulundu. $OUTPUT_DIR/thog_github kontrol ediniz."
	else
		echo "[cammk] github repolarinda key/secret bulunamadi."
		rm -f "$OUTPUT_DIR/thog_github"
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
	dnsx -d "$TARGET" -w "$WORDLIST" -silent -retry 2 -o "$OUTPUT_DIR/dnsx_brute_results"
	if [ -s "$OUTPUT_DIR/dnsx_brute_results" ]; then
		echo "[cammk] bruteforce ile $(wc -l < "$OUTPUT_DIR/dnsx_brute_results") yeni subdomain adayi bulundu."
	else
		echo "[cammk] bruteforce ile yeni subdomain bulunamadi."
	fi
	cat "$OUTPUT_DIR/subfinder_results" "$OUTPUT_DIR/dnsx_brute_results" 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains_list"
}

#live subdomain probe httpx-toolkit (global COMMON_HTTP_PORTS)
run_httpx_probe(){
	echo "[cammk] canli subdomain testi (httpx)..."
	httpx-toolkit -l "$OUTPUT_DIR/subdomains_list" -ports "$COMMON_HTTP_PORTS" -o "$OUTPUT_DIR/live_subdomains"
	[ -s "$OUTPUT_DIR/live_subdomains" ] || echo "[!] canli subdomain bulunamadi."
}

#API endpoint icerik indirme + trufflehog
run_api_secrets(){
	if [ -s "$OUTPUT_DIR/api_endpoints" ]; then
		echo "[cammk] api endpoint bulundu. sonuclar $OUTPUT_DIR/api_endpoints dosyasına kaydedildi."
		mkdir -p "$OUTPUT_DIR/api_responses"
		echo "[cammk] api endpoint icerikleri indiriliyor..."
		cat "$OUTPUT_DIR/api_endpoints" | httpx-toolkit -silent -rl "$RATE" -t 2 -random-agent -sr -srd "$OUTPUT_DIR/api_responses"


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
	cat "$OUTPUT_DIR/subdomains_list" | dnsx -a -resp-only -retry 2 | sort -u > "$OUTPUT_DIR/resolved_ips"
	[ -s "$OUTPUT_DIR/resolved_ips" ] || echo "[!] ip resolve edilemedi, masscan/naabu bos donebilir."
}

#masscan full port scan
run_masscan(){
	echo "[cammk] masscan taramasi yapiliyor..."
	sudo masscan -iL "$OUTPUT_DIR/resolved_ips" -p1-65535 --rate 1000 --retries 3 -oL "$OUTPUT_DIR/masscan_raw"
}

#verified_ports = masscan + naabu + httpx birlesimi
run_naabu(){
	: > "$OUTPUT_DIR/verified_ports"

	# 1) masscan'in bulduklari (ip:port)
	if [ -s "$OUTPUT_DIR/masscan_raw" ]; then
		grep "open" "$OUTPUT_DIR/masscan_raw" | awk '{print $4":"$3}' >> "$OUTPUT_DIR/verified_ports" || true
	fi

	# 2) naabu connect scan 
	if [ -s "$OUTPUT_DIR/resolved_ips" ]; then
		local naabu_ports
		[ "$NAABU_PORTS" = all ] && naabu_ports="-" || naabu_ports="$COMMON_HTTP_PORTS"
		naabu -l "$OUTPUT_DIR/resolved_ips" -p "$naabu_ports" -s c -silent >> "$OUTPUT_DIR/verified_ports" 2>/dev/null || true
		echo "[cammk] naabu tamamlandi (kapsam: $NAABU_PORTS)."
	fi

	# 3) httpx'in zaten dogruladigi HTTP portlari
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

#whatweb ile canli hostlarda framework/surum tespiti
run_whatweb(){
	if [ ! -s "$OUTPUT_DIR/live_subdomains" ]; then
		echo "[cammk] canli host yok, whatweb atlaniyor."
		return 0
	fi
	echo "[cammk] whatweb ile teknoloji tespiti yapiliyor..."
	whatweb -i "$OUTPUT_DIR/live_subdomains" -a 3 -t 5 --no-errors \
		--log-brief="$OUTPUT_DIR/whatweb_brief.txt" \
		--log-json="$OUTPUT_DIR/whatweb.json"
	echo "[cammk] whatweb tamamlandi. ozet: whatweb_brief.txt, json: whatweb.json"
}

#katana crawl
run_katana(){
	if [ ! -s "$OUTPUT_DIR/live_subdomains" ]; then
		echo "[cammk] canli host yok, katana atlaniyor."
		return 0
	fi
	echo "[cammk] katana ile crawl yapiliyor..."
	katana -list "$OUTPUT_DIR/live_subdomains" -jc -kf all -d 3 -c 3 -rl "$RATE" -silent -o "$OUTPUT_DIR/katana_urls"
	[ -s "$OUTPUT_DIR/katana_urls" ] && echo "[cammk] katana tamamlandi. $(wc -l < "$OUTPUT_DIR/katana_urls") url katana_urls dosyasina kaydedildi." || echo "[!] katana url uretmedi."
}

#katana js filter + trufflehog
run_katana_js(){
	if [ ! -s "$OUTPUT_DIR/katana_urls" ]; then
		echo "[cammk] katana_urls yok, js secret taramasi atlaniyor."
		return 0
	fi
	grep -iE '\.js($|\?)' "$OUTPUT_DIR/katana_urls" | sort -u > "$OUTPUT_DIR/katana_js_urls" || true
	if [ ! -s "$OUTPUT_DIR/katana_js_urls" ]; then
		echo "[cammk] js dosyasi bulunamadi, trufflehog atlaniyor."
		rm -f "$OUTPUT_DIR/katana_js_urls"
		return 0
	fi
	echo "[cammk] $(wc -l < "$OUTPUT_DIR/katana_js_urls") js dosyasi indiriliyor..."
	mkdir -p "$OUTPUT_DIR/katana_js_responses"
	cat "$OUTPUT_DIR/katana_js_urls" | httpx-toolkit -silent -rl "$RATE" -t 2 -random-agent -sr -srd "$OUTPUT_DIR/katana_js_responses"

	if [ -d "$OUTPUT_DIR/katana_js_responses" ] && [ -n "$(ls -A "$OUTPUT_DIR/katana_js_responses" 2>/dev/null)" ]; then
		echo "[cammk] js dosyalarinda secret aramalari yapilacak. trufflehog baslatiliyor..."
		trufflehog filesystem "$OUTPUT_DIR/katana_js_responses" --no-update > "$OUTPUT_DIR/thog_katana_js"
		[ ! -s "$OUTPUT_DIR/thog_katana_js" ] && rm -f "$OUTPUT_DIR/thog_katana_js"
	else
		echo "[cammk] indirilmis js yaniti yok, trufflehog atlaniyor."
	fi

	if [ -f "$OUTPUT_DIR/thog_katana_js" ]; then
		echo "[cammk] js dosyalarinda key/secret bulundu. $OUTPUT_DIR icerisinde kontrol ediniz."
	else
		echo "[cammk] js dosyalarinda key/secret bulunamadi."
	fi
}

#fuzzing - ffuf ile canli hostlarda gizli dizin/dosya/panel aramasi
run_fuzz(){
	if [ ! -s "$OUTPUT_DIR/live_subdomains" ]; then
		echo "[cammk] canli host yok, fuzzing atlaniyor."
		return 0
	fi
	if [ ! -f "$FUZZ_WORDLIST" ]; then
		echo "[!] fuzz wordlist yok ($FUZZ_WORDLIST), fuzzing atlaniyor. (script klasorune 'fuzz_wordlist.txt' koyun)"
		return 0
	fi
	echo "[cammk] ffuf ile fuzzing yapiliyor..."
	: > "$OUTPUT_DIR/fuzz_results"
	while IFS= read -r host; do
		[ -z "$host" ] && continue
		# -ac: wildcard/false-positive, -s: sadece bulunan path'i yaz
		# </dev/null: ffuf interaktif konsolu loop stdin'ini (host dosyasini) yiyip takilmasin
		ffuf -u "${host%/}/FUZZ" -w "$FUZZ_WORDLIST" -mc 200,204,301,302,307,401,403,405 -ac -t 5 -rate "$RATE" -p 0.1-0.5 -timeout 10 -s </dev/null 2>/dev/null \
			| sed "s#^#${host%/}/#" >> "$OUTPUT_DIR/fuzz_results" || true
	done < "$OUTPUT_DIR/live_subdomains"
	sort -u "$OUTPUT_DIR/fuzz_results" -o "$OUTPUT_DIR/fuzz_results"
	[ -s "$OUTPUT_DIR/fuzz_results" ] && echo "[cammk] fuzzing tamamlandi. $(wc -l < "$OUTPUT_DIR/fuzz_results") sonuc fuzz_results dosyasina kaydedildi." || echo "[cammk] fuzzing sonuc uretmedi."
}

#dedupe + 404/fp ayiklama - tum kaynaklardan url'leri birlestir, httpx ile canli olanlari dogrula
#not: 403/404 de canli sayilir (hedeftir), status code filtrelenmez
run_dedupe(){
	cat "$OUTPUT_DIR/gau_filtered" "$OUTPUT_DIR/api_endpoints" "$OUTPUT_DIR/katana_urls" \
		"$OUTPUT_DIR/fuzz_results" "$OUTPUT_DIR/live_subdomains" 2>/dev/null \
		| sort -u > "$OUTPUT_DIR/all_urls"
	if [ ! -s "$OUTPUT_DIR/all_urls" ]; then
		echo "[cammk] birlestirilecek url yok, dedupe atlaniyor."
		return 0
	fi
	echo "[cammk] $(wc -l < "$OUTPUT_DIR/all_urls") url httpx ile dogrulaniyor (dedupe + fp/404)..."
	cat "$OUTPUT_DIR/all_urls" | httpx-toolkit -silent -status-code -title -o "$OUTPUT_DIR/all_live_urls"
	[ -s "$OUTPUT_DIR/all_live_urls" ] && echo "[cammk] dedupe tamamlandi. $(wc -l < "$OUTPUT_DIR/all_live_urls") canli url all_live_urls dosyasina kaydedildi." || echo "[cammk] canli url bulunamadi."
}

############################################
###               VULN SCAN              ###
############################################

#--- WAF farkindalik yardimcilari ---
#tek host'a rastgele-yol prob at, HTTP status don
waf_probe_status(){
	local url="$1" ua="$2" rand
	rand="zz$(date +%s%N | tail -c 7)$RANDOM"
	curl -s -o /dev/null -m 10 -A "$ua" -w '%{http_code}' "${url%/}/$rand" 2>/dev/null
}

#403/406/429/503 = WAF blok
waf_is_blocked_status(){
	case "$1" in 403|406|429|503) return 0 ;; *) return 1 ;; esac
}

#tarama oncesi: challenge donen host'lari ayir -> hosts_open / hosts_defended
waf_classify(){
	local ua="$1" url status
	: > "$OUTPUT_DIR/hosts_open"; : > "$OUTPUT_DIR/hosts_defended"
	while IFS= read -r url; do
		[ -z "$url" ] && continue
		jitter
		status=$(waf_probe_status "$url" "$ua")
		if waf_is_blocked_status "$status"; then
			echo "$url" >> "$OUTPUT_DIR/hosts_defended"
		else
			echo "$url" >> "$OUTPUT_DIR/hosts_open"
		fi
	done < "$OUTPUT_DIR/live_subdomains"
	echo "[cammk] WAF on-tespiti: $(wc -l < "$OUTPUT_DIR/hosts_open" 2>/dev/null | tr -d ' ') acik, $(wc -l < "$OUTPUT_DIR/hosts_defended" 2>/dev/null | tr -d ' ') WAF/challenge (taramadan ayrildi)."
}

#tarama sonrasi canary: acik host hala erisilebilir mi?
waf_canary(){
	local ua="$1" url status
	: > "$OUTPUT_DIR/hosts_blocked"
	while IFS= read -r url; do
		[ -z "$url" ] && continue
		jitter
		status=$(waf_probe_status "$url" "$ua")
		waf_is_blocked_status "$status" && echo "$url" >> "$OUTPUT_DIR/hosts_blocked"
	done < "$OUTPUT_DIR/hosts_open"
	if [ -s "$OUTPUT_DIR/hosts_blocked" ]; then
		echo "[!] UYARI: $(wc -l < "$OUTPUT_DIR/hosts_blocked" | tr -d ' ') host tarama SIRASINDA bloklandi (bkz hosts_blocked)."
		echo "[!] Bu host'lardaki 'bulgu yok' sonucu GUVENILMEZ — manuel/origin inceleme gerekir."
	fi
}

#wafw00f: WAF vendor kimligi + gizli 200-challenge WAF'lari taramadan cikar
waf_fingerprint(){
	if ! command -v wafw00f >/dev/null 2>&1; then
		echo "[cammk] wafw00f kurulu degil, WAF vendor kimligi atlaniyor."
		return 0
	fi
	[ -s "$OUTPUT_DIR/hosts_open" ] || return 0

	echo "[cammk] wafw00f: $(wc -l < "$OUTPUT_DIR/hosts_open" | tr -d ' ') acik host'ta WAF vendor kimligi taraniyor..."
	wafw00f -i "$OUTPUT_DIR/hosts_open" -f json -o "$OUTPUT_DIR/waf_fingerprints.json" >/dev/null 2>&1 || true
	if [ ! -s "$OUTPUT_DIR/waf_fingerprints.json" ]; then
		echo "[cammk] wafw00f ciktisi bos/parse edilemedi, atlaniyor."
		return 0
	fi

	# tespit edilen WAF'lar (url \t firewall)
	jq -r '.[] | select(.detected==true) | "\(.url)\t\(.firewall)"' \
		"$OUTPUT_DIR/waf_fingerprints.json" 2>/dev/null > "$OUTPUT_DIR/waf_vendors.txt" || true
	if [ ! -s "$OUTPUT_DIR/waf_vendors.txt" ]; then
		echo "[cammk] wafw00f acik host'larda WAF tespit etmedi."
		return 0
	fi

	# curl 'acik' dedi ama wafw00f WAF gordu -> gizli WAF, taramadan cikar
	local drop="$OUTPUT_DIR/.stealth_urls"
	cut -f1 "$OUTPUT_DIR/waf_vendors.txt" | grep -xF -f - "$OUTPUT_DIR/hosts_open" > "$drop" 2>/dev/null || true
	if [ -s "$drop" ]; then
		grep -F -f "$drop" "$OUTPUT_DIR/waf_vendors.txt" > "$OUTPUT_DIR/hosts_stealth_waf" 2>/dev/null || true
		grep -vxF -f "$drop" "$OUTPUT_DIR/hosts_open" > "$OUTPUT_DIR/hosts_open.tmp" 2>/dev/null || true
		mv "$OUTPUT_DIR/hosts_open.tmp" "$OUTPUT_DIR/hosts_open"
		cat "$drop" >> "$OUTPUT_DIR/hosts_defended"
		echo "[!] wafw00f, curl'un 'acik' dedigi $(wc -l < "$drop" | tr -d ' ') host'ta GIZLI WAF buldu — taramadan cikarildi (bkz hosts_stealth_waf)."
	fi
	rm -f "$drop"

	echo "[cammk] WAF vendor dagilimi (acik host'lar):"
	cut -f2 "$OUTPUT_DIR/waf_vendors.txt" | sort | uniq -c | sort -rn
}

#Cloudflare arkasi origin IP tespiti
run_origin(){
	if [ ! -s "$OUTPUT_DIR/resolved_ips" ]; then
		echo "[cammk] resolved_ips yok (once run_resolve gerekir), origin tespiti atlaniyor."
		return 0
	fi

	# 1) hangi cozumlenen IP'ler CF edge? (origin degil)
	: > "$OUTPUT_DIR/cf_edge_ips"; : > "$OUTPUT_DIR/non_cf_ips"
	while IFS= read -r ip; do
		[ -z "$ip" ] && continue
		if is_cf_ip "$ip"; then echo "$ip" >> "$OUTPUT_DIR/cf_edge_ips"
		else echo "$ip" >> "$OUTPUT_DIR/non_cf_ips"; fi
	done < "$OUTPUT_DIR/resolved_ips"
	local ncf; ncf=$(wc -l < "$OUTPUT_DIR/cf_edge_ips" 2>/dev/null | tr -d ' ')
	echo "[cammk] CF edge tespiti: $ncf cozumlenen IP Cloudflare aralarinda (origin DEGIL, edge)."
	if [ "$ncf" -eq 0 ]; then
		echo "[cammk] Cloudflare arkasinda host yok gorunuyor — origin arama atlaniyor."
		return 0
	fi

	# 2) origin adaylari: uncover (shodan/censys)
	echo "[cammk] origin adaylari araniyor (uncover shodan,censys — keys.yaml gerekir)..."
	nuclei -uncover -uq "ssl:\"$TARGET\"" -ue shodan,censys -uf ip -ul 100 -silent 2>/dev/null \
		| sort -u > "$OUTPUT_DIR/origin_candidates" || true
	# CF aralarindaki adaylari ele
	if [ -s "$OUTPUT_DIR/origin_candidates" ]; then
		while IFS= read -r ip; do
			[ -z "$ip" ] && continue
			is_cf_ip "$ip" || echo "$ip"
		done < "$OUTPUT_DIR/origin_candidates" > "$OUTPUT_DIR/origin_candidates.f"
		mv "$OUTPUT_DIR/origin_candidates.f" "$OUTPUT_DIR/origin_candidates"
	fi
	if [ ! -s "$OUTPUT_DIR/origin_candidates" ]; then
		echo "[cammk] origin adayi bulunamadi (uncover bos veya keys yok)."
		return 0
	fi

	# 3) dogrulama: baslik eslesirse origin say
	: > "$OUTPUT_DIR/origin_ips"
	local ref_title cand_title ip
	ref_title=$(curl -s -m 10 -A "$USER_AGENT" "https://$TARGET/" 2>/dev/null | grep -oiE '<title>[^<]*' | head -1)
	while IFS= read -r ip; do
		[ -z "$ip" ] && continue
		jitter
		cand_title=$(curl -s -m 10 -k -A "$USER_AGENT" --resolve "$TARGET:443:$ip" "https://$TARGET/" 2>/dev/null | grep -oiE '<title>[^<]*' | head -1)
		if [ -n "$cand_title" ] && [ "$cand_title" = "$ref_title" ]; then
			echo "$ip" >> "$OUTPUT_DIR/origin_ips"
			echo "[cammk]   origin DOGRULANDI: $ip (site basligi eslesti)"
		fi
	done < "$OUTPUT_DIR/origin_candidates"

	if [ -s "$OUTPUT_DIR/origin_ips" ]; then
		echo "[cammk] $(wc -l < "$OUTPUT_DIR/origin_ips" | tr -d ' ') dogrulanmis origin IP -> origin_ips."
		if [ "$CF_BYPASS" = true ]; then
			echo "[!] origin IP'ler nuclei hedeflerine EKLENECEK (varsayilan) — KAPSAM DISI olabilir, ROE'yi dogrula! (kapatmak: --skip-cf-bypass)"
		else
			echo "[cammk] (not) --skip-cf-bypass verildi; origin IP'ler yalnizca raporlandi, taramaya dahil edilmedi."
		fi
	else
		echo "[cammk] dogrulanmis origin bulunamadi (adaylar hedef basligiyla eslesmedi)."
	fi
}

#ortak nuclei taramasi (domain + origin ayni flaglari paylasir)
nuclei_200(){
	local list="$1" out="$2" jout="$3"; shift 3
	nuclei -l "$list" \
		-t "$SCRIPT_DIR/nuclei_templates/" \
		-severity low,medium,high,critical \
		-ss host-spray -rl "$RATE" -c 10 -bs 10 \
		-retries 2 -timeout 10 -mhe 30 \
		-H "User-Agent: $USER_AGENT" \
		-tlsi -hpd -shp \
		-stats -si 30 \
		-o "$out" -je "$jout" \
		"$@" || true
}

#nuclei ile CWE-200 (sensitive info exposure) taramasi — WAF korumali
#not: template deposu kurulu olmali; ilk kullanimdan once bir kez: nuclei -ut
run_nuclei(){
	if [ ! -s "$OUTPUT_DIR/live_subdomains" ]; then
		echo "[cammk] canli host yok, nuclei taramasi atlaniyor."
		return 0
	fi

	# bu calismanin UA'si
	local ua="$USER_AGENT"

	# WAF on-tespiti: challenge donen host'lari ayir
	waf_classify "$ua"
	# wafw00f: gizli WAF'lari ayikla
	if [ "$SKIP_WAFW00F" != true ]; then
		waf_fingerprint
	else
		echo "[cammk] (atlandi) wafw00f vendor kimligi — SKIP_WAFW00F=true"
	fi
	if [ ! -s "$OUTPUT_DIR/hosts_open" ]; then
		echo "[!] taranabilir 'acik' host yok — hepsi WAF korumali. Muhtemel IP ban veya tam WAF kapsami; nuclei atlaniyor."
		return 0
	fi


	if [ ! -d "$SCRIPT_DIR/nuclei_templates" ] || [ -z "$(ls -A "$SCRIPT_DIR/nuclei_templates" 2>/dev/null)" ]; then
		echo "[cammk] nuclei_templates/ bos veya yok — taranacak custom template yok, nuclei atlaniyor."
		return 0
	fi
	echo "[cammk] nuclei exposure/CWE-200 taramasi baslatiliyor (WAF korumali)..."

	# 1) domain taramasi
	nuclei_200 "$OUTPUT_DIR/hosts_open" \
		"$OUTPUT_DIR/nuclei_exposures.txt" "$OUTPUT_DIR/nuclei_exposures.json"
	if [ -s "$OUTPUT_DIR/nuclei_exposures.txt" ]; then
		echo "[cammk] nuclei (domain) tamamlandi. $(wc -l < "$OUTPUT_DIR/nuclei_exposures.txt") bulgu -> nuclei_exposures.txt."
	else
		echo "[cammk] nuclei (domain) bulgu uretmedi."
		rm -f "$OUTPUT_DIR/nuclei_exposures.txt"
	fi

	# 2) ORIGIN taramasi, origin IP'yi tara.
	if [ "$CF_BYPASS" = true ] && [ -s "$OUTPUT_DIR/origin_ips" ]; then
		local origin_urls="$OUTPUT_DIR/origin_urls"
		sed 's#^#https://#' "$OUTPUT_DIR/origin_ips" | sort -u > "$origin_urls"
		echo "[!] $(wc -l < "$OUTPUT_DIR/origin_ips" | tr -d ' ') origin IP taraniyor (Host/SNI=$TARGET, CDN atlaniyor) — KAPSAM DISI riski (kapatmak: --skip-cf-bypass)."
		nuclei_200 "$origin_urls" \
			"$OUTPUT_DIR/nuclei_origin_exposures.txt" "$OUTPUT_DIR/nuclei_origin_exposures.json" \
			-H "Host: $TARGET" -sni "$TARGET"
		if [ -s "$OUTPUT_DIR/nuclei_origin_exposures.txt" ]; then
			echo "[!] nuclei (origin) $(wc -l < "$OUTPUT_DIR/nuclei_origin_exposures.txt" | tr -d ' ') bulgu -> nuclei_origin_exposures.txt (CDN-bypass yolu)."
		else
			echo "[cammk] nuclei (origin) bulgu uretmedi."
			rm -f "$OUTPUT_DIR/nuclei_origin_exposures.txt"
		fi
	fi

	# tarama sonrasi canary
	waf_canary "$ua"
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
	run_step SKIP_SWAGGER_POSTMAN run_swagger_postman
	run_step SKIP_GITHUB      run_github

	run_step SKIP_BRUTE       run_brute
	run_step SKIP_HTTPX_PROBE run_httpx_probe
	run_step SKIP_API_SECRETS run_api_secrets
	run_step SKIP_RESOLVE     run_resolve
	run_step SKIP_MASSCAN     run_masscan
	run_step SKIP_NAABU       run_naabu
	run_step SKIP_NMAP        run_nmap
	run_step SKIP_WHATWEB     run_whatweb
	run_step SKIP_KATANA      run_katana
	run_step SKIP_KATANA_JS   run_katana_js
	run_step SKIP_FUZZ        run_fuzz
	run_step SKIP_DEDUPE      run_dedupe
	run_step SKIP_ORIGIN      run_origin
	run_step SKIP_NUCLEI      run_nuclei

	echo "[cammk] pipeline tamamlandi."
}



#//"-tags tech"
#//waf detection template
#//latency jitter
#//ua randomize
#//find host ip behind cf
#//bypass cf if possible


main "$@"
