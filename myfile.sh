#!/bin/bash

#-u flag yokken cikis, o pipefail grep no result icin koruma
set -uo pipefail

#domain flag---
if [ -z "${1:-}" ]; then
	echo "Kullanim: $0 <DOMAINADI>"
	exit 1
fi

# dnsx bruteforce wordlist dependency
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="$SCRIPT_DIR/subdomain_wordlist.txt"
if [ ! -f "$WORDLIST" ]; then
	echo "[!] $WORDLIST bulunamadi. Devam etmeden once wordlist dosyanizi script ile ayni klasore 'subdomain_wordlist.txt' adiyla koyunuz."
	exit 1
fi

TARGET=$1
SAFE_TARGET=$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
OUTPUT_DIR="cammk_${SAFE_TARGET}"
mkdir -p "$OUTPUT_DIR"


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
check_deps


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

api_key_setup


############################################
###          PASSIVE RECON               ###
############################################
# hedefe dogrudan istek atmayan adimlar
# subfinder (pasif kaynaklar), gau (wayback/otx/commoncrawl), github/osint.

#subdomain enumeration (passive sources)
echo "[cammk] subfinder baslatiliyor..."
subfinder -d "$TARGET" -pc "$OUTPUT_DIR/keys.yaml" -recursive -o "$OUTPUT_DIR/subfinder_results"
echo "[cammk] subfinder tamamlandi. sonuclar $OUTPUT_DIR/subfinder_results dosyasina kaydedildi."

[ -s "$OUTPUT_DIR/subfinder_results" ] || echo "[!] subfinder sonuc uretmedi, sonraki adimlar bos/eksik olabilir."

#GAU
echo "[cammk] gau baslatiliyor..."
blacklist="css|jpg|jpeg|png|svg|gif|woff|woff2|ttf|eot|ico"
archive="zip|rar|7z|tar|gz|bak|sql|db|txt|env"

cat "$OUTPUT_DIR/subfinder_results" | gau > "$OUTPUT_DIR/gau_raw_results"
[ -s "$OUTPUT_DIR/gau_raw_results" ] || echo "[!] gau sonuc uretmedi."

# grep || true guarding against a no match
grep -ivE "\.($blacklist)($|\?)" "$OUTPUT_DIR/gau_raw_results"  > "$OUTPUT_DIR/gau_withArchive" || true
grep -iE  "\.($archive)($|\?)"   "$OUTPUT_DIR/gau_withArchive" > "$OUTPUT_DIR/gau_archive"     || true
grep -ivE "\.($archive)($|\?)"   "$OUTPUT_DIR/gau_withArchive" > "$OUTPUT_DIR/gau_filtered"    || true

echo "[cammk] gau tamamlandi. arsiv urlleri gau_withArchive, filtreli urller gau_filtered dosyasina kaydedildi."

#API leak sort
echo "[cammk] sonuclar postman ve swagger icin sortlaniyor..."
grep -iE "api|swagger|docs|postman|graphql|wadl" "$OUTPUT_DIR/gau_filtered" > "$OUTPUT_DIR/api_endpoints" || true


#Trufflehog GitHub scan (passive: repo/commit gecmisi)
echo "[cammk] domain ismini iceren github repolari taraniyor..."
echo "$TARGET" | metabigor github -o "$OUTPUT_DIR/github_results"
if [ -s "$OUTPUT_DIR/github_results" ]; then
	echo "[cammk] github repolari bulundu."
	# trufflehog github --repo ...   (placeholder: repo dongusu doldurulacak)
else
	echo "[cammk] domaine bagli github reposu bulunamadi"
	rm -f "$OUTPUT_DIR/github_results"   # FIX: -f, dosya olmayabilir
fi


############################################
###           ACTIVE RECON               ###
############################################
# hedefe dogrudan trafik gidiyor
# httpx probe, response indirme, dnsx->masscan, naabu, nmap vb.

#subdomain bruteforce dnsx
echo "[cammk] dnsx subdomain bruteforce baslatiliyor..."
dnsx -d "$TARGET" -w "$WORDLIST" -silent -o "$OUTPUT_DIR/dnsx_brute_results"
if [ -s "$OUTPUT_DIR/dnsx_brute_results" ]; then
	echo "[cammk] bruteforce ile $(wc -l < "$OUTPUT_DIR/dnsx_brute_results") yeni subdomain adayi bulundu."
else
	echo "[cammk] bruteforce ile yeni subdomain bulunamadi."
fi
cat "$OUTPUT_DIR/subfinder_results" "$OUTPUT_DIR/dnsx_brute_results" 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains_list"

#live subdomain probe httpx-toolkit
echo "[cammk] canli subdomain testi (httpx)..."
#Kaan hocanin portlari
COMMON_HTTP_PORTS="80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"
httpx-toolkit -l "$OUTPUT_DIR/subdomains_list" -ports "$COMMON_HTTP_PORTS" -o "$OUTPUT_DIR/live_subdomains"
[ -s "$OUTPUT_DIR/live_subdomains" ] || echo "[!] canli subdomain bulunamadi."

#API endpoint icerik indirme + trufflehog
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

#dnsx (ACTIVE: DNS cozumleme)
echo "[cammk] ipler resolvelaniyor..."
cat "$OUTPUT_DIR/subdomains_list" | dnsx -a -resp-only > "$OUTPUT_DIR/resolved_ips"
[ -s "$OUTPUT_DIR/resolved_ips" ] || echo "[!] ip resolve edilemedi, masscan/naabu bos donebilir."

#masscan full port scan (tepeye flag eklenecek, belli portlara limitlemek icin)
echo "[cammk] masscan taramasi yapiliyor..."
sudo masscan -iL "$OUTPUT_DIR/resolved_ips" -p1-65535 --rate 1000 -oL "$OUTPUT_DIR/masscan_raw"

#naabu + masscan bos donerse fallback
if [ ! -s "$OUTPUT_DIR/masscan_raw" ]; then
	echo "[cammk] masscan donus yapmadi, naabu fallback deneniyor..."
	sudo naabu -l "$OUTPUT_DIR/resolved_ips" -ss -o "$OUTPUT_DIR/verified_ports"
else
	cat "$OUTPUT_DIR/masscan_raw" | grep "open" | awk '{print $4":"$3}' | sudo naabu -ss -o "$OUTPUT_DIR/verified_ports"
	echo "[cammk] naabu tamamlandi."
fi


if [ -s "$OUTPUT_DIR/verified_ports" ]; then
	cut -d: -f1 "$OUTPUT_DIR/verified_ports" | sort -u > "$OUTPUT_DIR/nmap_hosts"
	ports=$(cut -d: -f2 "$OUTPUT_DIR/verified_ports" | sort -un | paste -sd, -)
	nmap -sV --version-intensity 2 -p "$ports" -iL "$OUTPUT_DIR/nmap_hosts" -oN "$OUTPUT_DIR/nmap_results"

	httpx-toolkit -l "$OUTPUT_DIR/verified_ports" -title -server -status-code -o "$OUTPUT_DIR/httpx_banner_grab"
else
	echo "[cammk] dogrulanmis port yok, nmap/httpx banner adimi atlaniyor."
fi
