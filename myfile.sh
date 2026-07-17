#!/bin/bash

#domain flag---
if [ -z "$1" ]; then
	echo "Kullanim: $0 <DOMAINADI>"
	exit 1
fi



TARGET=$1
OUTPUT_DIR="cammk"
mkdir -p "$OUTPUT_DIR"



api_key_setup(){
echo "istenilen api keyleri giriniz."
echo "bos birakilmasi durumunda bu keyin servisi kullanilmayacaktir."

read -p "Shodan API key: " shodan_key
read -p "VirusTotal API key: " vt_key
read -p "GitHub API key:" github_key

local config_file="$OUTPUT_DIR/keys.yaml"
> "$config_file"

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
    echo "api key ayarlama islemi tamamlandi. dosya: $config_file"
}
api_key_setup


#subdomain enumeration
echo "[cammk] subfinder baslatiliyor..." 
subfinder -d "$TARGET" -pc "$OUTPUT_DIR/keys.yaml" -o "$OUTPUT_DIR/subfinder_results"
cat "$OUTPUT_DIR/subfinder_results" | httpx-toolkit -ports 80,443,8080,8443,8000 -o "$OUTPUT_DIR/live_subdomains"
echo "[cammk] subfinder tamamlandi. sonuclar $OUTPUT_DIR/subfinder_results dosyasina kaydedildi. canli domainler $OUTPUT_DIR/live_subdomains dosyasina kaydedildi."

#endpoint scanning
echo "[cammk] gau baslatiliyor..."
blacklist="css|jpg|jpeg|png|svg|gif|woff|woff2|ttf|eot|ico"
archive="zip|rar|7z|tar|gz|bak|sql|db|txt|env"

cat "$OUTPUT_DIR/live_subdomains" | gau > "$OUTPUT_DIR/gau_raw_results"

grep -ivE "\.($blacklist)($|\?)" "$OUTPUT_DIR/gau_raw_results" > "$OUTPUT_DIR/gau_withArchive"
grep -iE "\.($archive)($|\?)" "$OUTPUT_DIR/gau_withArchive" > "$OUTPUT_DIR/gau_archive"
grep -ivE "\.($archive)($|\?)" "$OUTPUT_DIR/gau_withArchive" > "$OUTPUT_DIR/gau_filtered"

echo "[cammk] gau tamamlandi. arsiv urlleri gau_withArchive, filtreli urller gau_filtered dosyasina kaydedildi."

#API leak scan
echo "[cammk] sonuclar postman ve swagger icin sortlaniyor..."
cat "$OUTPUT_DIR/gau_filtered" | grep -iE "api|swagger|docs|postman|graphql|wadl" > "$OUTPUT_DIR/api_endpoints"

#Trufflehog API scan
if [ -s "$OUTPUT_DIR/api_endpoints" ]; then
	echo "[cammk] api endpoint bulundu. sonuclar $OUTPUT_DIR/api_endpoints dosyasına kaydedildi."
	mkdir -p "$OUTPUT_DIR/api_responses"
	echo "[cammk] api endpoint icerikleri indiriliyor..."
	cat "$OUTPUT_DIR/api_endpoints" | httpx-toolkit -silent -rl 5 -t 2 -random-agent -fc 404,403,401 -sr -srd "$OUTPUT_DIR/api_responses" # 2 threads & 5 concurrent connections, random agent
	echo "[cammk] api endpointlerde secret aramalari yapilacak. trufflehog baslatiliyor..."
	trufflehog filesystem "$OUTPUT_DIR/api_responses" --no-update > "$OUTPUT_DIR/thog_api_key"
	
	if [ ! -s "$OUTPUT_DIR/thog_api_key" ]; then
        	rm "$OUTPUT_DIR/thog_api_key"
	fi
	
else
	echo "[cammk] api endpoint bulunamadi."
	rm "$OUTPUT_DIR/api_endpoints"
fi

#Trufflehog GitHub scan
#echo "[cammk] domain ismini iceren github repolari taraniyor..."
#echo "$TARGET" | metabigor github -o "$OUTPUT_DIR/github_results"
#if [ -s "$OUTPUT_DIR/github_results" ]; then
#echo "[cammk] github repolari bulundu. sonuclar $OUTPUT_DIR/github_results dosyasına kaydedildi."
#echo "[cammk] github repolarinda secret aramalari yapilacak. trufflehog baslatiliyor..."
### trufflehog
#else
#echo "[cammk] domaine bagli github reposu bulunamadi"
#rm "$OUTPUT_DIR/github_results"
#fi

###olasi bir trufflehog secret/key hit durumunda
###thog_api_key veya thog_github_key dosyasi olarak


if [ -f "$OUTPUT_DIR/thog_api_key" ]; then
echo "[cammk] key/secret bulundu. $OUTPUT_DIR icerisinde kontrol ediniz."
else
echo "[cammk] herhangi bir key/secret bulunamadi."
fi

#dnsx
echo "[cammk] ipler resolvelaniyor..."
cat "$OUTPUT_DIR/live_subdomains" | dnsx -a -resp-only > "$OUTPUT_DIR/resolved_ips"
#masscan
echo "[cammk] masscan taramasi yapiliyor..."
sudo masscan -iL "$OUTPUT_DIR/resolved_ips" -p1-65535 --rate 1000 -oL "$OUTPUT_DIR/masscan_raw"
echo "[cammk] naabu baslatiliyor..."

cat "$OUTPUT_DIR/masscan_raw" | grep "open" | awk '{print $4":"$3}' > "$OUTPUT_DIR/devOnly_sorted_masscan"

#tum portlar veya sadece genel portlar olarak FLAG
#top 100 http portlar vs.

#naabu
if [ -z masscan_raw ]; then
echo "[masscan] donus yapmadi, naabu fallback deneniyor..."
cat "$OUTPUT_DIR/resolved_ips" | naabu -ss > "$OUTPUT_DIR/verified_ports"
else
cat "$OUTPUT_DIR/masscan_raw" | grep "open" | awk '{print $4":"$3}' | naabu -ss > "$OUTPUT_DIR/verified_ports"
echo "[cammk] naabu tamamlandi."
fi












