#!/bin/bash

#domain flag---
if [ -z "$1" ]; then
	echo "Kullanim: $0 <DOMAINADI>"
	exit 1
fi

TARGET=$1
OUTPUT_DIR="cammk"
mkdir -p "$OUTPUT_DIR"

#subdomain enumeration
echo "[cammk] subfinder baslatiliyor..." 
subfinder -d "$TARGET" -o "$OUTPUT_DIR/subfinder_results"
echo "[cammk] subfinder tamamlandi. sonuclar $OUTPUT_DIR/subfinder_results dosyasina kaydedildi."

#endpoint scanning
echo "[cammk] gau baslatiliyor..."
cat "$OUTPUT_DIR/subfinder_results" | gau > "$OUTPUT_DIR/gau_results"
echo "[cammk] gau tamamlandi. sonuclar $OUTPUT_DIR/gau_results dosyasina kaydedildi."

#API leak scan
echo "[cammk] sonuclar postman ve swagger icin sortlaniyor..."
cat "$OUTPUT_DIR/gau_results" | grep -iE "api|swagger|docs|postman|graphql|wadl" > "$OUTPUT_DIR/api_endpoints"



#Trufflehog API scan
if [ -s "$OUTPUT_DIR/api_endpoints" ]; then
	echo "[cammk] api endpoint bulundu. sonuclar $OUTPUT_DIR/api_endpoints dosyasına kaydedildi."
	mkdir -p "$OUTPUT_DIR/api_responses"
	echo "[cammk] api endpoint icerikleri indiriliyor..."
	cat "$OUTPUT_DIR/api_endpoints" | httpx-toolkit -silent -rl 5 -t 2 -random-agent -fc 404,403,401 -sr -srd "$OUTPUT_DIR/api_responses" # 2 threads & 5 concurrent connections, random agent
	echo "[cammk] api leaklerde secret aramalari yapilacak. trufflehog baslatiliyor..."
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
cat "$OUTPUT_DIR/subfinder_results" | dnsx -a -resp-only > "$OUTPUT_DIR/resolved_ips"
#masscan
echo "[cammk] masscan taramasi yapiliyor..."
sudo masscan -iL "$OUTPUT_DIR/resolved_ips" -p1-65535 --rate 1000 -oL "$OUTPUT_DIR/masscan_raw"
echo "[cammk] naabu baslatiliyor..."
cat "$OUTPUT_DIR/masscan_raw" | grep "open" | awk '{print $4":"$3}' > "$OUTPUT_DIR/devOnly_sorted_masscan"
cat "$OUTPUT_DIR/masscan_raw" | grep "open" | awk '{print $4":"$3}' | naabu -ss > "$OUTPUT_DIR/verified_ports"
echo "[cammk] naabu tamamlandi."












