20 strán po 4180 znakov na stranu ak bez obrázkov

# Analýza a Testovanie SIEM nástroja

## Abstrakt a Keywords

Zamerali sme sa na analýzu a testovanie systému pre správu bezpečnostných informácií a udalostí (SIEM), konkrétne na ELK Stack t.j. kombináciu Elasticsearch, Logstash a Kibany. Za úlohu sme si dali otestovať nasadenie a výkonnosť tohto systému pri spracovaní simulovaných bezpečnostných logov s využitím vlastného simulačného postupu a skriptu. Postupne sme prešli cez inštaláciu ELK v rámci existujúceho nasadenia SecurityOnion, cez Docker Compose po Google Cloud Compute. Vykonali sme experimentálne testy nad nástrojmi, diskutovali o možnostiach rozšírenia aj limitáciách. Výsledky ukazujú, že správne nakonfigurovaný ELK Stack dokáže efektívne spracovávať logy, ale je citlivý na formát vstupných dát a konfiguráciu filtrov.

Keywords: SIEM analysis, ELK Stack testing, Logstash, JSON log processing, log simulation, performance testing, SecurityOnion deployment, Docker Compose, Google Cloud Compute, experimental testing, configuration sensitivity, filter configuration

## Zadanie

1. Charakterizujte nástroje SIEM, ich komponenty a funkcie.
2. Vyberte vhodný SIEM nástroj (napr. ELK Stack, Splunk, Wazuh alebo iný) pre nasadenie.
3. Nasaďte vybraný nástroj do infraštruktúry (podľa možnosti) alebo implementujte ho v lokálnom prostredí s využitím datasetu so záznamami.
4. Spracujte zachytené dáta a vykonajte ich analýzu.
5. Vytvorte detekčné pravidlá.

## Úvod

### Prečo SIEM?

SIEM je možné nasadiť v rámci siete firmy so záujmom monitorovať väčšinu aktivity alebo konkrétne nasadenie. V prípade mojej diplomovky sa venujem honeypotom, tzv. pastiam na hackerov s cielom sledovať ich aktivitu, a pre dané sledovanie sa mi zíde čiastočne nasadený SIEM. Plnohodnotnejšie SIEM nasadenie má možnosť sledovať výstup z IDS, t.j. aj DNS, HTTP, Inbound, Outbound premávku a vďaka rozšíreniam aj Streaming (napr. cez Packetbeat).

### Súčasný stav SIEM nástrojov

Systémy SIEM sa vyvinuli na základné komponenty modernej kybernetickej bezpečnostnej infraštruktúry. Plnia ústrednú úlohu pri prevencii, detekcii a reakcii na kybernetické hrozby a poskytujú komplexné platformy, ktoré ponúkajú rozsiahlu viditeľnosť do bezpečnostných postojov organizácie. Nedávny vývoj zaznamenal konvergenciu systémov SIEM s nástrojmi na analýzu veľkých dát, čo umožňuje sofistikovanejšie možnosti detekcie hrozieb [1].

### ELK Stack

Open-source riešenie kombinujúce Elasticsearch, Logstash a Kibana, ktoré získalo významné prijatie ako SIEM alternatíva. Hoci ponúka robustné vyhľadávacie funkcie a možnosti vizualizácie, používatelia hlásia problémy s jeho operačnou komplexnosťou - najmä okolo príjmu logov a konfigurácie pipeline [5]. Nákladové úvahy môžu byť významné pri škálovaní, pričom niektoré organizácie hlásia problémy s cenami založenými na RAM, ktoré nakoniec viedli k prechodu na iné riešenia [5]. Platforma je výrazne silná pre debugovanie aplikácií a správu logov, hoci niektorí používatelia kritizujú použiteľnosť rozhrania a zložitosť nástrojov pipeline ako Logstash, ktorý je považovaný za "príliš ťažký" pre nasadenie na úrovni hostiteľa [5]. Pre prostredia s vysokým objemom (TB/deň) sú štruktúrované logovanie a správne ETL procesy kľúčové pre efektívnu prevádzku [2, 5]. Práve ELK Stack riešenie plánujem inštalovať a testovať v rámci projektu BVI, keďže je open source.

### Alternatívne SIEM riešenia

#### Splunk Enterprise

Líder v oblasti SIEM riešení, obzvlášť známy svojimi výkonnými vyhľadávacími a analytickými schopnosťami pri ovládaní expertmi SPL (Splunk Processing Language) [3]. Hoci je drahý pri škálovaní (náklady môžu dosiahnuť 7-ciferné čísla pri 1-100TB+/deň), zostáva "zlatým štandardom" v SIEM technológii s neprekonanými analytickými schopnosťami v porovnaní s alternatívami [5]. Platforma je osobitne cenená pre svoje operácie typu hunt a podnikové funkcie, aj keď mnohé organizácie sú nútené používať riešenia pre smerovanie dát ako Cribl na riadenie nákladov. Hoci existuje bezplatná verzia (obmedzená na 500 MB/deň), podnikové nasadenia typicky vyžadujú významné investície do licencií aj odborných znalostí [3, 5].

- Výhody:
  - Výkonné vyhľadávacie a analytické schopnosti pomocou SPL
  - "Zlatý štandard" v SIEM technológii
  - Vynikajúce podnikové funkcie a operácie typu hunt
- Nevýhody:
  - Vysoké náklady pri škálovaní (7-ciferné sumy pri 1-100TB+/deň)
  - Vyžaduje významné investície do licencií a odborných znalostí
  - Bezplatná verzia je obmedzená na 500 MB/deň


#### IBM QRadar

Podnikové SIEM riešenie získané IBM v roku 2011 (pôvodne vyvinuté Q1 Labs). Hoci je považované za vysoko cenené v podnikovom bezpečnostnom priestore, niektorí kritici ho opisujú ako "vylepšený syslog server s rozhraním pre dotazy" [5]. Platforma sa bežne nachádza spolu so Splunk a ArcSight vo veľkých podnikových prostrediach, najmä tam, kde regulačný súlad vyžaduje centralizovanú správu logov. Hoci ponúka možnosti korelácie udalostí a monitorovania, jeho adopcia sa zdá byť viac riadená podnikovými predajnými vzťahmi než technickou prevahou, pričom pozorovatelia poznamenávajú jeho obmedzené zastúpenie vo veľkých technologických spoločnostiach v porovnaní s alternatívami [5]. K dispozícii je komunitná edícia pre testovanie a malé nasadenia, čo ho robí prístupným spolu s Azure Sentinel pre organizácie skúmajúce SIEM možnosti [1, 5].

- Výhody:
  - Vysoko cenené v podnikovom prostredí
  - Silné možnosti korelácie udalostí a monitorovania
  - Dostupná komunitná edícia pre testovanie
- Nevýhody:
  - Niektorí ho považujú len za "vylepšený syslog server"
  - Adopcia často riadená viac vzťahmi než technickou prevahou
  - Obmedzené zastúpenie vo veľkých tech spoločnostiach
  
#### Wazuh

- Výhody:
  - Open-source riešenie s dôrazom na endpoint ochranu
  - Integrovaný systém detekcie prienikov
  - Dobrá integrácia s ELK Stack
- Nevýhody:
  - Menšia komunita v porovnaní s ELK
  - Obmedzené možnosti vizualizácie
  - Vyžaduje dodatočné nástroje pre komplexnejšiu analýzu

### Porovnanie kľúčových funkcií

- **Výkon & Škálovateľnosť**: Zatiaľ čo Splunk je považovaný za "mainframe SIEM" s vynikajúcimi vyhľadávacími schopnosťami pri škálovaní, náklady môžu explodovať pri dosiahnutí 1TB/deň logov [5]. ELK Stack ponúka dobrú škálovateľnosť, ale čelí výzvam s cenami RAM, ktoré sa môžu stať prohibitívne [5].
- **Nákladová štruktúra**: Tradičné SIEM používajú rôzne cenové modely - Splunk účtuje podľa úložiska, QRadar podľa počtu udalostí, čo vedie mnohé organizácie k hľadaniu hybridných prístupov alebo data pooling riešení [5].
- **Možnosti dotazov**: Každá platforma má svoj vlastný dotazovací jazyk (SPL pre Splunk, EQL pre Elastic), pričom Splunk SPL je považovaný za obzvlášť výkonný pre komplexné scenáre threat huntingu [5].
- **Komplexnosť integrácie**: Všetky riešenia vyžadujú významné úsilie pre integráciu zdrojov logov, pričom používatelia hlásia výzvy pri správe agentov a konfigurácií pipeline naprieč rôznymi platformami [5].

### Trhové trendy a budúci vývoj

SIEM trh prechádza významnou transformáciou:

- Infraštruktúrne spoločnosti (Datadog, Snowflake) sa rozširujú do bezpečnostnej analytiky [5]
- Poskytovatelia cloudu vyvíjajú integrované SIEM možnosti, čím vytvárajú výzvu pre zaužívalých dodávateľov [5]
- Zameranie sa presúva od čistej správy logov ku kombinovaným platformám pre pozorovateľnosť a bezpečnosť [5]
- Vznikajúce riešenia zdôrazňujú optimalizáciu nákladov prostredníctvom oddeleného výpočtu/úložiska a serverless architektúr [5]

### Prečo Docker

- Výhody
  - Možnosť škálovať jednotlivé komponenty
  - Rýchle PoC nasadenie a obnova po zlyhaní
  - Konzistentné prostredie naprieč vývojom
  - Podporná vrstva pre microservices architektúru
  - Flexibilita pri konfigurácii a verziovaní
  - Schopnosť štandardizovať zdroj environment premenných medzi kontajnermi do jedného `.env` súboru
- Nevýhody
  - Komerčná entita
  - Programátori sa príliš spoliehajú na Docker, potenciál pre supply chain útok (mitigovateľný)
  - Dodatočná vrstva, t.j. nebeží priamo na HW = vyžaduje viac systémových zdrojov pre handling
  - Nič nie je perfektné: Problémy s `cache` pri `docker build`, zahltenie systému s `docker images` mitigovateľné cez `docker prune` atp.
  - Nedostupný pre staršie OS, `image` musí byť tiež buildovaný pre danú platformu napr. problém s častou nedostupnosťou images pre `ppc64le` alebo `arm`

### Dôvod výberu ELK stacku

- Výhody
  - Open-source riešenie s rozsiahlou komunitou
  - Robustné vyhľadávacie funkcie a vizualizácie
  - Flexibilita a modularita pri nasadení - nie je určený len pre SIEM
  - Vie byť aj nákladovo efektívny pri správnom nastavení
- Nevýhody
  - Flexibilita a modularita pri nasadení - vie skomplikovať krivku učenia
  - Podstatná konfigurácia je mimo GUI (`.yml` a `.conf` súbory ako napr. `logstash/conf.d/isimbeat.conf`, riešiteľné vlastnou plugin implementáciou)
  - Systémová obsluha je mimo GUI (napr. reštart ELK stacku treba cez `docker` alebo `systemctl` príkazy (podľa typu inštalácie), tiež riešiteľné vlastnou implementáciou)
  - Popularita môže nabádať k (mitigovateľnému) supply chain útoku

Jedno z najväčších negatív ELK stacku, ktoré osobne vnímam je, že pre potreby SIEM konfigurácie filtrov je nutné editovať konfiguračné súbory `logstash/conf.d/isimbeat.conf` namiesto priameho interaktívneho definovania v grafickom rozhraní. Druhé je, že jeho modulárne nasadenie môže dodávať pocit prílišnej obtiažnosti pre nových používateľov napr. postupnosť posieania od zdroja cez `filebeat` na `logstash` na `elasticsearch` až na `kibanu`.

Existuje nadstavba nad ELK stack menom SecurityOnion, ktorá je spravovaná separátnou organizáciou s menšou komunitou. Táto nadstavba sa snaží obohatiť ELK stack tak, aby sa jednalo o kompletné SIEM riešenie out-of-the-box. Momentálne je distribuovaná ako Linux ISO.

- Výhody SecurityOnion voči čistému ELK riešeniu:
  - Ready-made, integrované SIEM služby/rozšírenia, Docker stále zvnútra
  - Predkonfigurované nastavenie na ktorom sa dá stavať
  - Limitácie FREE voči PRO zrovnateľné s ELK ako takým	(t.j. pre SecurityOnion treba PRO pre notifikácie a SLA)
  - SIEM špecif. dokumentácia https://docs.securityonion.net/en/2.4/
- Nevýhody SecurityOnion voči čistému ELK riešeniu:
  - Nedostupný ako Docker images (len do 2021), teraz už len ako Linux ISO alebo Azure/AWS/GoogleCloud Image, t.j. buď manuálne kopírovanie konfigurácie alebo vyššie nároky na HW
  - Viac špecifická t.j. menšia komunita a zodpovedná firma
  - Výrazne viac sys. zdrojov (CPU+RAM) na prevádzku

_img diagram_

### Súlad s ochranou údajov (GDPR)

Nie som právnik, ale...

Bežne platí, že GDPR slúži pre ochranu osobných údajov dotknutých osôb. Ak avšak niekto vykonáva činnosť s úmyslom poškodiť prevádzkovateľa (napr. kompromitácia systému), tak táto činnosť nemá dôvod spadať do rozsahu práv poskytovaných GDPR. Ak dôjde k prieniku, spracovanie možno údajne odôvodniť ako "oprávnený záujem s cieľom ochrany". Organizácie majú právo vyšetrovať bezpečnostné incidenty, kde vraj nie je potrebný súhlas škodlivého používateľa. Treba avšak dokumentovať oprávnenosť, resp. prečo sa organizácia rozhodla konať. V rámci bezpečnostného incidentu možno zaznamenať všetkú škodlivú aktivitu: nahrané súbory, spustené príkazy, upravené údaje, atp.

Potreba anonymizácie teda spadá len na činnosť používateľov, ktorí pristupujú k nášmu systému legitímnym spôsobom. Riadny postoj by som preferoval ujať právnou cestou, resp. kontaktom s právnikom, aby sa predišlo nedorozumeniam.

## Oblasti zamerania, rozsah a ciele projektu

### Zber a agregácia logov

Systém by mal v praxi spracovávať príjem dát z viacerých zdrojov z rôznych sieťových komponentov a bezpečnostných nástrojov, minimálne stačí **virtualizované prostredie v rámci Dockera. Snaha o normalizáciu formátu s cieľom konzistentného spracovania a analýzy rôznych formátov logov.** V praxi existuje aj ďalšia optimalizácia zberu logov, ktorá zabraňuje bottleneckom a zabezpečuje spoľahlivé spracovanie dát, čo je v Docker prostredí vylúčiteľné.

### Schopnosti analýzy v reálnom čase

Rozšírenie projektu by mohlo obsahovať metódy korelácie udalostí s cieľom skúmať pochopenie vzťahov medzi bezpečnostnými udalosťami z rôznych zdrojov, avšak nám stačí **detekcia rôznych typov útokov**. Upozorňovanie treba testovať s cieľom **poskytnúť včasné notifikácie**. Správny chod vyžaduje monitorovanie a následnú optimalizáciu, stačí **poznamenať nedostatky monitorovania**.

### Metódy detekcie hrozieb

Budú implementované **jednoduché mechanizmy detekcie** ako detekcia frekvencie requestov vedúca k DoS, a len ak zostane čas, tak na identifikácií známych signatúr hrozieb a vzorov útokov. V praxi sú tiež implementované schopnosti identifikácie anomálií, ktoré pomáhajú detekovať predtým neznáme hrozby prostredníctvom analýzy správania, to (t.j. behaviorálna analýza) avšak nie je cieľom projektu, podobne nebude povinné ani testovanie efektívnosti korelačných pravidiel. Budú vyvinuté **aspoň základné techniky redukcie falošných pozitív** pre zlepšenie presnosti upozornení, čo by v praxi malo znížiť záťaž na analytikov.

### Súlad a reporting

Sú aj požiadavky na **súlad s ochranou údajov (GDPR)**. Treba vyhodnotiť **možnosti pseudoanonymizácie** na ochranu citlivých údajov pri zachovaní ich využiteľnosti pre analýzu a detekciu hrozieb. Jedná sa skôr o analytickú úlohu. Tvorba audítorských záznamov, ktoré sa bežne vyžadujú napr. v spoločnostiach s väčšími alebo kritickými systémami, nie je vyžadovaná.

### Požiadavky na integráciu

Táto časť nebude v projekte, je uvedená len informačne, keďže je potreba v dostatočne veľkých spoločnostiach. V praxi treba zvážiť možnosti integrácie SIEM infraštruktúry v rámci existujúceho technologického stacku organizácie, t.j. vyhodnotenie autentifikačného systému, LDAP/AD, atp., dostupnosť API. Pre potreby tohto projektu **postačuje Docker**.

## Architektúra prostredia experimentu

Nasadenie bolo skúšané v rámci Dockera lokálne a neskôr aj cez Google Cloud Compute inštancie. Dôvod využitia Google Cloud Compute je nedostatok lokálnych zdrojov a zároveň akcia pre nových používateľov vďaka ktorej je možné VM využiť pre implementáciu tohto zadania zadarmo.

### Virtualizované prostredie v rámci Dockera

Docker inštalovaný v prostredí macOS (Intel) s 8GB RAM.

Prítomné sú 4 časti a jeden Docker Compose súbor. Najprv je vhodné si inštaláciu na nečisto otestovať, teda uvediem príkazy bez `docker compose` a následne uvediem moju inštaláciu s `docker-compose.yml`.

#### Testovacia Docker inštalácia

Na internete sa nachádza návod, ako sprevádzkovať inštaláciu ELK + Suricata cez Docker nad Ubuntu [7].

Postup:

1. Konfigurácia OS networking [Appendix 1]

2. Stiahnutie Docker images [Appendix 2]

3. Spustenie v poradí [Appendix 3]

4. Logstash [Appendix 4]

Pre `logstash` bol v návode uvedený Dockerfile súbor, ktorý sa vybuildoval a až následne sa vlastný image spustil cez `docker run`

5. Suricata [Appendix 5]

Pre testovanie je možné pridať aj inštanciu Suricaty ako IDS. V mojom prípade to nie je súčasť vypracovania, venujem sa jej bližšie pri detekcií hrozieb, avšak nebudem ju pridávať do svojho `docker compose` nižšie.

Autor článku spúšťa jednotlivé služby pod `host` sieťou aby mal prístup k `sniff` NIC, keďže nemá skúsenosť s tvorbou virtuálnych `docker` sietí.

#### Docker Compose

Docker Compose obsahuje definície jednotlivých služieb (E, L, K, SSL) vrátane ich naviazania (pomocou `healthcheck` definícií).

Spoločné prvky:

- Zdieľaná virtuálna sieť (bridge)
- JSON logovanie s rotáciou
- Kontroly dostupnosti (healthchecky)
- Docker Volumes pre E/L/K dáta menežované priamo dockerom, konfigurácia bindovaná zo zložky
- SSL certifikáty pripojené len na čítanie

Jednotlivé časti `docker-compose.yml` inštalácie sú:

1. Základná Elasticsearch konfigurácia: [Appendix 6]

2. Nastavenie kibana_system hesla: [Appendix 7]

3. Základná Kibana konfigurácia: [Appendix 8]

4. Základná LogStash konfigurácia: [Appendix 9]

Nasadenie prebehlo nasledovnými príkazmi: [Appendix 10]

### Google Cloud Compute VM

Keďže žiaden z mojich strojov nemal dostatočnú RAM pre pohodlný beh ELK stacku tak, aby sa dal vykonať stress-test experiment, tak som musel siahnuť po externých dodávateloch. Pokúsil som sa predtým o upgrade RAM, keďže spolubývajúci mal nevyužité 2x8GB RAMky po ruke, len aby som zistil, že môj podarený Thinkpad X260 má len jeden SODIMM slot, uf. Prístup na fakultný OpenStack taktiež nemám, keďže došlo ku komunikačnému šumu. Každopádne internet je bohatý na riešenia...

Google Cloud ponúka momentálne 300USD kredit zadarmo, vďaka ktorému mi vie VM bežať mesiac bez prerušenia (i keď ja ju zastavujem vždy keď ju nepoužívam, takže platím väčšinou len za HDD). Pred začiatkom vypracovania tejto časti zadania som mal plný kredit a k dátumu odovzdania mám vyše 255USD kreditu stále dostupných.

Špecifikácie, ktoré som vybral zahŕňajú 32GB RAM a typ inštancie `e2-highmem-4`.

Inicializácia Google Cloud Compute VM prebehla v nasledovnej postupnosti:

1. Registrácia Google účtu (už bol)
2. Vytvorenie projektu v Google Cloud ("My First Project")
3. Priradenie možnosti použiť Google Cloud Compute API k môjmu projektu (jednorázový súhlas)
4. Výber vhodnej VM resp. image, kontrola cenníka a úprava pre správne rozloženie hardvérových zdrojov
5. Inicializácia
6. Priradenie statickej IP k VM
7. Inštalácia gcloud CLI
8. Kopírovanie gcloud SSH príkazu
9. Pripojenie na VM cez `gcloud compute ssh`
10. Vypnutie/zapnutie VM pomocou `gcloud compute start` a `gcloud compute stop`
11. (Kopírovanie súborov cez `gcloud compute scp`)

Následne bolo možné dokonfigurovať funkčné riešenie ELK stacku priamo vo VM.

_screenshoty obrazoviek_

Pre pripojenie používam nasledovný príkaz, ktorý zároveň umožňuje aj prístup na Kibana GUI vďaka SSH port forwardingu (porty okrem SSH mám v Google Cloud Compute Firwall pravidlách blokované pre prístup z vonka): [Appendix 11]

## Simulácia záťaže Linux prostredia

Možnosti sú nasledovné:

1. Prvý nápad: `cat /dev/zero > /dev/null` funguje pre 100% využitie jedného jadra

2. Druhý nápad: Vhodnejšia je utilita menom `stress`, inštalácia cez `apt install stress` a využitie napr. `./stress --cpu 3`.

3. Tretí (a realizovaný) nápad: Počas samotného testovania sa mi osvojilo sa spoliehať len na rýchlosť (`scale`) môjho simulátora, prišlo mi, že výsledky sú vhodnejšie a zmysluplnejšie ako púšťať `stress`.

Simulácie resp. testy nad nimi sa vykonávali predovšetkým na základe druhej a tretej konfigurácie.

### Prvá ELK konfigurácia pre logy

Základný obsah upravenej fungujúcej konfigurácie je nasledovný:

- Elasticsearch `/etc/elasticsearch/elasticsearch.yml`: [Appendix 12]

- FileBeat `/etc/filebeat/filebeat.yml`: [Appendix 13]

- Kibana `/etc/kibana/kibana.yml`: [Appendix 14]

Pokúsil som sa (neúspešne) aj o nastavenie nových SSL certifikátov. Problém nebol v nefunkčnom certifikáte, ale skôr v CLI jednotlivých ELK komponentov, ktoré odmietalo pracovať pri zapnutom `xpack.security.http.ssl` pre `elasticsearch`. V praxi by bolo nutné nájsť lepšie riešenie, môj návrh je dať ELK za reverzné proxy, ktoré by riešil SSL namiesto samotných ELK komponentov. Každopádne SSL konfiguračný proces bol nasledovný:

[Appendix 15]

Následne bolo potrebné, aby som nastavil heslo pre vstavané účty, keďže pôvodné heslá k nim nie sú v pred-generovanom ELK image dostupné:

[Appendix 16]

Pre prehľad, obsah zložiek je momentálne nasledovný:

[Appendix 17]

#### Spustenie simulácie logov

Najprv som vlastný skript pre simuláciu logov preniesol na danú Google Compute inštanciu:

[Appendix 18]

Následne bol spustený skript, aby `filebeat` dostával vstup, ktorý som overil ako viditeľný na Kibane:

[Appendix 19]

Samotné logy sú pomerne bohaté na parametre, jeden z prvých riadkov obsahuje 48000 znakov. To je za jeden (áno jeden) záznam v logu, z toho najdlhšia hodnota v rámci daného jedného záznamu je okolo 64 znakov, t.j. obsahuje cez 300 unikátnych parametrov. Niektoré riadky sú výrazne kratšie.

#### Prvotné meranie výkonu

Počas simulácie som pozoroval využitie CPU/RAM cez `htop` a trochu sa pozrel na logy samotného ELK nasadenia.

`htop` vykazoval stabilné využitie 17.7GB až 18.2GB RAM z 32GB dostupných. Jadrá CPU boli kolísavé, pravdepodobne kvôli rozdielnej dĺžke jednotlivých riadkov, každopádne ešte nebol zapnutý `logstash` ani `json` parser v ňom, takže `elasticsearch` obdržiaval od `filebeat` len raw hodnoty riadkov bez dodatočného spracovania. Minimálne využitie jadier: Žiadne nebolo pod 30% a väčšinu času bolo minimálne jedno jadro nad 80% miestami nad 90%, avšak každú cca sekundu iné, zvyšné medzi 30%-80%.

Väčšinu CPU zaberal práve `logstash`, ktorý má síce viacero aktívnych procesov, avšak jeden konkrétny zaberal 394% t.j. 4 jadrá. Toto sa dialo aj napriek tomu, že v konfigurácií `filebeat` je nastavený vstup priamo do `elasticsearch` bez `logstash`. Pravdepodobne dochádza k dodatočnému spracovaniu mimo nastavenú konfiguráciu. Samotné prijaté logy v Kibane ukazujú dodatočné identifikačné prvky, ktoré musel priradiť Elasticsearch.

### Druhá ELK konfigurácia pre logy

Neskôr (iný deň) po vypnutí a zapnutí VM pokračujem v zadaní. Tento krát som spravil nasledovné úpravy:

1. Nastavil som `logstash/conf.d/isimbeat.conf` aby okrem prijímania dát z "beats" t.j. `filebeat` a odosielania na `elasticsearch` mal aj filter, konkrétne aby parsoval `json` - cieľom je aby jednotlivé parametre logov boli dostupné ako filtre v Kibane, čo mi neskôr dovolí nastaviť filtre, vlastný dashboard, alerty a notifikácie.
2. Nastavil som `filebeat.yml` aby namiesto portu 9200 pre `elasticsearch` posielal na port 5044 (`beat` pre `logstash`)
3. Opätovne som spustil simuláciu logov identickým postupom (vypnutie VM vyplo pôvodný `tmux` session)

Obsah konfigurákov je teda nasledovný:

- FileBeat `/etc/filebeat/filebeat.yml`: [Appendix 20]

- LogStash `/etc/logstash/conf.d/isimbeat.conf`: [Appendix 21]


Službu `filebeat` bolo potrebné reštartovať, pre istotu som rovno reštartoval aj `logstash`.

Následne bol spustený skript, aby `filebeat` dostával vstup, ktorý som opätovne overil ako viditeľný na Kibane:

[Appendix 22]

Logy avšak prestali prichádzať, z logov `logstash` (logception) som zistil nasledovnú skutočnosť:

`Could not index... [celý obsah riadku logu]... "reason"=>"Limit of total fields [1000] has been exceeded"`

Počas prvého dátového vstupu sa totiž vytvoril index v "Stack Management -> Index Management", kde limit nie je korektne nastavený. Upravil som teda limit pre indexy:

[Appendix 23]

Reštartoval som pre istotu `logstash`.

Následne som si z `logstash` logu všimol formátovací problém s JSON, keďže výstup nebol ukončený (obsahoval čiarky na konci každého riadku a prvý symbol bol `[` avšak bez `]` z posledného riadku celého log súboru).

Po úprave `run.py` tak, aby logoval bez `[]` a bez čiarok na konci riadkov som si všimol, že logstash nemá žiadne chybové hlášky, avšak logy stále nepribúdali v Kibane. Pokúsim sa teda aby výstupný `sim/*.json` z `run.py` vždy mal aj čiarky na konci riadkov (okrem posledného) a aj `[]` ako ohraničenie celého logu:

[Appendix 24]

Teraz keď je JSON korektný má `logstash` stále problém! Nedokáže pracovať nad `null` hodnotami (tvári sa, že vie) aj napriek tomu, že súbor je 100% validný JSON.

[Appendix 25]

Bohužial, ako som pri viacerých pokusoch zistil, problém je, že `filebeat` očakáva jeden riadok logu ako samostatný JSON sám o sebe, t.j. JSON dump s indentom (bez minifikácie) je problém lebo každý riadok je len časť jedného záznamu (jeden parameter s hodnotou). Nápodobne je problém aj minifikácia, lebo všetky riadky sú v jednom. Štandardný `json.dump()` je teda nekompatibilný. Log budem teda zapisovať len ako jeden objekt bez okolitých `[]` a bez čiarok za objektom. Jednotlivé riadky sú teda validný JSON, ale celý `.json` súbor ako taký nie je.

Tento postup zafungoval, avšak tiež som zistil, že štýl `CyberLab cowrie` logov nie je ideálny, pretože všetky majú vonkajšie `session_id` nastavené ako kľúč, t.j. `{"0b74e20e": [{"session_id": "0b74e20e",` čo rozbíja unikátnosť názvov fieldov v Kibane. Upravil som teda svoj simulačný skript nasledovne:

[Appendix 26]

#### Druhé meranie výkonu

Teraz je inštalácia stabilná na 18.8GB RAM s 0-12% využitia jednotlivých jadier, väčšinou okolo 0-1.3% využitia. Vyzerá, že napojenie `filebeat` na `logstash` namiesto `elasticsearch` ako aj upravené spracovanie JSONu pre správny parsing fieldov pomohlo. Skúsim zvýšiť `scale` faktor v mojom simulačnom skripte z predvoleného `1` na `5`, ktorý spôsobí väčšie zahltenie (v priemere 5x rýchlejšie budú pribúdať logy).

`python3 run.py --scale 5`

Teraz vidno, že každých približne 5 sekúnd sa zvýši využitie všetkých jadier zo štandardných 0-3% o 5% na 5-7%, teda dochádza k spracovaniu. Python skript beží celú dobu a jeho zapisovanie prebieha častejšie ako 5 sekúnd. Jedná sa totiž práve o `elasticsearch`, ktorý ukazuje dve inštancie s približne rovnakým zahltením celkového CPU v daných 5 sekundových intervaloch na 36% inak 0.7-1.3% na inštanciu idle.

V 30 sekundových intervaloch Kibana momentálne ukazuje príjem okolo 100 logov (jeden záznam v skutočnosti kvôli úprave so `session_id` je teraz už viac záznamov posielaných naraz). Zrýchlim simuláciu nad identickým súborom (pôjde odznova ten istý súbor).

`python3 run.py --scale 15`

Teraz už cítiť v identických intervaloch (okolo 5sekúnd) nárazovejšie zaťaženie CPU, teda väčšinu času je 0-3%, ale v nárazoch vie byť aj nad 30% každé jadro. Stále sa jedná o mizivé množstvo celkového CPU. Momentálne sú nárazy nevyvážené, predpokladám že sa jedná o trojitý problém:

1. Pod jedným pôvodným záznamom je viacero (1-x) záznamov, viac znamená väčšie nárazové využitie CPU
2. Pod jedným vnútorným záznamom môže byť výrazne viac parametrov ako pod iným, znamená väčší náraz
3. Náhodná hodnota medzi 4-7 môže byť častejšie nižšia, väčší náraz

Je to nepredvídateľnosť vstupu logov, ktorých parametre a časovanie býva z praxe skôr rôzne. Reálny test (experiment) je ale využitie `stress` nástroja tak, aby CPU bolo dlhodobo zahltené inou činnosťou (napr. z praxe aktualizácie, zálohovanie, administrátorská činnosť, rozbitý proces, atp.).

Samotnú simuláciu pre naše potreby ponechám na škále 15, teda 4/15 - 7/15 sekúnd simulátor pridá jeden rozložený (ako som spomínal záznamy z vnútra záznamu) pôvodný záznam. Zatial to znamenalo zahltenie v priemere okolo 350 záznamov na 30 sekúnd.

### Testy funkčnosti

Pred testami zahltenia (experimentom) boli úspešne vykonané nasledovné testy príjmu logov ako takého:

1. Napojenie FileBeat priamo na Elasticsearch (prvá konfigurácia), vypnutý LogStash filter, škála simulácie 1x.

2. Napojenie FileBeat na LogStash (druhá konfigurácia), vypnutý LogStash filter, škála simulácie 1x.

3. Napojenie FileBeat na LogStash, vypnutý LogStash filter, škála simulácie 5x.

4. Napojenie FileBeat na LogStash, vypnutý LogStash filter, škála simulácie 15x.

### Tretia konfigurácia (pridaný filter)

- LogStash `/etc/logstash/conf.d/isimbeat.conf`: [Appendix 27]

## Experiment

Môj experiment, hlavný bod práce, má byť skúmanie dochvilnosti príjmu logov a schopnosť spracovania údajov pri rôznych záťažiach.

### Prvé testy zahltenia (s filtrom)

V Kibane je vidno, že index prijíma logy po skupinách. Odchýlka medzi skupinami logov sú vždy 2 sekundy. Každé 2 sekundy teda pribudnú všetky parsované logy za dané 2 sekundy. V rámci jednej skupiny je ešte milisekundový rozdiel (desiatky max. stovky milisekúnd) v dvoch pod-skupinkách viditeľný len pri sub-sekundovom zoome nad Discover dashboardom.

Výsledná odozva je merateľná na základe logov Elasticsearch, alebo v mojom prípade na základe odpočtu minimálnej a maximálnej odchylky spôsobovanej simulátorom logov (4/scale až 7/scale sekúnd) s pripočítaním prvotnej odozvy (čas prvého záznamu v Kibane - čas spustenia simulátora). Prvotná odchýlka a konečná odchýlka bola meraná pomocou `date ; python3 run.py --scale N ; date` a následnou kontrolou voči času prvého a posledného záznamu v Kibane. Inicializačná odozva skriptu je na úrovni milisekúnd (max. 400ms). FileBeat je nastavený nad zložkou a nie súborom, všetky testy spočívali v prehrávaní len jedného logového súboru, teda nedošlo k vzniku dodatočného súboru, jediný súbor vždy vznikol (odmazanie a začiatok zápisu) pri každom spustení simulátora.

Poradie testov:

1. Napojenie FileBeat na LogStash, zapnutý LogStash (date + geoip + mutate) filter, škála simulácie 15x.

- 9:21:12 začiatok simulácie
- 9:22:53 koniec simulácie

Simulovaných bolo 277 riadkov pôvodného logu.

2. Napojenie FileBeat na LogStash, zapnutý LogStash (date + geoip + mutate) filter, škála simulácie 30x.

- 9:31:06 začiatok simulácie
- 9:34:15 koniec simulácie

Simulovaných bolo 1018 riadkov pôvodného logu.

3. Napojenie FileBeat na LogStash, zapnutý LogStash (date + geoip + mutate) filter, škála simulácie 60x. Zároveň meranie využitia CPU cez `htop`.

- 9:38:21 začiatok simulácie
- 9:42:35 koniec simulácie

Simulovaných bolo okolo 2200 riadkov pôvodného logu.

Využitie CPU simulátora je zanedbateľné (0.6% jedného jadra pri 60x škále simulácie). Najviac CPU využíva `logstash`, t.j. väčšinou viac ako 400%, teda 100% z polovice jadier (celkovo 8 jadier). Toto využite pretrvalo až po manuálny reštart `logstash` o 12 minút po konci poslednej simulácie.

Logy z posledných troch testov nie sú dostupné v Kibane. Logy `logstash` neobsahujú chyby, je evidentné, že príčinou je `filter`. Testy som opakoval s vypnutým filterom (druhá konfigurácia). Problém je riešiteľný manuálnym trial-and-error avšak v prípade nekonzistentných logov na vstupe (nie momentálny prípad, ale čaká ma na diplomovke) vnímam toto správanie ako výrazný problém a budem teda potrebovať separátny pre-processor mimo ELK na všetky logy.

Bolo tiež pozorované, že ak LogStash zostal zaseknutý v spracovávaní, tak po reštarte nebude evidovať do indexu žiadne už prítomné logy ani s novou konfiguráciou, teda výstup z `filebeat` je prakticky vyhodený.

V kombinácií s týmito pozorovaniami a predošlými pri zistení potreby špecificky (nie uplne korektne) formátovať JSON je vidno, že `logstash` je extrémne senzitívny čo sa týka vstupu aj spracovania a nie je pre moje potreby (monitoring pre honeypot diplomový projekt) použiteľný bez separátneho pre-processingu.

Po spomínanom reštarte `logstash` a viac ako polhodinovom oneskorení sú dostupné alerty v Kibane, ale viac ako 90% poslednej tretej simulácie chýba. Tieto testy v mojom ponímaní teda zlyhali.

Kibana o týchto problémoch ako čiste zobrazovacie UI tiež neinformuje, pre istotu by mohlo byť vhodné mať dodatočný monitoring pre `logstash` využitie CPU, ktorý by sa dal vizualizovať v Kibane.

Pri Kibane som pri kontrole timestampov natrafil pri maximálnom sub-sekundovom zoome nad Discover timelineom na bug, kde sa nedá kurzorom highlightnúť posledný stĺpec v rade.

---

### Druhé testy zahltenia (bez filtra)

Poradie testov na základe časov jednotlivých záznamov v Kibana indexe:

1. Napojenie FileBeat na LogStash, žiaden filter, škála simulácie 15x. Zároveň meranie využitia CPU cez `htop`.

Meranie odchýlky:

- 10:23:49 začiatok simulácie
- 10:23:50.597 timestamp prvého kibana alertu
- 10:25:40 koniec simulácie
- 10:25.40.678 timestamp posledných 10 kibana alertov

Simulovaných bolo 304 riadkov pôvodného logu. Nebola vnímaná odozva v `logstash` spracovaní pri kontrole `htop`.

2. Napojenie FileBeat na LogStash, žiaden filter, škála simulácie 30x. Zároveň meranie využitia CPU cez `htop`.

- 10:28:40 začiatok simulácie
- 10:28:50.596 timestamp prvých 17 kibana alertov
- 10:31:49 koniec simulácie
- 10:31:50.781 timestamp posledných 7 kibana alertov

Simulovaných bolo 1019 riadkov pôvodného logu. Taktiež nebola vnímaná odozva v `logstash` spracovaní pri kontrole `htop`.

3. Napojenie FileBeat na LogStash, žiaden filter, škála simulácie 60x. Zároveň meranie využitia CPU cez `htop`.

- 10:36:05 začiatok simulácie
- 10:36:10.597 timestamp prvého kibana alertu
- 10:39:15 koniec simulácie
- 10:39:16.884 timestamp posledných 12 kibana alertov

Simulovaných bolo 2038 riadkov pôvodného logu. Taktiež nebola vnímaná odozva v `logstash` spracovaní pri kontrole `htop`.

Výsledky preukazujú, že `logstash` vie byť responzívny a mať bezproblémový chod v prípade korektnej (špecifickej) konfigurácie a korektného (špecifického) vstupu.

## Dodatočné inštalačné možnosti

Tieto dve možnosti neboli skúšané, keďže existujúce Google Cloud Compute nasadenie je pre moje potreby optimálne:

Komplexné SIEM riešenie, ktoré sa obtiažnejšie nasadzuje z hladiska pluginov, rozšírení, vlastných skriptov, atp. môže byť nápomocné inštalovať pomocou Ansible. Nejednalo by sa o dodatočnú metódu, ale skôr o zaručenie jednotnosti vybranej inštalačnej metódy. Výhodu vidím v prípade viac-násobnej inštalácie, pre potreby zálohovania inštalačného postupu, prípadne pre kroky v inštalácií, ktoré je nutné opakovať napr. pri reinštaláciách. [8]

Okrem nasadenia ELK stacku lokálne alebo pomocou image dostupného pre zaužívaných cloudových providerov ako Google Cloud alebo AWS existuje aj ELK Cloud, na ktorý sa dá registrovať priamo u spoločnosti Elastic. [9]

### Snaha nasadiť SecurityOnion

V rámci vypracovania zadania som si všimol existenciu zadarmo dostupného riešenia SIEM menom SecurityOnion, ktoré nadväzuje na ELK stack, obohacuje konfiguráciu a vytvára nadstavbu s ďalšími aplikovateľnými možnosťami.

Skúšal som nasadiť verziu 2.4.

Má rozsiahlu dokumentáciu k SIEM tématike a podporu istých rozšírení: https://docs.securityonion.net/en/2.4

Ako som postupne zistil, dokumentácia nemá korektné hardvérové špecifikácie:

  - v lokálnej VM import HDD velkosť nestačí, vyhodí chybu min. 99GB
  - na cloude min. velkosť HDD je velkosť marketplace image t.j. momentálne na Google Cloud je to 256GB

Na pozadí využíva `saltstack` pre manažment konfigurácie.

- Postup inštalácie bol nasledovný:
  - securityonion.net odkazuje na github link, konkrétne `DOWNLOAD_AND_VERIFY_ISO.md`
  - zvyšok securityonion github repozitára je dlhodobo neaktualizovaný
  - v danom markdown je odkaz na ISO, ktoré má nestabilný zdroj, treba `sha256sum` verifikáciu
  - ISO má po stiahnutí 13GB, aj napriek tomu prebieha dodatočné sťahovanie z repozitára počas samotnej inštalácie
  - počas inštalácie je curl timeout, resp. rozbitý `sigs.securityonion.net` prístup, opraviteľný cez `Airgap: True`
  - Airgap nie je poriadne rešpektovaný (stále sťahuje z repozitára, tentokrát fungujúceho)

_screenshot_

Samotná inštalácia kvôli problémom so `securityonion.net` serverom nebola po viacerých pokusoch úspešne ukončená, bolo by teda nutné manuálne viac krát upraviť inštalačné skripty. Základnú úpravu som vykonal len pre aplikovanie `airgap` vlastnosti na cloudovej inštalácií ako hotfix (bypass) `sigs.securityonion.net` problému, kde ju nebolo predvolene možné konfigurovať.

### Časy Docker ELK vs SecurityOnion

ELK v Dockeri (lokálna Arch Linux VM s minimálnymi službami)

- install+build time realisticky 5-20min
2GB RAM 2core = 15min
- es01 potom kibana potom logstash
- es01 sa štartuje 1m30s
- kibana 6s a nie je uplne stabilná
- logstash bez konfig. 1s + nestab.
- kibana pokrač. 9min+
- 2GB RAM VM ledva funguje, viac-sekundový lag pre napr. docker container ls -a

SecurityOnion (lokálna VM)

- u mňa VM HW max: 100GB HDD, 2core CPU, 4GB RAM = 20min install pri eduroam 15-20MB/s a 2min startup (nekompletná inštalácia)
(pre porovnanie ELK docker compose up prvý install + build v podobnej VM je 5min)

## Politiky Elastic Fleet

Definícia politík vo Fleet zobrazení funguje na základe Elastic Agentov, t.j. "Agent Policy 1". Politiky obsahujú integrácie.

### Elastic Agent

Má využitie ako separátny vstup pre elasticsearch, ktorý existuje v rámci inej VM alebo hostiteľa. Je možné ho spustiť na rôznych operačných systémoch. Jeho úlohou je získať logy zo separátnych systémov a poslať ich do ELK inštancie.

Pre potreby zadania nie je potrebný, keďže naše riešenie priamo implementuje logovanie aj SIEM v rámci rovnakej VM.

V prípade behu ElasticAgenta na Windows logy nie sú v ideálnom formáte, teda je vhodné nainštalovať Windows službu ako Sysmon64 priamo od Microsoftu. V rámci Kibana obrazovky Fleet je následne možné v grafickom rozhraní pridať integráciu pre Sysmon64.

_screenshot_

Po správnej aplikácií integrácie je možné jednotlivé logy pozorovať v Kibana Discover cez `logs-*`, resp. konkrétne `windows.sysmon_operational`.

## Bližšie SIEM nasadenie v ELK

### Dostupné fields

CyberLab `cowrie` logy, ktoré feedujem do Kibany majú dostupné nasledovné fieldy:

[Appendix 28]

### Notifikácie

Poskytovanie notifikácií cez sledovanie ElasticSearch logov nepokladám za dostatočné, keďže môžu mať odozvu t.j. nemusia byť včasné.

Nápodobne notifikácie, ktoré priamo parsujú logové súbory pred vstupom do `filebeat` nepokladám za správne, keďže by obchádzali celý ELK stack.

Keďže vstavaný notifikačný systém nie je dostupný pre Free Tier ELK stacku, tak najjednoduchšie riešenie, ktoré vnímam je pridať output pod `logstash/conf.d/isimbeat.conf` do ktorého sa budú spracované logy posielať podobne ako sa posielajú do `elasticsearch`. Jedna z možností ako správne zachytiť LogStash výstup je monitorovať sieťové pakety, ktoré sú posielané na nami definovaný port sekundárneho tzv. "sham" elasticsearch. Následne viem vytvoriť Python skript, ktorý dokáže tento formát paketov prijať a spracovať do notifikácií napr. cez e-mail.

[Appendix 29]

### Logovanie

Predvolenú konfiguráciu `filebeat.yml` upravujem tak, aby namiesto priameho napojenia na `elasticsearch` port bola napojená na `logstash` port. Následne v `logstash/conf.d/isimbeat.conf` nastavujem `input` na `beats` port a output na `elasticsearch`. Po reštarte služieb a overení funkčnosti (pozorovanie v Kibane) začínam prácu na pipeline, aby boli `json` logy správne parsované.

Podľa definície `logstash/conf.d/isimbeat.conf` konfigurácie má elasticsearch mať špecifický spôsob menovania indexov, tie sa dá pozrieť v Kibane pod "Stack Management -> Index Management".

Keďže vstupné `CyberLab Dataset` logy sú v JSON formáte, tak stačí nastaviť LogStash tak, aby ich parsoval ako JSON.

### Simulácia útoku 

Na internete existuje viacero logov, ktoré obsahujú podozrivú činnosť, jedným z nich je CyberLab dataset, ktorý obsahuje predovšetkým Cowrie logy. Cowrie je SSH honeypot, teda pretvaruje sa ako legitímna služba SSH a naschvál je otvorená pre útočníkov, aby sa sledovala ich činnosť. Tieto CyberLab logy sa väčšinou datujú okolo roku 2019, avšak myslím, že postačujú pre potreby tohto zadania.

#### Vlastný Log Replay Skript

Keďže logy, ktoré dataset obsahuje sme obdržali kompletné, je potrebné simulovať ich časovanie, teda pribúdanie jednotlivých riadkov tak, aby sme videli ako ELK stack riešenie reaguje na samotnú aktivitu, než celkový súbor logov.

Princíp je prečítať CyberLab log z `./logs`, vytiahnuť z neho nasledovný riadok, počkať istý čas a vložiť riadok do `./sim` výstupu t.j. kopírovanie riadok za riadkom s oneskorením.

Použité knižnice:

[Appendix 30]

Hlavná simulačná funkcia `simulate_logs` kontroluje existenciu zložky do ktorej sa uloží riadok z logov, prípadne ju vytvára. Následne funkcia skúša čítať `.json` za radom, potom vstupný súbor otvára, enumeruje a simuluje časový odstup, na základe ktorého zapisuje. Súčasťou skriptu je aj chybový výstup a simulácia náhodného časového odstupu pre ťažšie čitateľné formáty času. Samotný zápis vyzerá nasledovne:

[Appendix 31]

Nižšie sú uvedené niektoré spomínané časti kódu:

Časť kontroly existencie:

[Appendix 32]

Časť otvorenia súborov:

[Appendix 33]

Skript má celkovo 254 riadkov (pred editáciou kvôli JSON pre-processingu).

### Analýza rôznych formátov logov

V rámci špecifikácie som si zadefinoval, že sa budem snažiť štandardizovať rozličné formáty logov do jednotného. Na tento účel sa bežne využíva práve `logstash/conf.d/isimbeat.conf`, do ktorého sa dajú na vstupe `input` nastaviť rôzne typy logov, ich obsah transformovať pomocou `pipeline` časti a finálny JSON sa posiela na `output` t.j. `elasticsearch` v našom prípade.

Logy ktoré som obdržal nie je potrebné štandardizovať, keďže sa už jedná o JSON formát, každopádne je potrebné spomenúť, že môžu byť aj v tradičnom `.log` formáte napr. typu `TIMESTAMP...[KIND]...ENTRY` alebo pre Docker `CONTAINER |...[KIND]...ENTRY`, kde `...` môže byť medzera alebo tab, prípadne aj dodatočné oddelovače.

Pre jednotlivé typy logov by bolo teda nutné vytvárať separátny `logstash` filter, avšak existujú ML riešenia postavené na GPT-2, ktoré riešia túto problematiku, t.j. snažia sa identifikovať jednotlivé prvky záznamov v `.log` súbore. [6]

Myslím, že riešenie postavené na ML, ktoré na výstupe dodá staticky definovaný filter je ideálne, pretože vie filter vytvoriť bez vstupu skúsenej osoby a neobmedzuje rýchlosť filtrovania. Jediný problém je, že treba už mať záznamy logov, na základe ktorých sa filter vytvorí.

Skúsenosť s nasadením ML môže byť tiež problém, avšak vnímam ho len ako dočasný, keďže v prípade záujmu existuje množstvo snahy v poslednej dobe zjednodušiť prístup k umelej inteligencií a aj ML.

### Dodatky k detekcií hrozieb

V minulosti existoval projekt synesis lite pre integráciu suricaty s ELK stackom, repozitár je archivovaný od 2021 https://github.com/robcowart/synesis_lite_suricata. jeho zameraním boli alerty, flows, http, dns aj štatistika. [10]

V praxi sa zvykne používať aj firewall. suricata vie byť integrovaná priamo do firewallu ako je pfsense.

IDS v praxi funguje tak, že sa posiela do neho kópia internetovej premávky, aby sa predišlo latencií.

Pre suricatu je vhodné mať nastavené dve sieťové karty (jednu ako mirror resp. sniff) a vie byť senzitívna na pamäť, môže dochádzať k buffer problémom v prípade viac ako 4GB RAM.

## Návrhy vylepšení

Prívetivé mi prídu nasledovné možnosti:

- detekcia ďalších útokov
- ďalšie typy logov
- pre-processor pre logstash
- out-of-the-box fungujúca securityonion inštalácia (možno viac šťastia v inom mesiaci)
- viac konfigurovateľný a lepšie nastavený dashboard (taby a dropdowny)
- setup, ktorý vyžaduje menej systémových zdrojov (vyradenie rôznych bináriek, optimalizácia počtu procesov, optimalizácia logov samotných komponentov ELK stacku, ľahšia linux distribúcia, atp.)
- priradenie sniffing network interface (možnosť dostupná v securityonion) a/alebo živých logov z IDS napr. zo Suricaty
- upgrade simulátora o automatizovaný `top` capture do csv súboru pre automatické vyhodnotenie testov
- integrácia už spomínaného Windows sysmon a reálne využitie možností Elastic Fleet

## Literatúra

NITHIKA, K. S. a kol. Analysis, Trends, and Utilization of Security Information and Event Management (SIEM) in Critical Infrastructures. In: 2024 10th International Conference on Advanced Computing and Communication Systems (ICACCS). IEEE, 2024. ISBN 979-8-3503-8436-9.
HONGKAMNERD, W. a kol. Effects of SIEM Recovery Time: Case Study on Security Onion. In: 2024 21st International Conference on Electrical Engineering/Electronics. IEEE, 2024. ISBN 979-8-3503-8155-9.
VAZÃO, A. a kol. SIEM Open Source Solutions: A Comparative Study. In: 14th Iberian Conference on Information Systems and Technologies. IEEE, 2019. ISBN 978-989-98434-9-3.
ELASTIC. ELK Stack Documentation [online]. [cit. 2025-04-28]. Dostupné na: https://www.elastic.co/guide/index.html
Y COMBINATOR. Hacker News Comments and Discussions [online]. [cit. 2025-04-28]. Dostupné na: https://hn.algolia.com
FOMICHEV, A. a kol. GPT-2C: A Parser for Honeypot Logs Using Large Pre-trained Language Models. In: Conference proceedings [online]. ACM, 2021. Dostupné na: https://dl.acm.org/doi/pdf/10.1145/3487351.3492723
GRADIUS. Containerizing my NSM stack — Docker, Suricata and ELK [online]. 31.12.2017 [cit. 2025-04-28]. Dostupné na: https://medium.com/@0xgradius/containerizing-my-nsm-stack-docker-suricata-and-elk-5be84f17c684
I.T SECURITY LABS. Security SIEM Detection Lab Setup Tutorial part 1 - ELK SIEM with ZEEK and Suricata [online video]. YouTube, 2024 [cit. 2025-04-28]. Dostupné na: https://youtu.be/IwlV3wVX4xs
ELASTIC. Elastic Cloud [online]. [cit. 2025-04-28]. Dostupné na: https://www.elastic.co/cloud
I.T SECURITY LABS. How To Setup Suricata Intrusion Detection System - Security SIEM Detection Lab Setup #5 [online video]. YouTube, 2024 [cit. 2025-04-28]. Dostupné na: https://youtu.be/YA2tGrBQ4v0?list=PLyJqGMYm0vnMHLPbmT1-fknzTzR7auBEb


## Dodatky

`run.py`

_screenshoty sem_

Appendix 1:

```bash
ip link set <INTERFACE> multicast off
ip link set <INTERFACE> promisc on
ip link set <INTERFACE> up
tcpdump -i $INTERFACE port 80
```

Appendix 2:

```bash
docker pull ubuntu
docker pull docker.elastic.co/elasticsearch/elasticsearch:6.1.1
docker pull docker.elastic.co/kibana/kibana:6.1.1
docker pull docker.elastic.co/logstash/logstash:6.1.1
```

Appendix 3:

```bash
# Elasticsearch prvy
docker run -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" --hostname=elastic --name=elastic --network=host -t --mount source=elastic,destination=/usr/share/elasticsearch/data docker.elastic.co/elasticsearch/elasticsearch:6.1.1
# Kibana druha
docker run -e ELASTICSEARCH_URL="http://localhost:9200" --hostname=kibana --name=kibana --network=host -p 5601:5601 -t docker.elastic.co/kibana/kibana:6.1.1
```

Appendix 4:

```bash
# Logstash
mkdir logstash
wget https://github.com/gradiuscypher/grIDS/blob/master/docker/logstash/Dockerfile
docker build -t logstash .
docker run --hostname=logstash --name=logstash --network="host" -e "xpack.monitoring.elasticsearch.url=http://localhost:9200" -t logstash
```

Appendix 5:

```bash
# Suricata
mkdir suricata
wget https://github.com/gradiuscypher/grIDS/blob/master/docker/suricata/Dockerfile
docker build -t suricata .
docker run --network=host --hostname=suricata --name=suricata -it suricata
```

Appendix 6:

```bash
image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
container_name: es01
environment:
  - discovery.type=single-node
  - xpack.security.enabled=true
  - xpack.security.http.ssl.enabled=true
  - xpack.security.http.ssl.key=certs/es01/es01.key
  - xpack.security.http.ssl.certificate=certs/es01/es01.crt
  - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
  - xpack.security.transport.ssl.enabled=true
  - xpack.security.transport.ssl.key=certs/es01/es01.key
  - xpack.security.transport.ssl.certificate=certs/es01/es01.crt
  - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
  - xpack.security.transport.ssl.verification_mode=certificate
  - bootstrap.memory_lock=true
  - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
ulimits:
  memlock:
    soft: -1
    hard: -1
volumes:
  - ../elasticsearch/certs:/usr/share/elasticsearch/config/certs:ro
  - es01_data:/usr/share/elasticsearch/data
ports:
  - "${ES_PORT}:${ES_PORT}"
networks:
  - elastic
healthcheck:
  test:
    [
      "CMD-SHELL",
      "curl -s --cacert config/certs/ca/ca.crt https://es01:9200 | grep -q 'missing authentication credentials'"
    ]
  interval: 10s
  timeout: 10s
  retries: 120
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```

Appendix 7:


```bash
image: curlimages/curl:7.85.0  # Use a lightweight image
depends_on:
  es01:
    condition: service_healthy
entrypoint: >
  /bin/sh -c '
    echo "Setting the kibana_system password...";
    until curl --cacert /certs/ca/ca.crt -X POST -u elastic:${ELASTIC_PASSWORD} -H "Content-Type: application/json" \
      "https://es01:9200/_security/user/kibana_system/_password" -d "{\"password\":\"${KIBANA_PASSWORD}\"}";
      do echo "Waiting for Elasticsearch to be ready...";
      sleep 5;
    done

    # If the loop exits, curl succeeded
    echo "Password set successfully for kibana_system.";
    exit 0;
  '
volumes:
  - ../elasticsearch/certs/ca:/certs/ca:ro
networks:
  - elastic
restart: "no"
```

Appendix 8:


```bash
image: docker.elastic.co/kibana/kibana:${STACK_VERSION}
container_name: kibana
environment:
  - SERVER_SSL_ENABLED=true
  - SERVER_SSL_KEY=config/certs/kibana/kibana.key
  - SERVER_SSL_CERTIFICATE=config/certs/kibana/kibana.crt
  - SERVERNAME=kibana
  - ELASTICSEARCH_HOSTS=https://es01:9200
  - ELASTICSEARCH_USERNAME=kibana_system
  - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
  - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
ports:
  - "${KIBANA_PORT}:${KIBANA_PORT}"
healthcheck:
  test:
    [
      "CMD-SHELL",
      "curl -I --cacert config/certs/ca/ca.crt  https://kibana:5601 | grep -E \"HTTP/1\\.1 (200 OK|302 Found)\""
    ]
  interval: 10s
  timeout: 10s
  retries: 1200
depends_on:
  es01:
    condition: service_healthy
  init-password:
    condition: service_completed_successfully
volumes:
  - ../kibana/certs:/usr/share/kibana/config/certs:ro
  - kibana_data:/usr/share/kibana/data
networks:
  - elastic
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```

Appendix 9:


```bash
image: docker.elastic.co/logstash/logstash:${STACK_VERSION}
container_name: logstash
environment:
  - ELASTIC_USERNAME=${ELASTIC_USERNAME}
  - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
  - ELASTIC_HOSTS=https://es01:9200
ports:
  - "${LOGSTASH_PORT}:${LOGSTASH_PORT}"
healthcheck:
  test: [
    "CMD", 
    "curl -I -f --cacert config/certs/ca/ca.crt https://logstash:9600/_node/stats"] #TODO xpack/security is not turned on
  interval: 30s
  timeout: 10s
  retries: 5
depends_on:
  es01:
    condition: service_healthy
  kibana:
    condition: service_healthy
volumes:
  - ../logstash/certs:/usr/share/logstash/certs:ro
  - ../logstash/logstash.yml:/usr/share/logstash/config/logstash.yml:ro 
  - ../logstash/pipeline.conf:/usr/share/logstash/pipeline/logstash.conf:ro
  - ../logstash/geoip/dbs/:/geoip
  - logstash_data:/usr/share/logstash/data
networks:
  - elastic
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```

Appendix 10:

```bash
git clone (privátne repo)
cd certs/root-ca
chmod +x gen_elk_certs.sh
./gen_elk_certs.sh
cd ../..
cd docker
vi .env
docker compose up (-d)
```

Appendix 11:

```bash
gcloud compute ssh --zone "us-central1-c" "elk-2-vm" --project "fluent-opus-458215-u1" --ssh-flag="-L 5601:localhost:5601"

# stop instance when not used to reduce costs
gcloud compute instances stop --zone "us-central1-c" "elk-2-vm" --project "fluent-opus-458215-u1"

# start instance before ssh
gcloud compute instances start --zone "us-central1-c" "elk-2-vm" --project "fluent-opus-458215-u1"
```

Appendix 12:

```bash
cat <<EOF | sudo tee /etc/elasticsearch/elasticsearch.yml
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl:
  enabled: false
  keystore.path: certs/http.p12
xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12
cluster.initial_master_nodes: ["elk-stack-debian12"]
http.host: 0.0.0.0
EOF
```

Appendix 13:


```bash
cat <<EOF | sudo tee /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: filestream
  id: my-filestream-id
  enabled: true
  paths:
    - /home/fiit-bvi/isimlog/sim/*.json
    #- /var/log/*.log
    
filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

setup.kibana:

output.elasticsearch:
  hosts: ["localhost:9200"]
  preset: balanced

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
EOF
```

Appendix 14:

```bash
cat <<EOF | sudo tee /etc/kibana/kibana.yml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana/kibana.log
      layout:
        type: json
  root:
    appenders:
      - default
      - file
pid.file: /run/kibana/kibana.pid
EOF
```

Appendix 15:


```bash
# regenerate certs for elasticsearch with custom internal ip and hostname
/usr/share/elasticsearch/bin/elasticsearch-certutil http
n
n
n
passwordgoeshere

y
elk

10.128.0.5
34.55.143.29
localhost

10.128.0.5
34.55.143.29

# copy over newly generated certs
apt install unzip
unzip /usr/share/elasticsearch/elasticsearch-ssl-http.zip
sudo mkdir -p /etc/elasticsearch/certs/elasticsearch
sudo cp elasticsearch/http.p12 /etc/elasticsearch/certs/elasticsearch/
sudo cp kibana/elasticsearch-ca.pem /etc/elasticsearch/certs/elasticsearch/

# set correct permissions 
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
sudo chmod 660 /etc/elasticsearch/certs/elasticsearch/http.p12
sudo chmod 660 /etc/elasticsearch/certs/elasticsearch/elasticsearch-ca.pem
```

Appendix 16:


```bash
# less /var/log/elasticsearch/elasticsearch.log
  ...
  Auto-configuration will not generate a password for the elastic built-in superuser, as we cannot  determine if there is a terminal attached to the elasticsearch process. You can use the `bin/elasticsearch-reset-password` tool to set the password for the elastic user.
  ...
# less /var/log/kibana/kibana.log

# make sure to disable xpack.security.http.ssl before running
/usr/share/elasticsearch/bin/elasticsearch-reset-password --auto -u kibana_system

# for me: gqNoqO4M9gb8zIZD0fg0

/usr/share/elasticsearch/bin/elasticsearch-reset-password --auto -u elastic

# for me: +a1VgisxbsUN*R0Y-+b5

# click through website then for verification code run
# /usr/share/kibana/bin/kibana-verification-code
# /usr/share/kibana/bin/kibana-keystore add elasticsearch.password # add new password for kibana_system from above - seems that this is not getting anywhere

# port forward kibana to localhost for access was already done, but now is relevant
gcloud compute ssh --zone "us-central1-c" "elk-2-vm" --project "fluent-opus-458215-u1" --ssh-flag="-L 5601:localhost:5601"
```

Appendix 17:

```bash
# kibana config files
find /etc/kibana -type f
node.options
kibana.yml
kibana.keystore

# logstash config files
find /etc/logstash -type f
startup.options
logstash-sample.conf
jvm.options
logstash.yml
log4j2.properties
pipelines.yml

# elasticsearch config files
find /etc/elasticsearch -type f
users_roles
elasticsearch.yml
users
jvm.options
log4j2.properties
roles.yml
elasticsearch-plugins.example.yml
elasticsearch.keystore
role_mapping.yml
certs/http_ca.crt
certs/http.p12
certs/elasticsearch/http.p12
certs/elasticsearch/http-elk-1.key
certs/elasticsearch/http-elk-1.csr
certs/elasticsearch/elasticsearch-ca.pem
certs/transport.p12

# filebeat config files
find /etc/filebeat -type f
/etc/filebeat/modules.d/*.yml.disabled
/etc/filebeat/filebeat.reference.yml
/etc/filebeat/filebeat.yml
/etc/filebeat/fields.yml
```

Appendix 18:

```bash
# transfer zip
gcloud compute scp --recurse --zone "us-central1-c" isimlog.zip fiit-bvi@elk-2-vm:~/ --project "fluent-opus-458215-u1"

# extract logs into folder isimlog
sudo apt install unzip tmux
sudo unzip isimlog.zip -d isimlog
sudo chown -R root:root isimlog
sudo chmod -R a+r isimlog
sudo find isimlog -type d -exec chmod a+x {} \;
```

Appendix 19:

```bash
tmux
cd isimlog
python3 run.py
^b d #detach from tmux
```

Appendix 20:


```bash
cat <<EOF | sudo tee /etc/filebeat/filebeat.yml
filebeat.inputs:
- type: filestream
  id: my-filestream-id
  enabled: true
  paths:
    - /home/fiit-bvi/isimlog/sim/*.json
  json.overwrite_keys: true
  json.keys_under_root: true
  fields_under_root: true

filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1

setup.kibana:

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
EOF
```

Appendix 21:

```c
cat <<EOF | sudo tee /etc/logstash/conf.d/isimbeat.conf
input {
    beats {
        port => 5044
        codec => "json"
    }
}

output {
    elasticsearch {
        hosts => ["localhost:9200"]
        index => "isimlog-%{+YYYY.MM}"
        document_type => "cowrie"
    }
}
EOF
```

Appendix 22:

```bash
tmux
cd isimlog
python3 run.py
^b d #detach from tmux
```

Appendix 23:

```bash
# reset field limit
curl -X PUT "localhost:9200/cowrie-*/_settings" -H 'Content-Type: application/json' -d'
{
  "index.mapping.total_fields.limit": 5000
}'
# response
{"acknowledged":true}
```

Appendix 24:

```py
line_data = []
for line_num, line in enumerate(infile, 1):
  try:
    # Parse JSON object 
    line = line.strip()
    if line.startswith('['):
      line = line[1:]
    if line.endswith(','):
      line = line[:-1]
    if line.endswith(']'):
      line = line[:-1]
    data = json.loads(line)
    
    print(f"Simulating timestamp at line {line_num}. Using random timing.", file=sys.stderr)
    wait_seconds = random.uniform(4, 7) / scale_factor
    time.sleep(wait_seconds)
    total_wait_time += wait_seconds
    
    # Append the line data
    line_data.append(data)
    
    # Write all line data as a json array using single write
    # Seek to beginning of the file and overwrite all data
    outfile.seek(0)
    outfile.write(json.dumps(line_data, indent=2))
    outfile.truncate()
    continue
```

Appendix 25:

```log
# logstash log
.filters.json    ][main][f863430cebe210714abe5dd501d2912142f74c3e4ab18149439c42e7e6598cba] Error parsing json {:source=>"message", :raw=>"        \"shasum\": null,", :exception=>#<LogStash::Json::ParserError: Unexpected character (':' (code 58)): expected a valid value (JSON String, Number, Array, Object or token 'null', 'true' or 'false')
```

Appendix 26:

```py
try:
  # Parse JSON object 
  line = line.strip()
  if line.startswith('['):
    line = line[1:]
  if line.endswith(','):
    line = line[:-1]
  if line.endswith(']'):
    line = line[:-1]
  data = json.loads(line)

  print(f"Simulating timestamp at line {line_num}. Using random timing.", file=sys.stderr)
  wait_seconds = random.uniform(4, 7) / scale_factor
  time.sleep(wait_seconds)
  total_wait_time += wait_seconds
  
  # dump entire log entry (including outer session_id enclosure, not efficient for ELK index and bad with filters)
  # outfile.write(json.dumps(data) + '\n')

  # dump without outer session_id enclosure
  data = data[list(data.keys())[0]]
  for entry in data:
      outfile.write(json.dumps(entry) + '\n')
  lines_in_file += len(data)
  total_lines_processed += len(data)
  continue
```

Appendix 27:

```c
cat <<EOF | sudo tee /etc/logstash/conf.d/isimbeat.conf
input {
    beats {
        port => 5044
        codec => "json"
    }
}

filter {
    date {
        match => ["timestamp", "ISO8601"] 
        target => "@timestamp"
        tag_on_failure => ["_dateparsefailure"]
    }

    geoip {
        source => "src_ip"
        target => "geoip"
        add_field => {
            "[geoip][coordinates]" => "%{[geoip][longitude]}"
            "[geoip][coordinates]" => "%{[geoip][latitude]}"
        }
        tag_on_failure => ["_geoipfailure"] 
    }

    mutate {
        add_field => {
            "event_type" => "honeypot_log"
            "log_source" => "cowrie"
        }
        remove_field => ["@version"]
        tag_on_failure => ["_mutatefailure"]
    }
}

output {
    elasticsearch {
        hosts => ["localhost:9200"]
        index => "isimlog-%{+YYYY.MM}"
        document_type => "cowrie"
    }
}
EOF
```

Appendix 28:

```
@timestamp
@version
agent.ephemeral_id
agent.id
agent.name
agent.type
agent.version
cloud.account.id
cloud.availability_zone
cloud.instance.id
cloud.instance.name
cloud.machine.type
cloud.project.id
cloud.provider
cloud.region
cloud.service.name
compCS
data
dst_host_identifier
duration
ecs.version
encCS
event.original
eventid
fingerprint
geolocation_data.city_name
geolocation_data.continent_code
geolocation_data.country_code2
geolocation_data.country_code3
geolocation_data.country_name
geolocation_data.dma_code
geolocation_data.ip
geolocation_data.latitude
geolocation_data.location.lat
geolocation_data.location.lon
geolocation_data.longitude
geolocation_data.postal_code
geolocation_data.region_code
geolocation_data.region_name
geolocation_data.timezone
host.architecture
host.containerized
host.hostname
host.id
host.ip
host.mac
host.name
host.os.codename
host.os.family
host.os.kernel
host.os.name
host.os.platform
host.os.type
host.os.version
input.type
kexAlgs
keyAlgs
log.file.device_id
log.file.inode
log.file.path
log.offset
macCS
message
outfile
password
sensor
session_id
shasum
size
src_ip_identifier
src_port
ssh_client_version
tags
timestamp
ttylog
url
username
```

Appendix 29:

```c
output {
  if "shouldmail" in [tags] {
    email {
      to => 'technical@example.com'
      from => 'monitor@example.com'
      subject => 'Alert - %{title}'
      body => "Tags: %{tags}\\n\\Content:\\n%{message}"
      template_file => "/tmp/email_template.mustache"
      domain => 'mail.example.com'
      port => 25
    }
  }
}
```

Appendix 30:

```py
import os
import re
import time
import datetime
import argparse
import shutil
import sys
import json
import random
```

Appendix 31:

```py
json.dump({session_id: [event_slim]}, outfile)
outfile.write('\n')
```

Appendix 32:

```py
try:
  if os.path.exists(dest_dir):
    print(f"Destination directory '{dest_dir}' exists. Cleaning it up...")
    # Ensure it's safe to remove (e.g., not '/') although basic check included
    if dest_dir and dest_dir != '/':
      # Check if it's a directory before removing tree
      if os.path.isdir(dest_dir):
        shutil.rmtree(dest_dir)
        elif os.path.isfile(dest_dir):
        os.remove(dest_dir) # Remove if it's a file
```

Appendix 33:

```py
try:
  with open(source_path, 'rt', encoding='utf-8') as infile:
    with open(dest_path, 'wt', encoding='utf-8') as outfile:
      for line_num, line in enumerate(infile, 1):
        try:
          # Parse JSON object
          line = line.strip()
          if line.startswith('['):
            line = line[1:]
          if line.endswith(','):
            line = line[:-1]
          if line.endswith(']'):
            line = line[:-1]
          data = json.loads(line)
```

Custom Log Simulation Script (run.py):

```python
import os
import re
import time
import datetime
import argparse
import shutil
import sys
import json
import random

# Function to parse timestamp (handles ISO 8601 format with optional 'Z')
def parse_timestamp(ts_str):
    """
    Parses an ISO 8601 timestamp string into a timezone-aware datetime object.
    Handles the trailing 'Z' for UTC.
    """
    try:
        # Remove trailing 'Z' if present and add explicit UTC timezone info
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        # Use fromisoformat for robust parsing
        dt = datetime.datetime.fromisoformat(ts_str)
        # Ensure timezone is set (should be by fromisoformat with +00:00)
        if dt.tzinfo is None:
             # Fallback if timezone somehow wasn't parsed, assume UTC
             dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except ValueError:
        print(f"Error: Could not parse timestamp string: '{ts_str}'", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected error parsing timestamp '{ts_str}': {e}", file=sys.stderr)
        return None

# Main function to simulate log generation
def simulate_logs(source_dir, dest_dir, scale_factor):
    """
    Reads log files from source_dir, simulates timing based on timestamps,
    and writes logs to dest_dir with scaled timing.
    """
    # --- 1. Prepare Destination Directory ---
    try:
        if os.path.exists(dest_dir):
            print(f"Destination directory '{dest_dir}' exists. Cleaning it up...")
            # Ensure it's safe to remove (e.g., not '/') although basic check included
            if dest_dir and dest_dir != '/':
                # Check if it's a directory before removing tree
                if os.path.isdir(dest_dir):
                     shutil.rmtree(dest_dir)
                elif os.path.isfile(dest_dir):
                     os.remove(dest_dir) # Remove if it's a file
                else:
                     print(f"Warning: '{dest_dir}' exists but is neither a file nor a directory. Attempting removal.", file=sys.stderr)
                     # Attempt removal, might fail for special file types
                     try:
                         os.remove(dest_dir)
                     except OSError:
                          try:
                              os.rmdir(dest_dir) # Try removing as empty dir
                          except OSError as e:
                              print(f"Error: Could not remove existing '{dest_dir}': {e}", file=sys.stderr)
                              sys.exit(1)

            else:
                 print(f"Error: Invalid destination directory specified: '{dest_dir}'", file=sys.stderr)
                 sys.exit(1)

        print(f"Creating destination directory: {dest_dir}")
        os.makedirs(dest_dir, exist_ok=True) # exist_ok=True in case rmtree had issues but dir is usable

    except PermissionError:
        print(f"Error: Permission denied when trying to access or modify '{dest_dir}'. Please check permissions.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error preparing destination directory '{dest_dir}': {e}", file=sys.stderr)
        sys.exit(1)

    # --- 2. Find and Sort Source Files ---
    try:
        all_files = [f for f in os.listdir(source_dir)
                     if f.startswith('cyberlab_') and f.endswith('.json') and os.path.isfile(os.path.join(source_dir, f))]
        # Sort files chronologically based on the date in the filename
        all_files.sort()
    except FileNotFoundError:
        print(f"Error: Source directory not found: '{source_dir}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error listing or sorting files in source directory '{source_dir}': {e}", file=sys.stderr)
        sys.exit(1)

    if not all_files:
        print(f"No log files matching 'cyberlab_*.json' found in '{source_dir}'. Exiting.")
        return

    print(f"Found {len(all_files)} log files to process.")

    # --- 3. Simulation Loop ---
    global_first_entry = True
    last_timestamp_dt = None
    total_lines_processed = 0
    total_wait_time = 0
    start_sim_time = time.monotonic()

    for filename in all_files:
        source_path = os.path.join(source_dir, filename)
        dest_path = os.path.join(dest_dir, filename)
        print(f"\nProcessing '{filename}' -> '{dest_path}'...")

        lines_in_file = 0
        file_start_time = time.monotonic()

        try:
            with open(source_path, 'rt', encoding='utf-8') as infile:
                with open(dest_path, 'wt', encoding='utf-8') as outfile:
                    for line_num, line in enumerate(infile, 1):
                        try:
                            # Parse JSON object 
                            line = line.strip()
                            if line.startswith('['):
                                line = line[1:]
                            if line.endswith(','):
                                line = line[:-1]
                            if line.endswith(']'):
                                line = line[:-1]
                            data = json.loads(line)
                    
                            print(f"Simulating timestamp at line {line_num}. Using random timing.", file=sys.stderr)
                            wait_seconds = random.uniform(4, 7) / scale_factor
                            time.sleep(wait_seconds)
                            total_wait_time += wait_seconds
                    
                            # dump entire log entry (including outer session_id enclosure, not efficient for ELK index and bad with filters)
                            # outfile.write(json.dumps(data) + '\n')

                            # dump without outer session_id enclosure
                            data = data[list(data.keys())[0]]
                            for entry in data:
                                outfile.write(json.dumps(entry) + '\n')
                            lines_in_file += len(data)
                            total_lines_processed += len(data)
                            continue

                        except json.JSONDecodeError:
                            print(f"Warning: Invalid JSON at line {line_num} of {filename}. Using random timing.", file=sys.stderr)
                            wait_seconds = random.uniform(4, 7) / scale_factor
                            time.sleep(wait_seconds)
                            total_wait_time += wait_seconds
                            outfile.write(line)
                            continue

        except Exception as e:
            print(f"An error occurred processing '{filename}': {e}", file=sys.stderr)

        file_end_time = time.monotonic()
        file_duration = file_end_time - file_start_time
        print(f"Finished processing '{filename}' ({lines_in_file} lines). File processing time: {file_duration:.2f}s")

    # --- 4. Simulation Summary ---
    end_sim_time = time.monotonic()
    total_duration = end_sim_time - start_sim_time
    print("\n--------------------")
    print("Simulation finished.")
    print(f"Total log files processed: {len(all_files)}")
    print(f"Total log entries processed: {total_lines_processed}")
    print(f"Total simulated wait time (sleep calls): {total_wait_time:.2f} seconds")
    print(f"Total real time elapsed for simulation: {total_duration:.2f} seconds")
    if scale_factor != 1.0:
        print(f"Time scaling factor used: {scale_factor} ({'faster' if scale_factor > 1 else 'slower'} than original)")
    print("--------------------")

# --- Argument Parsing and Script Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simulate log generation from gzipped JSON files with adjustable timing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help
    )
    parser.add_argument(
        "--source",
        default="./logs",
        help="Directory containing the source log files (e.g., cyberlab_YYYY-MM-DD.json)."
    )
    parser.add_argument(
        "--dest",
        default="./sim", 
        help="Directory where simulated logs will be written (will be cleaned before start)."
    )
    parser.add_argument(
        "--scale",
        type=float,
        default=1.0,
        help="Time scaling factor for simulation speed. >1.0 speeds up, <1.0 slows down, 1.0 is real-time based on timestamps."
    )

    args = parser.parse_args()

    # Validate scale factor
    if args.scale <= 0:
        print("Error: Scaling factor must be a positive number.", file=sys.stderr)
        sys.exit(1)

    print("Starting log simulation...")
    print(f"  Source Dir: {os.path.abspath(args.source)}")
    print(f"  Dest Dir  : {os.path.abspath(args.dest)}")
    print(f"  Scale Factor: {args.scale}")
    print("--------------------")

    # Run the simulation
    try:
        simulate_logs(args.source, args.dest, args.scale)
    except KeyboardInterrupt:
        print("\nSimulation interrupted by user. Exiting.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected critical error occurred during simulation: {e}", file=sys.stderr)
        sys.exit(1)

    print("Simulation script completed.")
```