---
Name:   Zlepšenie efektivity honeypot nástroja pomocou zvýšenia úrovne interakcie
Eng:    Improving Honeypot Tool Efficiency by Increasing Interaction Level
Place:  Ústav počítačového inžinierstva a aplikovanej informatiky, FIIT STU
Oblasť: Kombinované bezpečnostné riešenia
---

## Run

On siem vm first:

sudo apt install docker docker-compose curl wget zip unzip git jq
cd openstack-siem-work/elk_dockerized/docker
sudo docker compose up

wait for siem-vm-ip:5601/app/home#/ to be available

then on main vm:

sudo apt install docker docker-compose curl wget zip unzip git jq
cd openstack-work
sudo docker compose up

## Assignment

Honeypot tools in cybersecurity serve to attract attackers and collect data about their behavior. Existing solutions often offer limited simulation capabilities which may deter attackers. Focus on the analysis, conceptualization, implementation and testing of honeypot solutions for web HTTPS services: e-commerce, administration and API. Analyze existing honeypot solutions, fingerprinting possibilities and propose procedures for increasing interaction. Implement a proxy for redirecting suspicious visitors from production to honeypot environment including logging of attacker activity and data visualization. Address efficient initialization of honeypot instances customized for the attacker with data transfer and storage of changes by IP. As part of conceptualization and implementation integrate open-source honeypot solutions and honeytokens. Include findings from scientific publications concerning the application of behavioral analysis for attack detection and consider relevant laws. Appropriately document program parts including deployment procedures. Test the solution on a series of attack scenarios identified based on current trends in web security. Evaluate the effectiveness of the implemented solution by comparing the level of interaction against basic honeypot systems.

## Zadanie

Honeypot nástroje v kybernetickej bezpečnosti slúžia na prilákanie útočníkov a zber dát o ich správaní. Existujúce riešenia často ponúkajú obmedzené možnosti simulácie, ktoré môžu odradiť útočníkov. Zamerajte sa na analýzu, konceptualizáciu, implementáciu a testovanie honeypot riešení pre webové HTTPS služby: e-shop, administráciu a API. Analyzujte existujúce honeypot riešenia, možnosti fingerprintingu a navrhnite postupy pre zvýšenie interakcie. Implementujte proxy pre presmerovanie podozrivých návštevníkov z produkčného na honeypot prostredie vrátane logovania aktivity útočníkov a vizualizácie dát. Riešte efektívnu inicializáciu honeypot inštancie prispôsobenej útočníkovi s prenosom dát a memorizáciou zmien podľa IP. V rámci konceptualizácie a implementácie integrujte open-source honeypot riešenia a honeytokens. Zahrňte poznatky vedeckých publikácií týkajúcich sa aplikácie behaviorálnej analýzy pre detekciu útokov a zohľadnite relevantné zákony. Programové časti vhodne dokumentujte vrátane postupu ich nasadenia. Riešenie testujte na sérii útočných scenárov identifikovaných na základe aktuálnych trendov vo webovej bezpečnosti. Vyhodnoťte efektívnosť implementovaného riešenia porovnaním miery interakcie oproti základným honeypot systémom.

## Primary Literature STN ISO 690 SK

[1] SRINIVASA, Shishir, PEDERSEN, Jens M. a VASILOMANOLAKIS, Emmanouil, 2023. Gotta Catch 'em All: A Multistage Framework for Honeypot Fingerprinting. Digital Threats. Roč. 4, č. 3. DOI: 10.1145/3584976

[2] NINTSIOU, Maria, GRIGORIOU, Elisavet, KARYPIDIS, Paris Alexandros, SAOULIDIS, Theocharis, FOUNTOUKIDIS, Eleftherios a SARIGIANNIDIS, Panagiotis, 2023. Threat intelligence using Digital Twin honeypots in Cybersecurity. In: IEEE International Conference on Cyber Security and Resilience (CSR). s. 530-537. DOI: 10.1109/CSR57506.2023.10224997