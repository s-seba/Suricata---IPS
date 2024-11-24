
# Suricata jako IPS - homelab

> Konfiguracja programu Suricata w trybie IPS.  
> Wersja: [suricata-7.0.7](https://suricata.io/download/)

## Spis treści
- [1. Informacje](#1-informacje)
- [2. Przygotowanie](#2-przygotowanie)
  - [2.1 Maszyna wirtualna "omega"](#21-maszyna-wirtualna-omega)
  - [2.2 Maszyna wirtualna "alfa"](#22-maszyna-wirtualna-alfa)
  - [2.3 Przekierowanie portów](#23-przekierowanie-portów)
- [3. Konfiguracja NFQUEUE i Suricaty](#3-konfiguracja-nfqueue-i-suricaty)
  - [3.1 NFQUEUE](#31-nfqueue)
  - [3.2 Suricata](#32-suricata)
- [4. Reguły](#4-reguły)
- [5. Uruchomienie](#5-uruchomienie)
- [6. Weryfikacja](#6-weryfikacja)
- [7. Uwagi](#7-uwagi)

---

## 1. Informacje

Celem projektu jest konfiguracja domowego laboratorium i uruchomienie Suricaty jako IPS. 

W projekcie zostały wykorzystane:
- Oprogramowanie do wirtualizacji VMware.
- Systemy operacyjne Ubuntu Server 24.04.1

Komputer-host dla maszyn wirtualnych pracuje w sieci `192.168.0.1/24`.  
Maszyny wirtualne:
- `omega`
- `alfa`  

Suricata zosatnie zainstalowana na maszynie `omega`, będzie monitorować ruch z `alfa` jak i z `omega`.
rokach.

#### [🔝 Powrót do menu głównego](#spis-treści)
---

## 2. Przygotowanie

W `alfa` i `omega` odszukaj i odkomentowuj linijkę w pliku `/etc/sysctl.conf`:
```bash
net.ipv4.ip_forward=1
```

Dodaj wirtualne interfejsy kart sieciowych:  
- **VMware**: `VM -> Settings -> Hardware -> Add... -> Network Adapter -> Finish`.  
- Ustaw w interfejsach opcje:
  - **Connected**.
  - **Connect at power on**.  
  

> **⚠️ Uwaga:** Nazwy interfejsów mogą być inne na Twojej maszynie. Sprawdź je za pomocą:
> `ip a` 
> i dostosuj je w dalszych k

#### [🔝 Powrót do menu głównego](#spis-treści)
---

### 2.1 Maszyna wirtualna "omega"

#### Połączenie sieciowe interfejsów:
- `ens33: 192.168.0.9/24` - bridge.
- `ens37: 192.168.1.1/24` - host-only.

#### Plik konfiguracyjny `netplan`:
Znajduje się w katalogu `/etc/netplan`. Zamień jego zawartość na:
```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.0.9/24
      nameservers:
        addresses:
          - 1.0.0.1
          - 1.0.0.1
      routes:
        - to: 0.0.0.0/0
          via: 192.168.0.1
    ens37:
      dhcp4: no
      addresses:
        - 192.168.1.1/24
```

Zatwierdź zmiany:
```bash
netplan apply
```

#### Konfiguracja `omega` jako router:
```bash
iptables -t nat -A POSTROUTING -o ens33 -j MASQUERADE
iptables -A FORWARD -i ens33 -o ens37 -j ACCEPT
iptables -A FORWARD -i ens37 -o ens33 -j ACCEPT
```

#### [🔝 Powrót do menu głównego](#spis-treści)
---

### 2.2 Maszyna wirtualna "alfa"

#### Połączenie sieciowe interfejsów:
- `ens33: 192.168.0.178/24` - bridge.
- `ens37: 192.168.1.3/24` - host-only.
- `ens38: 192.168.1.2/24` - host-only.

#### Plik konfiguracyjny interfejsów sieciowych:
Znajduje się w katalogu `/etc/netplan`. Zamień jego zawartość na:
```yaml
network:
  version: 2
  ethernets:
    ens38:
      dhcp4: no
      addresses:
        - 192.168.1.2/24
      routes:
        - to: 0.0.0.0/0
          via: 192.168.1.1
      nameservers:
        addresses:
          - 1.1.1.1
          - 1.0.0.1
    ens33:
      dhcp4: no
      addresses:
        - 192.168.0.178/24
    ens37:
      dhcp4: no
      addresses:
        - 192.168.1.3/24
```

Zatwierdź zmiany:
```bash
netplan apply
```
#### [🔝 Powrót do menu głównego](#spis-treści)
---

### 2.3 Przekierowanie portów

#### Przekierowanie portów na `omega`:
1. **SSH (`port 22` na interfejsie wewnętrznym):**
   ```bash
   iptables -t nat -A PREROUTING -d 192.168.0.9 -p tcp --dport 22 -j DNAT --to-destination 192.168.1.1:22
   ```

2. **SSH (`port 2222` na `alfa`):**
   ```bash
   iptables -t nat -A PREROUTING -d 192.168.0.9 -p tcp --dport 2222 -j DNAT --to-destination 192.168.1.2:22
   ```

3. **HTTP (`port 80` na `alfa`):**
   ```bash
   iptables -t nat -A PREROUTING -d 192.168.0.9 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.2:80
   ```

#### NAT na `omega`:
   ```bash
   iptables -t nat -A POSTROUTING -o ens37 -j MASQUERADE
   ```

#### [🔝 Powrót do menu głównego](#spis-treści)
---

## 3. Konfiguracja NFQUEUE i Suricaty

### 3.1 NFQUEUE
Przekierowanie ruchu do NFQUEUE:
```bash
iptables -I FORWARD -j NFQUEUE
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE
```

---

### 3.2 Suricata 

#### Instalacja:
Odsyłam do dokumentacji Suricaty:  
[Instalacja Suricata](https://docs.suricata.io/en/suricata-7.0.7/quickstart.html)

#### Konfiguracja:
Edytuj plik `/etc/suricata/suricata.yaml`:
```yaml
nfq:
  mode: accept
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  batchcount: 20
  fail-open: yes
runmode: workers
```


#### [🔝 Powrót do menu głównego](#spis-treści)
---

## 4. Reguły

### 4.1 Przykładowe reguły dla Suricaty:
1. **Blokowanie `echo request`:**
   ```bash
   drop icmp any any -> any any (msg:"ICMP PACKET DETECTED: Echo Request"; itype:8; classtype:policy-violation; sid:1; rev:1;)
   ```

2. **Blokowanie DNS dla `example.com`:**
   ```bash
   drop dns any any -> any any (msg:"DNS query detected: example.com"; dns.query; content:"example.com"; nocase; sid:2; rev:1;)
   ```
### 4.2 Dodaj reguły

- zapisz powyższe reguły do pliku `/var/lib/suricata/rules/my.rules`
- w pliku konfiguracyjnym `/etc/suricata/suricata.yaml` odnajdź linijkę:  
`rule-files:` i dodaj plik `my.rules`.

#### [🔝 Powrót do menu głównego](#spis-treści)
---

## 5. Uruchomienie

Sprawdzenie konfiguracji:
```bash
suricata -c /etc/suricata/suricata.yaml -T
```

Uruchomienie w trybie IPS:
```bash
suricata -c /etc/suricata/suricata.yaml -q 0
```

---

## 6. Weryfikacja

Na maszynie `alfa`:
```bash
ping -I ens38 google.com
curl --interface ens38 https://www.example.com
```

Oba połączenia powinny zostać zablokowane.  
Sprawdź logi na `omega`:
```bash
sudo tail -f /var/log/suricata/fast.log
```

#### [🔝 Powrót do menu głównego](#spis-treści)
---

## 7. Uwagi

- Po wprowadzeniu powyższych zmian w iptables  połączenie z siecią bez uruchominej Suricaty w trybie NFQUEUE będzie niemożliwe - ruch sieciowy "ginie" w kolejce NFQUEUE

 - Ulotna konfiguracja iptables. 
Po restarcie systemu wpisy z iptables zostają usunięte. Zachowaj konfigurację poprzez zainstalowanie  
`iptables-persistent`  
lub korzystajac z wbud
owanych narzędzi - zapis reguł do pliku:  
`iptables-save > /etc/iptables/my-rules`  
wczytanie po uruchomieniu:  
`iptables-save < /etc/iptables/my-rules`


