# ReconAi

ReconAi adalah tool reconnaissance triage untuk bug bounty & pentest yang fokus ke 1 hal: **membuat recon output langsung “enak dibaca” dan siap ditindak**.  
Ia menggabungkan discovery + subdomain + JS intelligence + API spec detection + scoring severity dalam satu CLI.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/Interface-CLI-informational)](#quick-start)

## Kenapa ReconAi

- Recon itu selalu dibutuhkan, tapi hasilnya sering bikin overwhelmed.
- ReconAi membantu **prioritize**: mana yang high-value (admin surface, docs, graphQL, param rawan, JS leaks) supaya waktu hunting lebih efisien.

## Fitur Utama

- **Attack Surface Probe**: cek path umum (admin, swagger/docs, graphql, OIDC discovery).
- **Subdomain Discovery (best-effort)**: CT + DNS dataset + parsing konten + DNS probing + live probing.
- **JS Intelligence**: extract endpoint, high entropy strings, secrets/tokens pattern, internal indicators.
- **API Spec Intelligence**: deteksi & parse OpenAPI/Swagger (JSON + fallback YAML sederhana) untuk mapping endpoint/parameter/auth scheme.
- **Smart Parameter Ranking**: scoring indikasi **IDOR / SSRF / Open Redirect** dari nama parameter.
- **GraphQL Probe ringan**: deteksi endpoint + indikasi introspection.
- **Severity Scoring + AI Explanation**: setiap temuan diberi skor & penjelasan singkat untuk triage cepat.
- **UX “terlihat jalan”**: ada status loading “Scanning…” dengan tahap-tahap scan.

## Quick Start

### Install

Requirement:
- Python 3.10+

Install dependency:

```bash
pip install rich
```

### Run

Scan target:

```bash
python reconai.py -d target.com
```

Mode scan:

```bash
python reconai.py -d target.com -p full
python reconai.py -d target.com -p deep
python reconai.py -d target.com -p api
python reconai.py -d target.com -p javascript
```

Tuning request:

```bash
python reconai.py -d target.com --timeout 12 --max-js 12 --workers 8
```

## Output (yang akan kamu lihat)

ReconAi bantu menyorot hal-hal seperti:
- Admin panel kemungkinan internal
- Endpoint dengan auth lemah (heuristic)
- GraphQL menarik + probe introspection ringan
- Parameter rawan IDOR / SSRF / Open Redirect (Smart Parameter Ranking)
- JS intelligence: endpoint, high entropy strings, secrets/tokens pattern, internal indicators
- API shadow endpoints (muncul di JS tapi tidak di HTML)
- Subdomain discovery + live probing
- Severity scoring otomatis + AI explanation singkat

## Contoh (Ringkas)

```bash
python reconai.py -d target.com -p full --timeout 12 --max-js 12 --workers 8
```

Yang biasanya jadi “headline”:
- Panel **ReconAI Metrics** (ringkasan)
- Tree **Attack Surface / JS Intelligence / Smart Parameters / GraphQL**
- Section **Subdomains** (terpisah, mudah dilihat)
- **Prioritized Findings** + **AI Explanation**

## Cara Kerja (Ringkas)

- Discovery: fetch HTML, ekstrak link/form/script, crawl ringan, probe path umum
- Subdomain: gabungan OSINT (CT/DNS dataset) + parsing dari konten + DNS probing (DoH) + live probing
- JS intel: download JS & inline script, cari endpoint/secrets/tokens/entropy/internal
- API spec: deteksi & parse OpenAPI/Swagger untuk mapping endpoint/parameter/auth scheme
- Scoring: setiap temuan diberi skor → severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)

## Catatan & Legal

- Tool ini dibuat untuk triage cepat, bukan pengganti manual verification.
- Subdomain discovery bersifat best-effort (tidak mungkin 100% lengkap tanpa sumber internal).
- Gunakan hanya pada target yang kamu punya izin untuk diuji.
