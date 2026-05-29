# ReconAi

AI-powered reconnaissance triage tool untuk bug bounty & pentest. Fokus ke output yang cepat dibaca: attack surface, subdomain, endpoint, parameter rawan, JS intel, dan scoring severity otomatis.

## Install

Requirement:
- Python 3.10+
- `rich`

Install dependency:

```bash
pip install rich
```

## Quick Start

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

## Output yang Dicari

ReconAi bantu menyorot hal-hal seperti:
- Admin panel kemungkinan internal
- Endpoint dengan auth lemah (heuristic)
- GraphQL menarik + probe introspection ringan
- Parameter rawan IDOR / SSRF / Open Redirect (Smart Parameter Ranking)
- JS intelligence: extract endpoint, high entropy strings, secrets/tokens pattern, internal indicators
- API shadow endpoints (muncul di JS tapi tidak di HTML)
- Subdomain discovery (best-effort) + live probing
- Severity scoring otomatis + AI explanation singkat

## Cara Kerja (Ringkas)

- Discovery: fetch HTML, ekstrak link/form/script, crawl ringan, probe path umum
- Subdomain: gabungan sumber OSINT (CT/DNS dataset) + DNS probing (DoH) + parsing dari konten
- JS intel: download JS & inline script, cari endpoint/secrets/tokens/entropy/internal
- API spec: deteksi & parse OpenAPI/Swagger (JSON + fallback YAML sederhana)
- Scoring: setiap temuan diberi skor → severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)

## Catatan Penting

- Tool ini dibuat untuk triage cepat, bukan pengganti manual verification.
- Subdomain discovery bersifat best-effort (tidak mungkin 100% lengkap tanpa sumber internal).
- Gunakan hanya pada target yang kamu punya izin untuk diuji.
