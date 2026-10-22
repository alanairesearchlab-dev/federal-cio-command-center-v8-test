# Federal CIO Intelligence Command Center

An independent, open-source intelligence dashboard that collects and visualizes publicly available federal cybersecurity, technology, and policy information.

**This is an independent research project. It is not an official government website, product, or service and is not affiliated with or endorsed by any federal agency.**

## v8.0 Intelligence Workspace

Open [Intelligence Workspace](intelligence.html) from the dashboard for explainable public-source triage, newly observed Federal Register records, downloadable executive briefings, cross-source CVE matches, and browser-local source/headline preferences. The Python workflow builds `data/intelligence.json` from the existing public feeds. No paid AI API, private data, or authentication is used. Automated classifications are heuristic and do not determine official severity, legal applicability, or agency exposure.

## Overview

The Federal CIO Intelligence Command Center provides a centralized interface for exploring publicly available information relevant to federal information technology, cybersecurity, and emerging technology.

Current capabilities include:

- CISA Known Exploited Vulnerabilities (KEV) intelligence.
- Vendor-level vulnerability analysis and filtering.
- Historical vulnerability catalog tracking.
- Federal Register publication monitoring.
- Executive intelligence summaries and downloadable briefings.
- Automated data collection and source freshness reporting.

## Data Sources

The dashboard currently uses:

- **Cybersecurity and Infrastructure Security Agency (CISA):** Public Known Exploited Vulnerabilities catalog.
- **Federal Register:** Public documents API, using broad keyword-based discovery.

Additional authoritative public sources may be incorporated as the project evolves.

## Data Collection and Methodology

Public information is retrieved through scheduled GitHub Actions workflows and stored as structured JSON within the repository.

The collection process supports historical comparisons, identification of newly observed records, and monitoring of source availability.

Automated collection runs daily at approximately 10:23 UTC. Actual execution times may vary due to GitHub scheduling.

For additional information about sources, methodology, and limitations, see the [About & Methodology](about.html) page.

## Interpretation and Limitations

This dashboard is intended for research and informational purposes.

- Vulnerability catalog counts do not represent the number of unpatched systems or provide a comparative measure of vendor security.
- Newly observed records are not necessarily newly discovered vulnerabilities.
- Federal Register keyword matches do not establish regulatory applicability or legal obligations.
- Automated classifications and summaries should be independently verified against authoritative sources.
- Information may be delayed, incomplete, or temporarily unavailable.

The dashboard does not perform system vulnerability assessments or determine organizational compliance.

## Deployment

The project is designed for deployment using GitHub Pages and GitHub Actions.

1. Create a public GitHub repository.
2. Upload the project files, preserving the `.github/workflows/collect.yml` structure.
3. Enable GitHub Pages under **Settings → Pages**, selecting the `main` branch and repository root.
4. Run the **Collect public intelligence** workflow from the Actions tab to initialize the data.
5. Access the published dashboard at `https://USERNAME.github.io/REPOSITORY/`.

If the workflow cannot commit updated data, review repository workflow permissions under **Settings → Actions → General**.

GitHub may delay scheduled jobs or disable inactive workflows.

## Local Preview

Run the following command from the project directory:

`python -m http.server 8000`

Then open `http://localhost:8000/` in your browser.

No additional Python packages are required for the local preview.

## Hosting and Costs

The project is designed to operate using free GitHub services, subject to GitHub's current usage limits and policies.

No custom domain, paid API subscription, or dedicated server is required.

## Public Information Policy

This repository is intended exclusively for publicly available information and supporting application code.

Do not submit confidential information, personal credentials, access tokens, private records, or other nonpublic material.

## Independence Statement

This project is independently developed for public-interest technology research. References to government organizations, publications, or technologies are informational and do not imply affiliation, sponsorship, or endorsement.

## Security advisories and cybersecurity news (v7)

The Cyber Intelligence workspace includes official CISA alerts and advisories, and separate public headlines from BleepingComputer, Krebs on Security, and The Hacker News. The Executive Overview includes an automated keyword-based Priority Watch. Keyword matches are **not** verified severity ratings, recommendations to take systems offline, or assessments of any organization's exposure.

The public collection workflow checks these feeds every four hours, subject to GitHub Actions scheduling delays. If individual sources fail, their last successfully retrieved items are retained and the source status records the error. RSS providers may restrict automated requests or change feed formats; check the Actions log and `data/status.json` when a source fails.

Articles remain on their publishers' websites. The dashboard displays headlines, dates, attribution, and outbound links, not full-text copies.


## v8.1 test release

Includes explainable security triage, policy-topic filtering, time-scoped briefings with printable output, vendor KEV drilldowns, explicit CVE-to-KEV cross-references, and browser-local vendor watchlists. CISA RSS feeds may still return HTTP 403 from GitHub Actions; source health explicitly reports failures. All attention signals are heuristics, not determinations of exposure or legal applicability.


## v8.2 acceptance changes

- Vendor Intelligence now uses a scroll-contained vendor selector and adjacent details, with 7-day, 30-day, and historical filters, product/CVE search, and ten-at-a-time pagination.
- Executive briefing leadership considerations are tailored to security reports, KEV records, and policy documents. The briefing applies a stricter title-based policy exclusion filter.
- The collector can fall back to CISA's official GitHub KEV mirror if the primary CISA KEV endpoint fails. CISA advisory RSS HTTP 403 failures remain visible in source health; no unofficial replacement is claimed.
- Public-source research only. No user identity, organizational assets, or authenticated government resources.
