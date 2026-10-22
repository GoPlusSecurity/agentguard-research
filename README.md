# GoPlus Security Research & Intelligence

This repository publishes security intelligence, vulnerability analysis, and defensive self-check skills from GoPlus Security. The materials focus on when a risk applies, which versions are affected or fixed, and how defenders can assess their own environments.

## What you'll find

- **Security intelligence:** Summaries of significant security developments, upstream disclosures, affected systems, and remediation progress.
- **Vulnerability analysis:** Explanations of the underlying issue, conditions for exposure, affected versions, fixes, and the evidence behind each conclusion.
- **Self-check skills:** Steps for inventorying assets, verifying runtime versions, reviewing exposure, and examining existing evidence. Some topics include offline scripts for checking local asset inventories.

## How to use this repository

Each topic lives in its own directory. Vulnerability topics typically include `case.md` for the analysis and `skill/SKILL.md` for the self-check workflow. Supporting references and scripts, when available, are under `skill/references/` and `skill/scripts/`.

Check the document's update date and cited sources, then compare its findings with the versions actually running in your environment, your application configuration, and the relevant exposure paths.

An upstream version number alone may not establish the status of a distribution package, custom build, or vendor product. Offline scripts help organize local inventory and items requiring review; verify remediation against running assets and the relevant vendor advisories.
