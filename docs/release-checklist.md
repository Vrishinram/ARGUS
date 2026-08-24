# ARGUS Release Checklist

Use this checklist for every versioned release (e.g., `v1.0.0`, `v1.1.0`).

## Pre-Release

- [ ] Confirm CI is green on default branch
- [ ] Run tests locally: `python -m pytest -v`
- [ ] Update `/home/runner/work/ARGUS/ARGUS/CHANGELOG.md`
- [ ] Verify README quickstart and badge links
- [ ] Verify demo assets are current

## Tag + Release

- [ ] Create annotated tag (`vX.Y.Z`)
- [ ] Publish GitHub Release with:
  - [ ] release summary
  - [ ] breaking changes (if any)
  - [ ] migration notes (if any)
  - [ ] linked changelog entries
- [ ] Attach release artifacts (if available):
  - [ ] terminal demo asset
  - [ ] architecture visual
  - [ ] packaged binary/container references

## Post-Release

- [ ] Share release link in launch channels (Reddit, HN, article)
- [ ] Update pinned project references and profile README highlights
- [ ] Monitor issues for regressions/false positives
