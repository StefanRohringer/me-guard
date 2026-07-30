# Demo Skill

A safe example skill for demonstrating Me-Guard.

## Files

- `greet.py` — Simple greeting function (safe code)
- `SKILL.md` — This description

## Test it

```bash
# From the me-guard directory:
python3 scripts/governance.py scan examples/demo-skill/
python3 scripts/governance.py sign examples/demo-skill/ --approve
python3 scripts/governance.py verify examples/demo-skill/
```
