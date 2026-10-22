# Upgrade & Rollback Procedures

This document provides operational instructions for upgrading the JARVIS Reverse Engineering Workbench codebase, applying schema migrations, managing toolchain updates, and performing rollback operations if regressions occur.

---

## 1. Version Control & Baseline Checkpoints

The repository maintains clean Git checkpoints:
- Baseline MVP: Commit `1fc1832`
- Production v1.0 Release: Current master commit

To check current status:
```powershell
cd C:\AI\jarvis-re-workbench
git status
git log --oneline -n 5
```

---

## 2. Upgrade Workflow

To upgrade the workbench to a newer release:

### Step 1: Backup Workspaces and Reports
```powershell
Copy-Item -Path "C:\AI\jarvis-re-workbench\workspace" -Destination "C:\AI\jarvis-re-workbench\workspace_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')" -Recurse
```

### Step 2: Pull Latest Code / Switch Branch
```powershell
git fetch origin
git checkout main
git pull
```

### Step 3: Update Dependencies
```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt --upgrade
```

### Step 4: Run Verification Tests
```powershell
python -m pytest -v
```
Ensure all 43 tests pass before resuming production service.

---

## 3. Rollback Procedures

If an upgrade introduces regressions, errors, or tool incompatibilities:

### A. Immediate Code Rollback
To restore the previous stable working checkpoint:
```powershell
# Discard uncommitted changes
git reset --hard HEAD

# Or roll back to a specific tagged release / commit
git checkout <commit_hash>
```

### B. Python Dependency Rollback
If a pip package update broke compatibility (e.g. angr or frida):
```powershell
pip install -r requirements.txt --force-reinstall
```

### C. Restoring Quarantined Samples and Reports
To restore reports and sample metadata from backup:
```powershell
Copy-Item -Path "C:\AI\jarvis-re-workbench\workspace_backup_*\*" -Destination "C:\AI\jarvis-re-workbench\workspace" -Recurse -Force
```

---

## 4. Disaster Recovery & Standalone ZIP Archive

A standalone snapshot archive is maintained at:
```
C:\AI\jarvis-re-workbench.zip
```
If the entire repository folder becomes corrupted:
1. Delete or move corrupted folder `C:\AI\jarvis-re-workbench`.
2. Extract the backup archive:
   ```powershell
   Expand-Archive -Path "C:\AI\jarvis-re-workbench.zip" -DestinationPath "C:\AI\jarvis-re-workbench"
   ```
3. Restart the service via `python -m uvicorn app.main:app --port 8000`.
