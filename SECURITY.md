# Security Notes

## Git History and Secrets

If you fork or adapt this repo and ever accidentally commit a credential, API token, or secret:

**Deleting the file and committing again is not enough.** The secret remains in Git history and is recoverable by anyone with read access to the repo.

The correct remediation steps are:

1. **Rotate the credential immediately.** Assume it is compromised from the moment it was committed, regardless of how quickly you act.

2. **Remove it from Git history** using one of:
   - [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) — faster and simpler than `git filter-branch`
   - `git filter-repo` — the currently recommended built-in approach
   ```bash
   # Remove a specific file from all history
   bfg --delete-files .env
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   git push --force
   ```

3. **Force push** after rewriting history. All collaborators will need to re-clone.

4. **Notify your security team** if the exposed credential had access to production systems or sensitive data.

GitHub's documentation on this: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

## TLS Verification

All API connectors in this repo use TLS verification enabled by default. The `CA_BUNDLE` environment variable controls the trust path:

```bash
# .env
CA_BUNDLE=/path/to/your-corporate-ca-bundle.crt  # custom CA
# or leave unset to use the system trust store (default)
```

`verify=False` does not appear in any connector script in this repo. If you encounter SSL errors in a corporate environment with TLS inspection, see `docs/TROUBLESHOOTING.md` for the correct fix (passing your CA bundle explicitly).

## Reporting a Security Issue

If you find a security problem in this code, open a GitHub issue or reach out directly. This is a public reference implementation — responsible disclosure is appreciated.
