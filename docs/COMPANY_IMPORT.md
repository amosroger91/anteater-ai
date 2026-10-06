# Company scope import

The scanner at `http://127.0.0.1:4317/run` includes **Fetch companies from HackerOne**. It uses the saved HackerOne username/token, with explicit environment values taking precedence, and calls the authenticated [HackerOne program-list API](https://api.hackerone.com/hacker-resources/#get-programs). These are programs available to that account; the API list is not a list of signed customer pentest contracts.

1. Save HackerOne credentials and your approver name in setup.
2. Fetch companies. Every returned company is selected initially. Search, deselect individual entries, or use Select all / Deselect all.
3. Choose **Review selected scope**. Anteater retrieves program policies, structured scopes, and exclusions, then shows the exact importable scope. Closed programs, prohibited or ambiguous automation policies, unavailable programs, and scope without a supported concrete web asset appear in the exclusion list.
4. Review allowed hosts/wildcards, concrete assets, excluded hosts, exact paths, permitted actions, request rate, and asset instructions. Check the permission statement and choose **Confirm and add scope**.
5. The selected eligible programs, scope rules, and named approval/source hash are saved to PostgreSQL. Approvals expire after seven days. No jobs are enqueued and no target scan starts from this action. An independently running discovery monitor may later enqueue currently admitted new hosts under the saved policy.

The import does not place companies in the owned-lab hostname list or grant private-network access. Unchecked entries leave any previously approved scope intact. **Companies already in scope** reads saved programs from PostgreSQL, including after a page reload. Database configuration uses `DATABASE_URL`; confirmation runs the existing migrations before writing scope.

## Confirmation and failure behavior

The server retains the fetched policy snapshot. The browser submits only selected handles, a reviewer name, and an explicit confirmation; it cannot inject replacement assets or policy. A review expires after 15 minutes. Refresh and review again after expiry. The user-confirmed batch has its own approval revision, and known asset origins retain their existing database IDs.

Fetching and scope preparation show progress and can be cancelled. Saving reports each successful company and each failure; successful saves are not rolled back if another company fails. A repeated confirmation of a finished batch does not write it again. Restarting the setup server discards an unconfirmed selection/review, while confirmed database records remain. If polling is interrupted, **Refresh import status** resumes it in the same page.

All API pagination stays on the exact HackerOne endpoint, refuses redirects, and is bounded by page, byte, and time limits. A failed directory page never returns an apparently complete partial company list. API tokens remain on the server and are not returned in selection or scope status. Only same-origin JSON requests from the local scanner can change an import.

On HTTP 429, directory and policy/scope requests pause and retry the same request once. `Retry-After` accepts seconds or an HTTP date, capped at 60 seconds; missing or malformed values use two seconds. The wait can be cancelled, counts toward the import's overall deadline, and is followed by a fresh request timeout. A second 429 stops the import with its existing rate-limit error; other HTTP errors are not retried.

## Verification status

The implementation and regression fixtures were reviewed statically on 2026-10-06. Tests, browser checks, HackerOne calls with real credentials, and target scans were not run for this change, following the user's instruction. Earlier fixture results do not validate this new UI/import path.
