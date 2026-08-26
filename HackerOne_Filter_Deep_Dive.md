# HackerOne filtering: Deep Dive & System Analysis

## 1. Project Objective
The goal of this project is to automate the identification of "Dead" HackerOne programs. A program is considered dead if:
- It is explicitly closed or deactivated.
- It has low response standards (below 100% by default).
- **CRITICAL**: It has **zero assets eligible for monetary bounties**.

## 2. The Core Challenge: The "Allegion" Phenomenon
During development, we discovered that some programs (like **Allegion**) were being incorrectly identified as **ACTIVE** when they should have been **DEAD**.

### Why it failed initially:
HackerOne is a **Single-Page Application (SPA)** built with React. This presents two major hurdles:
1. **Unreliable URL Parameters**: We tried navigating directly to `.../policy_scopes?bounty_eligibility=eligible`. However, HackerOne's React state often **ignores** this parameter on the first render, defaulting to the "All" view. This "All" view shows assets that are "Ineligible," leading the script to believe the program is active.
2. **React Hydration / Rendering Delays**: Even after the network is idle, the React engine might take a few seconds to "hydrate" the actual data into the DOM. If the script checks the text immediately, it sees an empty body or stale data.

## 3. The Engineered Solution
To solve these issues, the script was upgraded from a simple scraper to a **UI Automator**:

### Key Features of the Final Implementation:
- **Playwright Browser Context**: Uses a real Chromium instance to execute JavaScript and handle the React lifecycle.
- **UI Interaction (The "Click" Fix)**: Instead of trusting the URL, the script now:
  1. Navigates to the Scopes page.
  2. **Clicks** the "Bounty eligibility" dropdown.
  3. **Selects** the "Eligible for bounty" option manually.
  4. Waits for the React table to refresh.
- **Robust Guard Selectors**: The script specifically waits for elements like `.daisy-table` or the "No assets in scope" text before reading the page content.
- **Multi-Factor Classification**:
    - **Regex Detection**: Extracts the response efficiency percentage.
    - **Keyword Matching**: Checks for signals like "Program closed" or "Paused."
    - **Scope Validation**: Final check for the "No assets in scope" message after filtering.

## 4. How the Script Works (Step-by-Step)
1. **Input**: Reads a list of embedded submission URLs.
2. **Initial Check**: Navigates to the submission page to find the main "Security Page" link.
3. **Main Page**: Checks the program's header/sidebar for response standards and "Closed" signals.
4. **Policy Check**: If still active, it jumps to the scopes page, applies the bounty filter via UI clicks, and checks for remaining assets.
5. **Output**: Generates [hackerone_active.txt](file:///C:/Users/medoo/Desktop/private/hackerone_active.txt), `hackerone_dead.txt`, and a full CSV report.

## 5. Summary of Results
In a test of **329 URLs**, the script successfully filtered out **226 inactive programs**, leaving **103 high-quality, active targets**. This saves the researcher from manually checking hundreds of "Dead" or "VDP-only" programs.
