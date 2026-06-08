# MOSS Playbook: Web Risk Container App Dependency Updates

This playbook is part of the Web Risk Container App's **MOSS (Minimum Open Source Security)** compliance. It explains how to respond to vulnerability alerts and ensure our open-source dependencies are secure.

For tracking and general documentation, see:
*   **MOSS Dashboard:** [go/moss-dash](http://go/moss-dash)
*   **Vulnerability Monitoring:** [go/vuln-monitoring](http://go/vuln-monitoring)

## Alerting & Bug Routing

Vulnerability scanning is configured for all repositories on the `webrisk` Gerrit host (configured in [CL 740788929](http://cl/740788929)).

*   **Alerts Route to:** [reCAPTCHA Interrupts (Component 561426)](https://buganizer.corp.google.com/savedsearches/6594123?q=componentid:561426)
*   **CC:** `cloud-webrisk-team@google.com`

---

## How to Update Vulnerable Dependencies

When a vulnerability is detected (or during routine maintenance), you must update the dependency.

Because of internal `google3/...` import paths in Piper, **you cannot run `go get` or `go mod tidy` directly in your CitC workspace.** You must perform the update externally and copy the files back.

### Step-by-Step Instructions

1.  **Clone/Sync Externally:**
    Go to a local directory (outside CitC) and clone the public repository:
    ```bash
    git clone https://github.com/google/webrisk
    cd webrisk
    ```

2.  **Update the Dependency:**
    In your local clone, run the Go tools to update the specific vulnerable package (e.g., `golang.org/x/net`):
    ```bash
    # Update to latest:
    go get -u golang.org/x/net@latest

    # Clean up go.mod and go.sum:
    go mod tidy
    ```

3.  **Verify Externally:**
    Run the Go tests in your local clone to ensure no breaking changes:
    ```bash
    go test ./...
    ```

4.  **Copy Back to CitC:**
    Copy the updated `go.mod` and `go.sum` (and any modified `.go` files) from your local clone back into your google3 CitC workspace under `google3/third_party/webrisk/`.

5.  **Verify in google3:**
    In your CitC workspace, run the Blaze tests to ensure google3 compatibility:
    ```bash
    SKYBUILD=1 blaze test //third_party/webrisk:webrisk_test
    ```

6.  **Submit with Attestation:**
    Create a CL and add the following tag to your CL description:
    ```
    DEPS_CHECKED=true
    ```
    *This tag is required by a presubmit check to confirm you have followed this playbook and verified the updates.*

---

## Detailed Development Workflow
For a complete guide on developing and making non-dependency changes to the container app, see [DEVELOPMENT.md](file:///google/src/cloud/interweb/prodx-fixit-share-260608150135/google3/third_party/webrisk/DEVELOPMENT.md).
