# Web Risk Container App Development Guide

This document explains the development workflow for the Web Risk Container App.

## The Hybrid Workflow

The Source of Truth (SoT) for this code is in Piper (`google3/third_party/webrisk/`), but the container app is mirrored to GitHub ([github.com/google/webrisk](https://github.com/google/webrisk)) and relies on standard Go modules for external users.

Because the files in Piper use internal `google3/...` import paths, **standard Go toolchain commands (like `go get`, `go mod tidy`, and `go test`) cannot be run directly inside your google3 CitC workspace.** They will fail to resolve the internal imports.

To make updates (including dependency updates), you must use a hybrid workflow: **develop externally, copy back internally.**

---

## Step-by-Step Development Process

### 1. Make Changes in a GitHub Clone
Do not edit the Go files or `go.mod` directly in CitC if you need to run Go tools. Instead:

1.  Clone the public GitHub repository to your local machine (outside of CitC):
    ```bash
    git clone https://github.com/google/webrisk
    cd webrisk
    ```
2.  Make your code changes or dependency updates in this clone.
3.  If you are updating dependencies (e.g., to fix a vulnerability):
    ```bash
    # Update all packages:
    go get -u ./...
    # Or update a specific package:
    go get -u golang.org/x/net@latest

    # Tidy the module:
    go mod tidy
    ```
4.  Verify the changes by running the Go tests in the clone:
    ```bash
    go test ./...
    ```

### 2. Copy Changes Back to Piper
Once your changes are verified and working in the GitHub clone:

1.  Copy the modified files from your local GitHub clone back into your google3 CitC workspace under `google3/third_party/webrisk/`.
    *   *Make sure to copy `go.mod` and `go.sum` if you updated dependencies.*
2.  In your CitC workspace, verify that the google3 build is still healthy by running Blaze tests:
    ```bash
    SKYBUILD=1 blaze test //third_party/webrisk:webrisk_test
    ```

### 3. Submit the CL (with Attestation)
1.  Create your CL.
2.  **If you updated dependencies**, you must add the following tag to your CL description:
    ```
    DEPS_CHECKED=true
    ```
    *A presubmit check (configured in [METADATA](file:///google/src/cloud/interweb/prodx-fixit-share-260608150135/google3/third_party/webrisk/METADATA)) enforces this tag if `go.mod` or `go.sum` are modified. This confirms you followed this guide and verified the updates externally.*
3.  Submit the CL. Copybara will automatically mirror your changes back to GitHub.
