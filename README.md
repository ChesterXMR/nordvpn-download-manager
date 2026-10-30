# Nord Download Manager

Windows download manager that fetches each file over parallel connections, routing every download through its own NordVPN server. Not affiliated with NordVPN.

You need a NordVPN account with an active subscription to use it.

## Requirements

- [Rust](https://rustup.rs) (stable, MSVC toolchain)
- Visual Studio Build Tools with the **Desktop development with C++** workload
- [CMake](https://cmake.org/download/) and [LLVM](https://github.com/llvm/llvm-project/releases) (needed to build BoringSSL)
- [Node.js](https://nodejs.org) 20+

With winget:

```
winget install Rustlang.Rustup Kitware.CMake LLVM.LLVM OpenJS.NodeJS.LTS
winget install Microsoft.VisualStudio.2022.BuildTools --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

## Build

```
npm install
npx tauri build --no-bundle
```

Output: `src-tauri\target\release\nord-download-manager.exe`, a single portable exe with no installer.

## Usage

On first launch the app asks for a NordVPN access token. To get one:

1. Sign in at [my.nordaccount.com](https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/) (the app's **Open Nord Account** link goes straight there).
2. Open **NordVPN → Set up NordVPN manually** and enter the verification code Nord e-mails you.
3. On the **Access token** tab, click **Generate new token** and copy it.

Paste the token into the app and click **Sign in**. You only need to do this once: the app swaps the token for your NordVPN service credentials and stores them in Windows Credential Manager. Alternatively, choose **Use service credentials instead** and enter the service username and password shown on the same Nord Account page (not your e-mail and password).

Then paste a download link and click **Download**.
