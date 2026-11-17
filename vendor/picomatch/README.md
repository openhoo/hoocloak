# Temporary Picomatch backport

Both frontend build projects install the same local, MIT-licensed package as
`picomatch`. The archive starts with npm's `picomatch@4.0.7` and applies the
parser fix from [micromatch/picomatch#194](https://github.com/micromatch/picomatch/pull/194),
pinned to commit `7be3276fb8bd215a8c73fa066bcaf696c244ad88`, for
[GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf).
The local name and version identify the backport. The only other change to
the upstream files is the private package manifest metadata. The two archive
copies keep the provider and standalone SPA Docker contexts independent.

- npm upstream archive SHA-512 (SRI):
  `sha512-qcJu88Q2IWqJsDD529JKMdwGm/dvInW4HvQnRwiH9JtihJvzGOscDtHE3x1pBKeUOTysQ8kVmLnJ2kJu7yhcGA==`
- Checked-in backport archive SHA-256:
  `7016f8511a4399159fa74f6ffb078e934ffa282088507cf81fbace525f18103f`

To inspect or repack from the repository root:

```sh
repo=$(pwd)
work=$(mktemp -d)
(
  cd "$work" &&
  npm pack picomatch@4.0.7 --ignore-scripts &&
  test "$(openssl dgst -sha512 -binary picomatch-4.0.7.tgz | openssl base64 -A)" = \
    'qcJu88Q2IWqJsDD529JKMdwGm/dvInW4HvQnRwiH9JtihJvzGOscDtHE3x1pBKeUOTysQ8kVmLnJ2kJu7yhcGA==' &&
  tar -xzf picomatch-4.0.7.tgz &&
  cd package &&
  git apply "$repo/vendor/picomatch/GHSA-fc5q-39xc-vjpf.patch" &&
  npm pkg set name=@hoocloak/picomatch version=4.0.7-hoocloak.1 &&
  npm pkg set private=true --json &&
  npm pack --ignore-scripts --pack-destination ..
)
```

The compressed bytes can vary with the npm and Node toolchain. Compare the
decompressed tar contents with the checked-in archive. If replacing the
archive, update both copies, regenerate both lockfiles, and verify clean
installs and builds.

Once a compatible official fix is available, replace both local overrides with
the official npm release, remove the archives and the Docker copy steps, and
run both full npm audits and the browser suite. Registry audit results do not
track this private backport; use the upstream advisory and release status to
decide when to replace it.
