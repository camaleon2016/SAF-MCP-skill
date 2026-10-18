# Releasing

Releases are published to npm as [`saf-mcp-skill`](https://www.npmjs.com/package/saf-mcp-skill) by `.github/workflows/publish.yml` when a GitHub Release is published. npm trusts that workflow through trusted publishing, so no npm token is stored anywhere, and each version carries a provenance attestation linking it to the commit and workflow run that built it.

## Every release

1. On a branch, set the version in three places and keep them equal (`npm test` checks this): `package.json`, `src/version.ts`, and `info.version` in `src/openapi/openapi.json`. Run `npm install` so the lockfile picks it up. Also update the version the README pins in its MCP client configs (`saf-mcp-skill@X.Y.Z`) and quotes in sample output; `npm test` fails until they match.
2. In `CHANGELOG.md`, give the new version a section and its release date.
3. Run `npm run ci`, open a pull request to `main`, and merge it once the checks pass.
4. Tag the merge commit and push the tag:

   ```bash
   git checkout main
   git pull
   git tag -a vX.Y.Z -m "saf-mcp-skill X.Y.Z"
   git push origin vX.Y.Z
   ```

5. On GitHub, draft a release from the tag with the changelog section as its notes, and publish it. Publishing the release starts the npm workflow.
6. Check the workflow run under **Actions**, then confirm the new version on npm. Its page shows a provenance badge.

The workflow refuses to publish when the release tag does not match `package.json`, and it runs the full test suite and the catalog check first.

## Machines with a private registry

If `npm config get registry` shows anything other than `https://registry.npmjs.org/` (a company feed or proxy, for example), add `--registry=https://registry.npmjs.org/` to `npm login`, `npm install`, and `npm publish` on that machine. `publishConfig` pins publishing to the public registry, and `npm test` fails if `package-lock.json` ever resolves packages from anywhere else.

## One time setup (already done for this package)

Trusted publishing can only be configured for a package that already exists, so the first version was published by hand:

1. From a clean clone of the release tag: `npm ci`, `npm run build`, `npm publish --dry-run` to review the contents, then `npm publish --access public` (with two factor authentication).
2. On npmjs.com, in the package's **Settings**, under **Trusted Publisher**, choose GitHub Actions and enter the owner `camaleon2016`, repository `SAF-MCP-skill`, and workflow filename `publish.yml`.
3. In the same settings, set publishing access to require two factor authentication and disallow tokens. Trusted publishing keeps working, and no token can publish.

## Verifying a published version

In any project that installed `saf-mcp-skill`:

```bash
npm audit signatures
```

It reports packages with verified registry signatures and provenance attestations.
