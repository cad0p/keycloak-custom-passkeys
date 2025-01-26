#!/usr/bin/env node
import * as esbuild from 'esbuild'

await esbuild.build({
  entryPoints: ['app/content/inventage.v2/SigningInPasskeys.tsx'],
  bundle: true,
  format: "esm",
  packages: "external",
  loader: { '.tsx': 'tsx' },
  outdir: '../resources/content/inventage.v2',
})
