import { fileURLToPath } from 'node:url';

const isProd = process.env.NODE_ENV === 'production';
const deployMode = process.env.WRKR_DOCS_DEPLOY_MODE === 'server' ? 'server' : 'static';
const useStaticExport = deployMode === 'static';
const repoRoot = fileURLToPath(new URL('../', import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: useStaticExport ? 'export' : undefined,
  basePath: useStaticExport && isProd ? '/wrkr' : '',
  assetPrefix: useStaticExport && isProd ? '/wrkr/' : '',
  outputFileTracingRoot: repoRoot,
  images: {
    unoptimized: true,
  },
  trailingSlash: useStaticExport,
};

export default nextConfig;
