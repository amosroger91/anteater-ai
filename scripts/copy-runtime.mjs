import { cp, mkdir } from 'node:fs/promises';
await mkdir('dist/apps/dashboard', { recursive: true });
await mkdir('dist/infrastructure', { recursive: true });
await cp('apps/dashboard/public', 'dist/apps/dashboard/public', { recursive: true });
await cp('infrastructure/postgres', 'dist/infrastructure/postgres', { recursive: true });
