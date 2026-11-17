import { mutateDirectoryWorkbench, readDirectoryWorkbench } from '../local-directory-workbench';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const GET = readDirectoryWorkbench;
export const POST = mutateDirectoryWorkbench;
