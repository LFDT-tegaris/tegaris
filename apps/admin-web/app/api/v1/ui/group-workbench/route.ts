import { mutateGroupWorkbench, readGroupWorkbench } from '../local-group-workbench';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const GET = readGroupWorkbench;
export const POST = mutateGroupWorkbench;
