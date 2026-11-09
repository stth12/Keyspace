import 'dotenv/config';
import { defineConfig } from 'prisma/config';
export default defineConfig({schema:'apps/api/prisma/schema.prisma',migrations:{path:'apps/api/prisma/migrations'},datasource:{url:process.env.MIGRATION_DATABASE_URL || process.env.DATABASE_URL || 'postgresql://invalid:invalid@localhost:5432/invalid'}});
