import bcrypt from "bcrypt";
import { Role } from "@prisma/client";
import { prisma } from "../src/prisma";

async function main() {
  const adminPass = await bcrypt.hash("admin1234", 10);
  const guardPass = await bcrypt.hash("guard1234", 10);

  await prisma.user.upsert({
    where: { username: "admin" },
    update: { passwordHash: adminPass, role: Role.ADMIN }, // ✅ เพิ่มตรงนี้
    create: { username: "admin", passwordHash: adminPass, role: Role.ADMIN },
  });

  await prisma.user.upsert({
    where: { username: "guard" },
    update: { passwordHash: guardPass, role: Role.GUARD }, // ✅ เพิ่มตรงนี้
    create: { username: "guard", passwordHash: guardPass, role: Role.GUARD },
  });

  console.log("✅ Seeded users: admin/admin1234, guard/guard1234");
}

main()
  .catch((e) => {
    console.error("❌ Seed error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });