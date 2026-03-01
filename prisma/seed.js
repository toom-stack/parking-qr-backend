"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcrypt_1 = __importDefault(require("bcrypt"));
const client_1 = require("@prisma/client");
const prisma_1 = require("../src/prisma");
async function main() {
    const adminPass = await bcrypt_1.default.hash("admin1234", 10);
    const guardPass = await bcrypt_1.default.hash("guard1234", 10);
    await prisma_1.prisma.user.upsert({
        where: { username: "admin" },
        update: { passwordHash: adminPass, role: client_1.Role.ADMIN }, // ✅ เพิ่มตรงนี้
        create: { username: "admin", passwordHash: adminPass, role: client_1.Role.ADMIN },
    });
    await prisma_1.prisma.user.upsert({
        where: { username: "guard" },
        update: { passwordHash: guardPass, role: client_1.Role.GUARD }, // ✅ เพิ่มตรงนี้
        create: { username: "guard", passwordHash: guardPass, role: client_1.Role.GUARD },
    });
    console.log("✅ Seeded users: admin/admin1234, guard/guard1234");
}
main()
    .catch((e) => {
    console.error("❌ Seed error:", e);
    process.exit(1);
})
    .finally(async () => {
    await prisma_1.prisma.$disconnect();
});
//# sourceMappingURL=seed.js.map