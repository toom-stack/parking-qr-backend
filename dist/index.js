"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const zod_1 = require("zod");
const crypto_1 = __importDefault(require("crypto"));
const qrcode_1 = __importDefault(require("qrcode"));
const multer_1 = __importDefault(require("multer"));
const prisma_1 = require("./prisma");
const client_1 = require("@prisma/client");
const pdfkit_1 = __importDefault(require("pdfkit"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));

const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json());

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

// ======================= Upload Config =======================
const uploadDir = path_1.default.join(process.cwd(), "uploads");
if (!fs_1.default.existsSync(uploadDir))
    fs_1.default.mkdirSync(uploadDir, { recursive: true });

const storage = multer_1.default.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
        const unique = Date.now() + "-" + crypto_1.default.randomBytes(6).toString("hex");
        const ext = path_1.default.extname(file.originalname || "");
        cb(null, unique + ext.toLowerCase());
    },
});

const upload = (0, multer_1.default)({
    storage,
    limits: {
        files: 5,
        fileSize: 8 * 1024 * 1024,
    },
});

// ให้เรียกรูปได้: http://host/uploads/<filename>
app.use("/uploads", express_1.default.static(uploadDir));

function auth(requiredRoles) {
    return (req, res, next) => {
        const header = req.headers.authorization;
        if (!header?.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Missing token" });
        }
        try {
            const token = header.slice(7);
            const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
            req.user = payload;
            if (requiredRoles && !requiredRoles.includes(payload.role)) {
                return res.status(403).json({ message: "Forbidden" });
            }
            next();
        }
        catch {
            return res.status(401).json({ message: "Invalid token" });
        }
    };
}

// ======================= Date Helpers =======================
function startOfDay(d) {
    return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0);
}
function endOfDay(d) {
    return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59, 999);
}
function startOfMonth(d) {
    return new Date(d.getFullYear(), d.getMonth(), 1, 0, 0, 0, 0);
}
function addDays(d, days) {
    const x = new Date(d);
    x.setDate(x.getDate() + days);
    return x;
}
function fmtYYYYMMDD(d) {
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
}
function safeDateFromYMD(s, end = false) {
    if (!s || typeof s !== "string") return null;
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
    if (!m) return null;
    const y = Number(m[1]);
    const mo = Number(m[2]) - 1;
    const d = Number(m[3]);
    if (end) return new Date(y, mo, d, 23, 59, 59, 999);
    return new Date(y, mo, d, 0, 0, 0, 0);
}
function problemLabel(problemType) {
    switch (problemType) {
        case "PARK_RED_WHITE":
            return "จอดเส้นขาวแดง";
        case "BLOCKING":
            return "ขวางทาง";
        case "NO_PARKING":
            return "จอดในที่ห้ามจอด";
        case "OTHER":
            return "อื่น ๆ";
        default:
            return String(problemType || "-");
    }
}
function resolveSummaryRange(query) {
    const now = new Date();

    const fromQuery = safeDateFromYMD(query.from, false);
    const toQuery = safeDateFromYMD(query.to, true);

    if (fromQuery && toQuery) {
        return {
            from: fromQuery,
            to: toQuery,
            label: `${fmtYYYYMMDD(fromQuery)} ถึง ${fmtYYYYMMDD(toQuery)}`,
            mode: "custom",
        };
    }

    const range = String(query.range || query.period || "").toLowerCase();

    if (range === "today" || range === "day" || range === "1d") {
        return {
            from: startOfDay(now),
            to: endOfDay(now),
            label: "วันนี้",
            mode: "today",
        };
    }

    if (
        range === "7days" ||
        range === "7d" ||
        range === "week" ||
        range === "last7days" ||
        range === "recent7"
    ) {
        const from = startOfDay(addDays(now, -6));
        return {
            from,
            to: endOfDay(now),
            label: "7 วันล่าสุด",
            mode: "7days",
        };
    }

    return {
        from: startOfMonth(now),
        to: endOfDay(now),
        label: "เดือนนี้",
        mode: "month",
    };
}

// ---------- Health check ----------
app.get("/", (_req, res) => res.json({ ok: true, service: "parking-qr-backend" }));

// ---------- Auth: Login ----------
app.post("/auth/login", async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            username: zod_1.z.string().min(1),
            password: zod_1.z.string().min(1),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { username, password } = parsed.data;
        const user = await prisma_1.prisma.user.findUnique({ where: { username } });

        if (!user)
            return res.status(401).json({ message: "Invalid credentials" });

        if (user.role === client_1.Role.GUARD && user.disabledAt) {
            return res.status(403).json({ message: "บัญชีนี้ถูกปิดใช้งาน" });
        }

        const ok = await bcrypt_1.default.compare(password, user.passwordHash);
        if (!ok)
            return res.status(401).json({ message: "Invalid credentials" });

        const token = jsonwebtoken_1.default.sign(
            { userId: user.id, role: user.role },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({ token, role: user.role });
    }
    catch (err) {
        next(err);
    }
});

/**
 * =============================================================
 * ADMIN: GUARDS CRUD (soft delete ด้วย disabledAt)
 * =============================================================
 */

app.post("/admin/guards", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            username: zod_1.z.string().min(3),
            password: zod_1.z.string().min(6),
            fullName: zod_1.z.string().min(1),
            employeeCode: zod_1.z.string().min(1),
            phone: zod_1.z.string().optional(),
            email: zod_1.z.string().email().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { username, password, fullName, employeeCode, phone, email } = parsed.data;
        const passwordHash = await bcrypt_1.default.hash(password, 10);

        const guard = await prisma_1.prisma.user.create({
            data: {
                username,
                passwordHash,
                role: client_1.Role.GUARD,
                fullName,
                employeeCode,
                phone,
                email,
            },
            select: {
                id: true,
                username: true,
                role: true,
                fullName: true,
                employeeCode: true,
                phone: true,
                email: true,
                createdAt: true,
                disabledAt: true,
            },
        });

        res.json(guard);
    }
    catch (err) {
        next(err);
    }
});

app.get("/admin/guards", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            q: zod_1.z.string().optional(),
            page: zod_1.z.string().optional(),
            pageSize: zod_1.z.string().optional(),
            includeDisabled: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const q = (parsed.data.q || "").trim();
        const page = Math.max(Number(parsed.data.page || 0), 0);
        const pageSize = Math.min(Math.max(Number(parsed.data.pageSize || 10), 1), 200);
        const includeDisabled = parsed.data.includeDisabled === "1";

        const where = {
            role: client_1.Role.GUARD,
            ...(includeDisabled ? {} : { disabledAt: null }),
            ...(q
                ? {
                    OR: [
                        { username: { contains: q, mode: "insensitive" } },
                        { fullName: { contains: q, mode: "insensitive" } },
                        { employeeCode: { contains: q, mode: "insensitive" } },
                        { phone: { contains: q, mode: "insensitive" } },
                        { email: { contains: q, mode: "insensitive" } },
                    ],
                }
                : {}),
        };

        const [items, total] = await Promise.all([
            prisma_1.prisma.user.findMany({
                where,
                orderBy: { createdAt: "desc" },
                skip: page * pageSize,
                take: pageSize,
                select: {
                    id: true,
                    username: true,
                    role: true,
                    fullName: true,
                    employeeCode: true,
                    phone: true,
                    email: true,
                    createdAt: true,
                    disabledAt: true,
                },
            }),
            prisma_1.prisma.user.count({ where }),
        ]);

        res.json({ items, total });
    }
    catch (err) {
        next(err);
    }
});

app.patch("/admin/guards/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        const schema = zod_1.z.object({
            fullName: zod_1.z.string().min(1).optional(),
            employeeCode: zod_1.z.string().min(1).optional(),
            phone: zod_1.z.string().nullable().optional(),
            email: zod_1.z.string().email().nullable().optional(),
            password: zod_1.z.string().min(6).optional(),
            disabled: zod_1.z.boolean().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const data = { ...parsed.data };

        if (data.password) {
            data.passwordHash = await bcrypt_1.default.hash(data.password, 10);
            delete data.password;
        }

        if (typeof data.disabled === "boolean") {
            data.disabledAt = data.disabled ? new Date() : null;
            delete data.disabled;
        }

        const updated = await prisma_1.prisma.user.update({
            where: { id },
            data,
            select: {
                id: true,
                username: true,
                role: true,
                fullName: true,
                employeeCode: true,
                phone: true,
                email: true,
                createdAt: true,
                disabledAt: true,
            },
        });

        res.json(updated);
    }
    catch (err) {
        next(err);
    }
});

app.delete("/admin/guards/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        const updated = await prisma_1.prisma.user.update({
            where: { id },
            data: { disabledAt: new Date() },
            select: { id: true, disabledAt: true },
        });
        res.json({ ok: true, ...updated });
    }
    catch (err) {
        next(err);
    }
});

/**
 * =============================================================
 * OWNERS CRUD
 * =============================================================
 */

app.post("/owners", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            fullName: zod_1.z.string().min(1),
            room: zod_1.z.string().optional(),
            year: zod_1.z.number().int().optional(),
            faculty: zod_1.z.string().optional(),
            major: zod_1.z.string().optional(),
            phone: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const owner = await prisma_1.prisma.owner.create({ data: parsed.data });
        res.json(owner);
    }
    catch (err) {
        next(err);
    }
});

app.get("/owners", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            q: zod_1.z.string().optional(),
            page: zod_1.z.string().optional(),
            pageSize: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const q = (parsed.data.q || "").trim();
        const page = Math.max(parseInt(parsed.data.page || "0", 10) || 0, 0);
        const pageSizeRaw = parseInt(parsed.data.pageSize || "10", 10) || 10;
        const pageSize = Math.min(Math.max(pageSizeRaw, 1), 200);

        const where = q.length > 0
            ? {
                OR: [
                    { fullName: { contains: q, mode: "insensitive" } },
                    { phone: { contains: q, mode: "insensitive" } },
                    { room: { contains: q, mode: "insensitive" } },
                    { faculty: { contains: q, mode: "insensitive" } },
                    { major: { contains: q, mode: "insensitive" } },
                ],
            }
            : {};

        const [items, total] = await Promise.all([
            prisma_1.prisma.owner.findMany({
                where,
                orderBy: { createdAt: "desc" },
                skip: page * pageSize,
                take: pageSize,
            }),
            prisma_1.prisma.owner.count({ where }),
        ]);

        res.json({ items, total });
    }
    catch (err) {
        next(err);
    }
});

app.patch("/owners/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        const schema = zod_1.z.object({
            fullName: zod_1.z.string().min(1).optional(),
            room: zod_1.z.string().nullable().optional(),
            year: zod_1.z.number().int().nullable().optional(),
            faculty: zod_1.z.string().nullable().optional(),
            major: zod_1.z.string().nullable().optional(),
            phone: zod_1.z.string().nullable().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const updated = await prisma_1.prisma.owner.update({
            where: { id },
            data: parsed.data,
        });

        res.json(updated);
    }
    catch (err) {
        next(err);
    }
});

app.delete("/owners/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        const vehicleCount = await prisma_1.prisma.vehicle.count({ where: { ownerId: id } });

        if (vehicleCount > 0) {
            return res.status(400).json({ message: "ลบไม่ได้: เจ้าของคนนี้มีรถลงทะเบียนอยู่" });
        }

        await prisma_1.prisma.owner.delete({ where: { id } });
        res.json({ ok: true });
    }
    catch (err) {
        next(err);
    }
});

/**
 * =============================================================
 * VEHICLES CRUD
 * =============================================================
 */

app.post("/vehicles", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            ownerId: zod_1.z.string().min(1),
            plateNo: zod_1.z.string().min(1),
            color: zod_1.z.string().optional(),
            brand: zod_1.z.string().optional(),
            model: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { ownerId, ...rest } = parsed.data;
        const count = await prisma_1.prisma.vehicle.count({ where: { ownerId } });

        if (count >= 2)
            return res.status(400).json({ message: "Owner already has 2 vehicles" });

        const qrToken = crypto_1.default.randomBytes(24).toString("hex");
        const vehicle = await prisma_1.prisma.vehicle.create({
            data: { ownerId, qrToken, ...rest },
        });

        res.json(vehicle);
    }
    catch (err) {
        next(err);
    }
});

app.get("/vehicles", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            q: zod_1.z.string().optional(),
            page: zod_1.z.string().optional(),
            pageSize: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const q = (parsed.data.q || "").trim();
        const page = Math.max(Number(parsed.data.page || 0), 0);
        const pageSize = Math.min(Math.max(Number(parsed.data.pageSize || 10), 1), 200);

        const where = q
            ? {
                OR: [
                    { plateNo: { contains: q, mode: "insensitive" } },
                    { brand: { contains: q, mode: "insensitive" } },
                    { model: { contains: q, mode: "insensitive" } },
                    { owner: { is: { fullName: { contains: q, mode: "insensitive" } } } },
                ],
            }
            : {};

        const [items, total] = await Promise.all([
            prisma_1.prisma.vehicle.findMany({
                where,
                include: { owner: true },
                orderBy: { createdAt: "desc" },
                skip: page * pageSize,
                take: pageSize,
            }),
            prisma_1.prisma.vehicle.count({ where }),
        ]);

        res.json({ items, total });
    }
    catch (err) {
        next(err);
    }
});

app.patch("/vehicles/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        const schema = zod_1.z.object({
            plateNo: zod_1.z.string().min(1).optional(),
            color: zod_1.z.string().nullable().optional(),
            brand: zod_1.z.string().nullable().optional(),
            model: zod_1.z.string().nullable().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const updated = await prisma_1.prisma.vehicle.update({
            where: { id },
            data: parsed.data,
            include: { owner: true },
        });

        res.json(updated);
    }
    catch (err) {
        next(err);
    }
});

app.delete("/vehicles/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;

        const result = await prisma_1.prisma.$transaction(async (tx) => {
            const v = await tx.vehicle.findUnique({ where: { id } });
            if (!v)
                return { ok: false, status: 404, message: "Vehicle not found" };

            await tx.reportImage.deleteMany({ where: { report: { vehicleId: id } } });
            await tx.report.deleteMany({ where: { vehicleId: id } });
            await tx.vehicle.delete({ where: { id } });

            const remaining = await tx.vehicle.count({ where: { ownerId: v.ownerId } });
            let deletedOwner = false;

            if (remaining === 0) {
                await tx.owner.delete({ where: { id: v.ownerId } });
                deletedOwner = true;
            }

            return {
                ok: true,
                deletedVehicleId: id,
                ownerId: v.ownerId,
                remainingVehicles: remaining,
                deletedOwner,
            };
        });

        if (!result.ok)
            return res.status(result.status).json({ message: result.message });

        res.json(result);
    }
    catch (err) {
        next(err);
    }
});

/**
 * =============================================================
 * SCAN + REPORTS (Guard/Admin)
 * =============================================================
 */

app.get("/vehicles/by-token/:token", auth([client_1.Role.ADMIN, client_1.Role.GUARD]), async (req, res) => {
    const token = req.params.token;
    try {
        const vehicle = await prisma_1.prisma.vehicle.findUnique({
            where: { qrToken: token },
            include: {
                owner: true,
                reports: {
                    orderBy: { reportedAt: "desc" },
                    take: 5,
                    include: {
                        guard: { select: { username: true, role: true, fullName: true } },
                        images: true,
                    },
                },
            },
        });

        if (!vehicle)
            return res.status(404).json({ message: "Not found" });

        res.json(vehicle);
    }
    catch (err) {
        console.error("❌ /vehicles/by-token ERROR", err?.stack ?? err);
        res.status(500).json({ message: err?.message ?? "Internal Server Error" });
    }
});

app.post("/reports", auth([client_1.Role.GUARD]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            qrToken: zod_1.z.string().min(1),
            problemType: zod_1.z.nativeEnum(client_1.ProblemType),
            locationText: zod_1.z.string().optional(),
            note: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { qrToken, problemType, locationText, note } = parsed.data;
        const vehicle = await prisma_1.prisma.vehicle.findUnique({ where: { qrToken } });

        if (!vehicle)
            return res.status(404).json({ message: "Vehicle not found" });

        const report = await prisma_1.prisma.report.create({
            data: {
                vehicleId: vehicle.id,
                guardUserId: req.user.userId,
                problemType,
                locationText,
                note,
            },
        });

        res.json(report);
    }
    catch (err) {
        next(err);
    }
});

app.post("/reports/with-images", auth([client_1.Role.GUARD]), upload.array("images", 5), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            qrToken: zod_1.z.string().min(1),
            problemType: zod_1.z.nativeEnum(client_1.ProblemType),
            locationText: zod_1.z.string().optional(),
            note: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const files = req.files;
        if (!files || files.length < 3) {
            return res.status(400).json({ message: "ต้องแนบรูปอย่างน้อย 3 รูป" });
        }

        const { qrToken, problemType, locationText, note } = parsed.data;
        const vehicle = await prisma_1.prisma.vehicle.findUnique({ where: { qrToken } });

        if (!vehicle)
            return res.status(404).json({ message: "Vehicle not found" });

        const report = await prisma_1.prisma.report.create({
            data: {
                vehicleId: vehicle.id,
                guardUserId: req.user.userId,
                problemType,
                locationText,
                note,
            },
        });

        const baseUrl = `${req.protocol}://${req.get("host")}`;

        await prisma_1.prisma.reportImage.createMany({
            data: files.map((f) => ({
                reportId: report.id,
                url: `${baseUrl}/uploads/${f.filename}`,
            })),
        });

        const full = await prisma_1.prisma.report.findUnique({
            where: { id: report.id },
            include: {
                images: true,
                vehicle: { select: { plateNo: true, brand: true, model: true, color: true, qrToken: true } },
                guard: { select: { username: true, role: true, fullName: true } },
            },
        });

        res.json(full);
    }
    catch (err) {
        next(err);
    }
});

app.get("/reports/my", auth([client_1.Role.GUARD]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            from: zod_1.z.string().optional(),
            to: zod_1.z.string().optional(),
            take: zod_1.z.string().optional(),
            skip: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { from, to, take, skip } = parsed.data;
        const where = { guardUserId: req.user.userId };

        if (from && to) {
            const fromDate = new Date(`${from}T00:00:00.000Z`);
            const toDate = new Date(`${to}T23:59:59.999Z`);
            where.reportedAt = { gte: fromDate, lte: toDate };
        }

        const reports = await prisma_1.prisma.report.findMany({
            where,
            orderBy: { reportedAt: "desc" },
            take: take ? Math.min(Number(take), 200) : 50,
            skip: skip ? Number(skip) : 0,
            include: {
                vehicle: { select: { plateNo: true, brand: true, model: true, color: true, qrToken: true } },
                guard: { select: { username: true, role: true, fullName: true } },
                images: true,
            },
        });

        res.json(reports);
    }
    catch (err) {
        next(err);
    }
});

app.get("/reports", auth([client_1.Role.ADMIN, client_1.Role.GUARD]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            qrToken: zod_1.z.string().optional(),
            vehicleId: zod_1.z.string().optional(),
            take: zod_1.z.string().optional(),
            skip: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { qrToken, vehicleId, take, skip } = parsed.data;

        if (req.user.role === client_1.Role.GUARD) {
            if (!qrToken)
                return res.status(400).json({ message: "GUARD must provide qrToken" });
        }
        else {
            if (!qrToken && !vehicleId)
                return res.status(400).json({ message: "Provide qrToken or vehicleId" });
        }

        let vid = vehicleId;
        if (!vid) {
            const vehicle = await prisma_1.prisma.vehicle.findUnique({ where: { qrToken: qrToken } });
            if (!vehicle)
                return res.status(404).json({ message: "Vehicle not found" });
            vid = vehicle.id;
        }

        const reports = await prisma_1.prisma.report.findMany({
            where: { vehicleId: vid },
            orderBy: { reportedAt: "desc" },
            take: take ? Math.min(Number(take), 200) : 50,
            skip: skip ? Number(skip) : 0,
            include: {
                vehicle: { select: { plateNo: true, brand: true, model: true, color: true, qrToken: true } },
                guard: { select: { username: true, role: true, fullName: true } },
                images: true,
            },
        });

        res.json(reports);
    }
    catch (err) {
        next(err);
    }
});

/**
 * =============================================================
 * ADMIN WEB: REPORTS LIST + SUMMARY + EDIT + DELETE
 * =============================================================
 */

app.get("/reports/admin", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            from: zod_1.z.string().optional(),
            to: zod_1.z.string().optional(),
            problemType: zod_1.z.nativeEnum(client_1.ProblemType).optional(),
            page: zod_1.z.string().optional(),
            pageSize: zod_1.z.string().optional(),
        });
        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const { from, to, problemType } = parsed.data;
        const page = Math.max(parseInt(parsed.data.page || "0", 10) || 0, 0);
        const pageSizeRaw = parseInt(parsed.data.pageSize || "10", 10) || 10;
        const pageSize = Math.min(Math.max(pageSizeRaw, 1), 200);

        const where = {};

        if (from && to) {
            const fromDate = new Date(`${from}T00:00:00.000Z`);
            const toDate = new Date(`${to}T23:59:59.999Z`);
            where.reportedAt = { gte: fromDate, lte: toDate };
        }

        if (problemType)
            where.problemType = problemType;

        const [total, items] = await Promise.all([
            prisma_1.prisma.report.count({ where }),
            prisma_1.prisma.report.findMany({
                where,
                orderBy: { reportedAt: "desc" },
                skip: page * pageSize,
                take: pageSize,
                include: {
                    vehicle: { include: { owner: true } },
                    guard: { select: { username: true, role: true, fullName: true } },
                    images: true,
                },
            }),
        ]);

        res.json({ items, total });
    }
    catch (err) {
        next(err);
    }
});

// ---------- Admin Web: DASHBOARD SUMMARY ----------
app.get("/reports/admin/summary", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const schema = zod_1.z.object({
            from: zod_1.z.string().optional(),
            to: zod_1.z.string().optional(),
            range: zod_1.z.string().optional(),
            period: zod_1.z.string().optional(),
        });

        const parsed = schema.safeParse(req.query);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const rangeInfo = resolveSummaryRange(parsed.data);
        const from = rangeInfo.from;
        const to = rangeInfo.to;

        const whereRange = {
            reportedAt: {
                gte: from,
                lte: to,
            },
        };

        const todayFrom = startOfDay(new Date());
        const todayTo = endOfDay(new Date());
        const monthFrom = startOfMonth(new Date());
        const monthTo = endOfDay(new Date());

        const [todayCount, monthCount, rangeCount, groupedProblems, groupedLocations, groupedVehicles, trendRows] =
            await Promise.all([
                prisma_1.prisma.report.count({
                    where: {
                        reportedAt: {
                            gte: todayFrom,
                            lte: todayTo,
                        },
                    },
                }),
                prisma_1.prisma.report.count({
                    where: {
                        reportedAt: {
                            gte: monthFrom,
                            lte: monthTo,
                        },
                    },
                }),
                prisma_1.prisma.report.count({ where: whereRange }),
                prisma_1.prisma.report.groupBy({
                    by: ["problemType"],
                    where: whereRange,
                    _count: { _all: true },
                    orderBy: {
                        _count: {
                            problemType: "desc",
                        },
                    },
                }),
                prisma_1.prisma.report.groupBy({
                    by: ["locationText"],
                    where: {
                        ...whereRange,
                        NOT: [{ locationText: null }, { locationText: "" }],
                    },
                    _count: { _all: true },
                    orderBy: {
                        _count: {
                            locationText: "desc",
                        },
                    },
                    take: 10,
                }),
                prisma_1.prisma.report.groupBy({
                    by: ["vehicleId"],
                    where: whereRange,
                    _count: { _all: true },
                    orderBy: {
                        _count: {
                            vehicleId: "desc",
                        },
                    },
                    take: 10,
                }),
                prisma_1.prisma.report.findMany({
                    where: {
                        reportedAt: {
                            gte: startOfDay(addDays(to, -6)),
                            lte: to,
                        },
                    },
                    select: {
                        reportedAt: true,
                    },
                    orderBy: {
                        reportedAt: "asc",
                    },
                }),
            ]);

        const topProblemRow = groupedProblems[0] || null;
        const topLocationRow = groupedLocations[0] || null;

        const problemBreakdown = groupedProblems.map((x) => ({
            problemType: x.problemType,
            label: problemLabel(x.problemType),
            count: x._count._all,
        }));

        const topLocations = groupedLocations.map((x) => ({
            locationText: x.locationText,
            label: x.locationText || "-",
            count: x._count._all,
        }));

        const vehicleIds = groupedVehicles.map((x) => x.vehicleId);
        const vehicleMap = new Map();

        if (vehicleIds.length > 0) {
            const vehicles = await prisma_1.prisma.vehicle.findMany({
                where: { id: { in: vehicleIds } },
                include: { owner: true },
            });
            for (const v of vehicles) {
                vehicleMap.set(v.id, v);
            }
        }

        const topVehicles = groupedVehicles.map((x) => {
            const v = vehicleMap.get(x.vehicleId);
            return {
                vehicleId: x.vehicleId,
                plateNo: v?.plateNo || "-",
                brand: v?.brand || null,
                model: v?.model || null,
                color: v?.color || null,
                ownerName: v?.owner?.fullName || null,
                count: x._count._all,
            };
        });

        const trendMap = new Map();
        for (let i = 0; i < 7; i++) {
            const d = startOfDay(addDays(to, -6 + i));
            trendMap.set(fmtYYYYMMDD(d), 0);
        }
        for (const row of trendRows) {
            const key = fmtYYYYMMDD(new Date(row.reportedAt));
            if (trendMap.has(key)) {
                trendMap.set(key, (trendMap.get(key) || 0) + 1);
            }
        }

        const trend7Days = Array.from(trendMap.entries()).map(([date, count]) => ({
            date,
            count,
        }));

        res.json({
            ok: true,
            range: {
                mode: rangeInfo.mode,
                label: rangeInfo.label,
                from: fmtYYYYMMDD(from),
                to: fmtYYYYMMDD(to),
            },
            cards: {
                todayCount,
                monthCount,
                reportCount: rangeCount,
                totalInRange: rangeCount,
                topProblemType: topProblemRow?.problemType || null,
                topProblemLabel: topProblemRow ? problemLabel(topProblemRow.problemType) : "-",
                topProblemCount: topProblemRow?._count?._all || 0,
                topLocationText: topLocationRow?.locationText || "-",
                topLocationCount: topLocationRow?._count?._all || 0,
            },
            todayCount,
            monthCount,
            reportCount: rangeCount,
            totalInRange: rangeCount,
            topProblem: topProblemRow
                ? {
                    problemType: topProblemRow.problemType,
                    label: problemLabel(topProblemRow.problemType),
                    count: topProblemRow._count._all,
                }
                : null,
            topLocation: topLocationRow
                ? {
                    locationText: topLocationRow.locationText,
                    label: topLocationRow.locationText || "-",
                    count: topLocationRow._count._all,
                }
                : null,
            problemBreakdown,
            topLocations,
            topVehicles,
            trend7Days,
            summaryText: `ช่วง ${rangeInfo.label} มีรายงาน ${rangeCount} รายการ`,
        });
    }
    catch (err) {
        next(err);
    }
});

app.patch("/reports/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        const schema = zod_1.z.object({
            problemType: zod_1.z.nativeEnum(client_1.ProblemType).optional(),
            locationText: zod_1.z.string().nullable().optional(),
            note: zod_1.z.string().nullable().optional(),
        });
        const parsed = schema.safeParse(req.body);
        if (!parsed.success)
            return res.status(400).json(parsed.error);

        const updated = await prisma_1.prisma.report.update({
            where: { id },
            data: parsed.data,
            include: {
                vehicle: { select: { plateNo: true, qrToken: true } },
                guard: { select: { username: true, fullName: true } },
                images: true,
            },
        });

        res.json(updated);
    }
    catch (err) {
        next(err);
    }
});

app.delete("/reports/:id", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const id = req.params.id;
        await prisma_1.prisma.reportImage.deleteMany({ where: { reportId: id } });
        await prisma_1.prisma.report.delete({ where: { id } });
        res.json({ ok: true, deletedReportId: id });
    }
    catch (err) {
        next(err);
    }
});

/**
 * =============================================================
 * QR / BADGE
 * =============================================================
 */

app.get("/qr/:token.png", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const token = req.params.token;
        const vehicle = await prisma_1.prisma.vehicle.findUnique({ where: { qrToken: token } });

        if (!vehicle)
            return res.status(404).json({ message: "Vehicle not found" });

        const qrValue = `parking-qr:${token}`;
        const pngBuffer = await qrcode_1.default.toBuffer(qrValue, {
            type: "png",
            errorCorrectionLevel: "M",
            margin: 2,
            scale: 8,
        });

        res.setHeader("Content-Type", "image/png");
        res.send(pngBuffer);
    }
    catch (err) {
        next(err);
    }
});

app.get("/badge/:token.pdf", auth([client_1.Role.ADMIN]), async (req, res, next) => {
    try {
        const token = req.params.token;
        const vehicle = await prisma_1.prisma.vehicle.findUnique({
            where: { qrToken: token },
            include: { owner: true },
        });

        if (!vehicle)
            return res.status(404).json({ message: "Vehicle not found" });

        const qrValue = `parking-qr:${token}`;
        const dataUrl = await qrcode_1.default.toDataURL(qrValue, {
            errorCorrectionLevel: "M",
            margin: 1,
            scale: 10,
        });
        const qrBuffer = Buffer.from(dataUrl.replace(/^data:image\/png;base64,/, ""), "base64");

        const CM = 28.346;
        const W = 10 * CM;
        const H = 15 * CM;

        const doc = new pdfkit_1.default({
            size: [W, H],
            margins: { top: 20, left: 20, right: 20, bottom: 20 },
        });

        res.setHeader("Content-Type", "application/pdf");
        const safePlate = (vehicle.plateNo || "vehicle").replace(/[^\w\-]+/g, "_");
        res.setHeader("Content-Disposition", `inline; filename="badge-${safePlate}.pdf"`);

        const fontPath = path_1.default.join(process.cwd(), "assets", "fonts", "THSarabunNew.ttf");
        if (fs_1.default.existsSync(fontPath))
            doc.font(fontPath);

        doc.pipe(res);

        const pageW = doc.page.width;

        doc.fontSize(14).text("มหาวิทยาลัยเทคโนโลยีราชมงคลศรีวิชัย", { align: "center" });
        doc.fontSize(10).text("สแกนเพื่อดูข้อมูลรถ / รายงานปัญหา", { align: "center" });
        doc.moveDown(1.2);

        const qrSize = 185;
        const qrX = (pageW - qrSize) / 2;
        const qrY = doc.y;
        doc.image(qrBuffer, qrX, qrY, { width: qrSize, height: qrSize });

        doc.y = qrY + qrSize + 15;

        const stripHeight = 42;
        const stripMargin = 25;
        doc.rect(stripMargin, doc.y, pageW - stripMargin * 2, stripHeight).fill("#1E4FA1");

        const stripY = doc.y;

        doc
            .fillColor("white")
            .fontSize(26)
            .text(vehicle.plateNo, stripMargin, stripY + 8, {
                width: pageW - stripMargin * 2,
                align: "center",
            });

        doc.fillColor("black");
        doc.y = stripY + stripHeight + 15;

        doc.fontSize(12).text(`ยี่ห้อ/รุ่น: ${vehicle.brand ?? "-"} ${vehicle.model ?? ""}`.trim(), { align: "center" });
        doc.text(`สี: ${vehicle.color ?? "-"}`, { align: "center" });

        doc.moveDown(0.5);
        doc.text(`เจ้าของ: ${vehicle.owner.fullName}`, { align: "center" });
        if (vehicle.owner.phone)
            doc.text(`โทร: ${vehicle.owner.phone}`, { align: "center" });

        doc.moveDown(0.5);
        doc.fontSize(8).text(`Token: ${token}`, { align: "center" });

        doc.end();
    }
    catch (err) {
        next(err);
    }
});

app.get("/vehicles/:token/qr.png", auth([client_1.Role.ADMIN]), (req, res) => {
    const token = req.params.token;
    return res.redirect(302, `/qr/${encodeURIComponent(token)}.png`);
});

app.get("/vehicles/:token/badge.pdf", auth([client_1.Role.ADMIN]), (req, res) => {
    const token = req.params.token;
    return res.redirect(302, `/badge/${encodeURIComponent(token)}.pdf`);
});

app.use((err, _req, res, _next) => {
    console.error("❌ API ERROR:", err);
    const message = err?.message || "Internal Server Error";
    res.status(500).json({ message });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ API running: http://0.0.0.0:${PORT}`);
});