import "dotenv/config";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { z } from "zod";
import crypto from "crypto";
import QRCode from "qrcode";
import multer from "multer";

import { prisma } from "./prisma";
import { Role, ProblemType } from "@prisma/client";

import PDFDocument from "pdfkit";
import fs from "fs";
import path from "path";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

// ======================= Upload Config =======================
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const unique = Date.now() + "-" + crypto.randomBytes(6).toString("hex");
    const ext = path.extname(file.originalname || "");
    cb(null, unique + ext.toLowerCase());
  },
});

const upload = multer({
  storage,
  limits: {
    files: 5,
    fileSize: 8 * 1024 * 1024,
  },
});

// ให้เรียกรูปได้: http://host/uploads/<filename>
app.use("/uploads", express.static(uploadDir));

// ---------- Auth middleware ----------
type JwtPayload = { userId: string; role: Role };

function auth(requiredRoles?: Role[]) {
  return (req: any, res: any, next: any) => {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Missing token" });
    }

    try {
      const token = header.slice(7);
      const payload = jwt.verify(token, JWT_SECRET) as JwtPayload;
      req.user = payload;

      if (requiredRoles && !requiredRoles.includes(payload.role)) {
        return res.status(403).json({ message: "Forbidden" });
      }
      next();
    } catch {
      return res.status(401).json({ message: "Invalid token" });
    }
  };
}

// ---------- Health check ----------
app.get("/", (_req, res) => res.json({ ok: true, service: "parking-qr-backend" }));

// ---------- Auth: Login ----------
app.post("/auth/login", async (req, res, next) => {
  try {
    const schema = z.object({
      username: z.string().min(1),
      password: z.string().min(1),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { username, password } = parsed.data;

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // ถ้าปิดใช้งาน guard
    if (user.role === Role.GUARD && (user as any).disabledAt) {
      return res.status(403).json({ message: "บัญชีนี้ถูกปิดใช้งาน" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user.id, role: user.role } satisfies JwtPayload,
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    next(err);
  }
});

/**
 * =============================================================
 * ADMIN: GUARDS CRUD (soft delete ด้วย disabledAt)
 * =============================================================
 */

// ---------- Admin: Create GUARD ----------
app.post("/admin/guards", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const schema = z.object({
      username: z.string().min(3),
      password: z.string().min(6),
      fullName: z.string().min(1),
      employeeCode: z.string().min(1),
      phone: z.string().optional(),
      email: z.string().email().optional(), // ถ้าไม่กรอกให้ส่ง undefined (อย่าส่ง "")
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { username, password, fullName, employeeCode, phone, email } = parsed.data;

    const passwordHash = await bcrypt.hash(password, 10);

    const guard = await prisma.user.create({
      data: {
        username,
        passwordHash,
        role: Role.GUARD,
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
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: List GUARDs ----------
app.get("/admin/guards", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const schema = z.object({
      q: z.string().optional(),
      page: z.string().optional(),
      pageSize: z.string().optional(),
      includeDisabled: z.string().optional(),
    });

    const parsed = schema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const q = (parsed.data.q || "").trim();
    const page = Math.max(Number(parsed.data.page || 0), 0);
    const pageSize = Math.min(Math.max(Number(parsed.data.pageSize || 10), 1), 200);
    const includeDisabled = parsed.data.includeDisabled === "1";

    const where: any = {
      role: Role.GUARD,
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
      prisma.user.findMany({
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
      prisma.user.count({ where }),
    ]);

    res.json({ items, total });
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Update GUARD ----------
app.patch("/admin/guards/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const schema = z.object({
      fullName: z.string().min(1).optional(),
      employeeCode: z.string().min(1).optional(),
      phone: z.string().nullable().optional(),
      email: z.string().email().nullable().optional(),
      password: z.string().min(6).optional(),
      disabled: z.boolean().optional(), // true=ปิดใช้งาน
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const data: any = { ...parsed.data };

    if (data.password) {
      data.passwordHash = await bcrypt.hash(data.password, 10);
      delete data.password;
    }

    if (typeof data.disabled === "boolean") {
      data.disabledAt = data.disabled ? new Date() : null;
      delete data.disabled;
    }

    // ถ้าส่ง email/phone เป็น null แปลว่าเคลียร์ค่า
    const updated = await prisma.user.update({
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
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Disable GUARD ----------
app.delete("/admin/guards/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const updated = await prisma.user.update({
      where: { id },
      data: { disabledAt: new Date() },
      select: { id: true, disabledAt: true },
    });

    res.json({ ok: true, ...updated });
  } catch (err) {
    next(err);
  }
});

/**
 * =============================================================
 * OWNERS CRUD
 * =============================================================
 */

// ---------- Admin: Create owner ----------
app.post("/owners", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const schema = z.object({
      fullName: z.string().min(1),
      room: z.string().optional(),
      year: z.number().int().optional(),
      faculty: z.string().optional(),
      major: z.string().optional(),
      phone: z.string().optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const owner = await prisma.owner.create({ data: parsed.data });
    res.json(owner);
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: List owners (search + pagination) ----------
app.get("/owners", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const schema = z.object({
      q: z.string().optional(),
      page: z.string().optional(),
      pageSize: z.string().optional(),
    });

    const parsed = schema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const q = (parsed.data.q || "").trim();
    const page = Math.max(parseInt(parsed.data.page || "0", 10) || 0, 0);
    const pageSizeRaw = parseInt(parsed.data.pageSize || "10", 10) || 10;
    const pageSize = Math.min(Math.max(pageSizeRaw, 1), 200);

    const where: any =
      q.length > 0
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
      prisma.owner.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: page * pageSize,
        take: pageSize,
      }),
      prisma.owner.count({ where }),
    ]);

    res.json({ items, total });
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Update owner ----------
app.patch("/owners/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const schema = z.object({
      fullName: z.string().min(1).optional(),
      room: z.string().nullable().optional(),
      year: z.number().int().nullable().optional(),
      faculty: z.string().nullable().optional(),
      major: z.string().nullable().optional(),
      phone: z.string().nullable().optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const updated = await prisma.owner.update({
      where: { id },
      data: parsed.data,
    });

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Delete owner (กันลบถ้ามีรถอยู่) ----------
app.delete("/owners/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const vehicleCount = await prisma.vehicle.count({ where: { ownerId: id } });
    if (vehicleCount > 0) {
      return res.status(400).json({ message: "ลบไม่ได้: เจ้าของคนนี้มีรถลงทะเบียนอยู่" });
    }

    await prisma.owner.delete({ where: { id } });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

/**
 * =============================================================
 * VEHICLES CRUD
 * =============================================================
 */

// ---------- Admin: Create vehicle (limit 2 per owner) ----------
app.post("/vehicles", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const schema = z.object({
      ownerId: z.string().min(1),
      plateNo: z.string().min(1),
      color: z.string().optional(),
      brand: z.string().optional(),
      model: z.string().optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { ownerId, ...rest } = parsed.data;

    const count = await prisma.vehicle.count({ where: { ownerId } });
    if (count >= 2) return res.status(400).json({ message: "Owner already has 2 vehicles" });

    const qrToken = crypto.randomBytes(24).toString("hex");
    const vehicle = await prisma.vehicle.create({
      data: { ownerId, qrToken, ...rest },
    });

    res.json(vehicle);
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: List vehicles (search + pagination) ----------
app.get("/vehicles", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const schema = z.object({
      q: z.string().optional(),
      page: z.string().optional(),
      pageSize: z.string().optional(),
    });

    const parsed = schema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const q = (parsed.data.q || "").trim();
    const page = Math.max(Number(parsed.data.page || 0), 0);
    const pageSize = Math.min(Math.max(Number(parsed.data.pageSize || 10), 1), 200);

    const where: any = q
      ? {
          OR: [
            { plateNo: { contains: q, mode: "insensitive" } },
            { brand: { contains: q, mode: "insensitive" } },
            { model: { contains: q, mode: "insensitive" } },
            // relation filter ที่ถูกต้อง
            { owner: { is: { fullName: { contains: q, mode: "insensitive" } } } },
          ],
        }
      : {};

    const [items, total] = await Promise.all([
      prisma.vehicle.findMany({
        where,
        include: { owner: true },
        orderBy: { createdAt: "desc" },
        skip: page * pageSize,
        take: pageSize,
      }),
      prisma.vehicle.count({ where }),
    ]);

    res.json({ items, total });
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Update vehicle ----------
app.patch("/vehicles/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const schema = z.object({
      plateNo: z.string().min(1).optional(),
      color: z.string().nullable().optional(),
      brand: z.string().nullable().optional(),
      model: z.string().nullable().optional(),
      // ถ้าจะย้าย ownerId ได้ค่อยเพิ่มทีหลัง (เสี่ยง)
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const updated = await prisma.vehicle.update({
      where: { id },
      data: parsed.data,
      include: { owner: true },
    });

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Delete vehicle (แก้ FK RESTRICT: ลบ reports/images ก่อน) ----------
app.delete("/vehicles/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const result = await prisma.$transaction(async (tx) => {
      const v = await tx.vehicle.findUnique({ where: { id } });
      if (!v) return { ok: false as const, status: 404 as const, message: "Vehicle not found" };

      // ลบรูปทั้งหมดของ report ที่ผูกกับรถคันนี้
      await tx.reportImage.deleteMany({ where: { report: { vehicleId: id } } });
      // ลบรายงานของรถคันนี้
      await tx.report.deleteMany({ where: { vehicleId: id } });
      // ลบรถ
      await tx.vehicle.delete({ where: { id } });

      // ถ้า owner ไม่มีรถเหลือแล้ว -> ลบ owner
      const remaining = await tx.vehicle.count({ where: { ownerId: v.ownerId } });
      let deletedOwner = false;
      if (remaining === 0) {
        await tx.owner.delete({ where: { id: v.ownerId } });
        deletedOwner = true;
      }

      return {
        ok: true as const,
        deletedVehicleId: id,
        ownerId: v.ownerId,
        remainingVehicles: remaining,
        deletedOwner,
      };
    });

    if (!result.ok) return res.status(result.status).json({ message: result.message });
    res.json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * =============================================================
 * SCAN + REPORTS (Guard/Admin)
 * =============================================================
 */

// ---------- Guard/Admin: Scan by token ----------
app.get("/vehicles/by-token/:token", auth([Role.ADMIN, Role.GUARD]), async (req: any, res) => {
  const token = req.params.token;

  try {
    const vehicle = await prisma.vehicle.findUnique({
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

    if (!vehicle) return res.status(404).json({ message: "Not found" });
    res.json(vehicle);
  } catch (err: any) {
    console.error("❌ /vehicles/by-token ERROR", err?.stack ?? err);
    res.status(500).json({ message: err?.message ?? "Internal Server Error" });
  }
});

// ---------- Guard: Create report (no images) ----------
app.post("/reports", auth([Role.GUARD]), async (req: any, res, next) => {
  try {
    const schema = z.object({
      qrToken: z.string().min(1),
      problemType: z.nativeEnum(ProblemType),
      locationText: z.string().optional(),
      note: z.string().optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { qrToken, problemType, locationText, note } = parsed.data;

    const vehicle = await prisma.vehicle.findUnique({ where: { qrToken } });
    if (!vehicle) return res.status(404).json({ message: "Vehicle not found" });

    const report = await prisma.report.create({
      data: {
        vehicleId: vehicle.id,
        guardUserId: req.user.userId,
        problemType,
        locationText,
        note,
      },
    });

    res.json(report);
  } catch (err) {
    next(err);
  }
});

// ---------- Guard: Create report WITH images (min 3 images) ----------
app.post(
  "/reports/with-images",
  auth([Role.GUARD]),
  upload.array("images", 5),
  async (req: any, res, next) => {
    try {
      const schema = z.object({
        qrToken: z.string().min(1),
        problemType: z.nativeEnum(ProblemType),
        locationText: z.string().optional(),
        note: z.string().optional(),
      });

      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json(parsed.error);

      const files = req.files as Express.Multer.File[] | undefined;
      if (!files || files.length < 3) {
        return res.status(400).json({ message: "ต้องแนบรูปอย่างน้อย 3 รูป" });
      }

      const { qrToken, problemType, locationText, note } = parsed.data;

      const vehicle = await prisma.vehicle.findUnique({ where: { qrToken } });
      if (!vehicle) return res.status(404).json({ message: "Vehicle not found" });

      const report = await prisma.report.create({
        data: {
          vehicleId: vehicle.id,
          guardUserId: req.user.userId,
          problemType,
          locationText,
          note,
        },
      });

      const baseUrl = `${req.protocol}://${req.get("host")}`;

      await prisma.reportImage.createMany({
        data: files.map((f) => ({
          reportId: report.id,
          url: `${baseUrl}/uploads/${f.filename}`,
        })),
      });

      const full = await prisma.report.findUnique({
        where: { id: report.id },
        include: {
          images: true,
          vehicle: { select: { plateNo: true, brand: true, model: true, color: true, qrToken: true } },
          guard: { select: { username: true, role: true, fullName: true } },
        },
      });

      res.json(full);
    } catch (err) {
      next(err);
    }
  }
);

// ---------- Guard: My report history ----------
app.get("/reports/my", auth([Role.GUARD]), async (req: any, res, next) => {
  try {
    const schema = z.object({
      from: z.string().optional(),
      to: z.string().optional(),
      take: z.string().optional(),
      skip: z.string().optional(),
    });

    const parsed = schema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { from, to, take, skip } = parsed.data;

    const where: any = { guardUserId: req.user.userId };

    if (from && to) {
      const fromDate = new Date(`${from}T00:00:00.000Z`);
      const toDate = new Date(`${to}T23:59:59.999Z`);
      where.reportedAt = { gte: fromDate, lte: toDate };
    }

    const reports = await prisma.report.findMany({
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
  } catch (err) {
    next(err);
  }
});

// ---------- Admin/Guard: Get reports by vehicle ----------
app.get("/reports", auth([Role.ADMIN, Role.GUARD]), async (req: any, res, next) => {
  try {
    const schema = z.object({
      qrToken: z.string().optional(),
      vehicleId: z.string().optional(),
      take: z.string().optional(),
      skip: z.string().optional(),
    });

    const parsed = schema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { qrToken, vehicleId, take, skip } = parsed.data;

    if (req.user.role === Role.GUARD) {
      if (!qrToken) return res.status(400).json({ message: "GUARD must provide qrToken" });
    } else {
      if (!qrToken && !vehicleId) return res.status(400).json({ message: "Provide qrToken or vehicleId" });
    }

    let vid = vehicleId;

    if (!vid) {
      const vehicle = await prisma.vehicle.findUnique({ where: { qrToken: qrToken! } });
      if (!vehicle) return res.status(404).json({ message: "Vehicle not found" });
      vid = vehicle.id;
    }

    const reports = await prisma.report.findMany({
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
  } catch (err) {
    next(err);
  }
});

/**
 * =============================================================
 * ADMIN WEB: REPORTS LIST + EDIT + DELETE
 * =============================================================
 */

// ---------- Admin Web: LIST REPORTS ----------
app.get("/reports/admin", auth([Role.ADMIN]), async (req: any, res, next) => {
  try {
    const schema = z.object({
      from: z.string().optional(), // YYYY-MM-DD
      to: z.string().optional(), // YYYY-MM-DD
      problemType: z.nativeEnum(ProblemType).optional(),
      page: z.string().optional(),
      pageSize: z.string().optional(),
    });

    const parsed = schema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const { from, to, problemType } = parsed.data;

    const page = Math.max(parseInt(parsed.data.page || "0", 10) || 0, 0);
    const pageSizeRaw = parseInt(parsed.data.pageSize || "10", 10) || 10;
    const pageSize = Math.min(Math.max(pageSizeRaw, 1), 200);

    const where: any = {};
    if (from && to) {
      const fromDate = new Date(`${from}T00:00:00.000Z`);
      const toDate = new Date(`${to}T23:59:59.999Z`);
      where.reportedAt = { gte: fromDate, lte: toDate };
    }
    if (problemType) where.problemType = problemType;

    const [total, items] = await Promise.all([
      prisma.report.count({ where }),
      prisma.report.findMany({
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
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Update report ----------
app.patch("/reports/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    const schema = z.object({
      problemType: z.nativeEnum(ProblemType).optional(),
      locationText: z.string().nullable().optional(),
      note: z.string().nullable().optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json(parsed.error);

    const updated = await prisma.report.update({
      where: { id },
      data: parsed.data,
      include: {
        vehicle: { select: { plateNo: true, qrToken: true } },
        guard: { select: { username: true, fullName: true } },
        images: true,
      },
    });

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Delete report (ReportImage cascade ถ้า schema ตั้งไว้) ----------
app.delete("/reports/:id", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const id = req.params.id;

    // เผื่อกรณี schema ไม่ได้ cascade จริง ก็ลบให้ชัวร์
    await prisma.reportImage.deleteMany({ where: { reportId: id } });
    await prisma.report.delete({ where: { id } });

    res.json({ ok: true, deletedReportId: id });
  } catch (err) {
    next(err);
  }
});

/**
 * =============================================================
 * QR / BADGE
 * =============================================================
 */

// ---------- Admin: Generate QR PNG by token ----------
app.get("/qr/:token.png", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const token = req.params.token;

    const vehicle = await prisma.vehicle.findUnique({ where: { qrToken: token } });
    if (!vehicle) return res.status(404).json({ message: "Vehicle not found" });

    const qrValue = `parking-qr:${token}`;

    const pngBuffer = await QRCode.toBuffer(qrValue, {
      type: "png",
      errorCorrectionLevel: "M",
      margin: 2,
      scale: 8,
    });

    res.setHeader("Content-Type", "image/png");
    res.send(pngBuffer);
  } catch (err) {
    next(err);
  }
});

// ---------- Admin: Badge PDF 10x15 cm ----------
app.get("/badge/:token.pdf", auth([Role.ADMIN]), async (req, res, next) => {
  try {
    const token = req.params.token;

    const vehicle = await prisma.vehicle.findUnique({
      where: { qrToken: token },
      include: { owner: true },
    });
    if (!vehicle) return res.status(404).json({ message: "Vehicle not found" });

    const qrValue = `parking-qr:${token}`;
    const dataUrl = await QRCode.toDataURL(qrValue, {
      errorCorrectionLevel: "M",
      margin: 1,
      scale: 10,
    });
    const qrBuffer = Buffer.from(dataUrl.replace(/^data:image\/png;base64,/, ""), "base64");

    const CM = 28.346;
    const W = 10 * CM;
    const H = 15 * CM;

    const doc = new PDFDocument({
      size: [W, H],
      margins: { top: 20, left: 20, right: 20, bottom: 20 },
    });

    res.setHeader("Content-Type", "application/pdf");
    const safePlate = (vehicle.plateNo || "vehicle").replace(/[^\w\-]+/g, "_");
    res.setHeader("Content-Disposition", `inline; filename="badge-${safePlate}.pdf"`);

    const fontPath = path.join(process.cwd(), "assets", "fonts", "THSarabunNew.ttf");
    if (fs.existsSync(fontPath)) doc.font(fontPath);

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
    if (vehicle.owner.phone) doc.text(`โทร: ${vehicle.owner.phone}`, { align: "center" });

    doc.moveDown(0.5);
    doc.fontSize(8).text(`Token: ${token}`, { align: "center" });

    doc.end();
  } catch (err) {
    next(err);
  }
});

// ---------- Alias routes (เพื่อ compatibility เดิม) ----------
app.get("/vehicles/:token/qr.png", auth([Role.ADMIN]), (req, res) => {
  const token = req.params.token;
  return res.redirect(302, `/qr/${encodeURIComponent(token)}.png`);
});

app.get("/vehicles/:token/badge.pdf", auth([Role.ADMIN]), (req, res) => {
  const token = req.params.token;
  return res.redirect(302, `/badge/${encodeURIComponent(token)}.pdf`);
});

// ---------- Global error handler ----------
app.use((err: any, _req: any, res: any, _next: any) => {
  console.error("❌ API ERROR:", err);
  const message = err?.message || "Internal Server Error";
  res.status(500).json({ message });
});

// ---------- Start server ----------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ API running: http://0.0.0.0:${PORT}`);
});