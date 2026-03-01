-- CreateTable
CREATE TABLE "ReportImage" (
    "id" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ReportImage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ReportImage_reportId_idx" ON "ReportImage"("reportId");

-- AddForeignKey
ALTER TABLE "ReportImage" ADD CONSTRAINT "ReportImage_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "Report"("id") ON DELETE CASCADE ON UPDATE CASCADE;
