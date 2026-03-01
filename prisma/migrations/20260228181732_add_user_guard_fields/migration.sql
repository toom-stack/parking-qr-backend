/*
  Warnings:

  - A unique constraint covering the columns `[employeeCode]` on the table `User` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[email]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "User" ADD COLUMN     "disabledAt" TIMESTAMP(3),
ADD COLUMN     "email" TEXT,
ADD COLUMN     "employeeCode" TEXT,
ADD COLUMN     "fullName" TEXT,
ADD COLUMN     "phone" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "User_employeeCode_key" ON "User"("employeeCode");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
