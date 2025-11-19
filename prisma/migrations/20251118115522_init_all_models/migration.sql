/*
  Warnings:

  - The values [PROCESSING,DELIVERED] on the enum `OrderStatus` will be removed. If these variants are still used in the database, this will fail.
  - The values [COMPLETED] on the enum `PayoutStatus` will be removed. If these variants are still used in the database, this will fail.
  - The values [SUSPENDED] on the enum `SellerStatus` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `stock` on the `Inventory` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `Inventory` table. All the data in the column will be lost.
  - You are about to drop the column `currency` on the `Order` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `Order` table. All the data in the column will be lost.
  - You are about to drop the column `createdAt` on the `OrderItem` table. All the data in the column will be lost.
  - You are about to drop the column `currency` on the `Product` table. All the data in the column will be lost.
  - You are about to drop the column `slug` on the `Product` table. All the data in the column will be lost.
  - You are about to drop the column `status` on the `Product` table. All the data in the column will be lost.
  - You are about to drop the column `thumbnail` on the `Product` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `Product` table. All the data in the column will be lost.
  - You are about to drop the column `phone` on the `Seller` table. All the data in the column will be lost.
  - You are about to drop the column `shopSlug` on the `Seller` table. All the data in the column will be lost.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "OrderStatus_new" AS ENUM ('PENDING', 'PAID', 'SHIPPED', 'COMPLETED', 'CANCELLED');
ALTER TABLE "public"."Order" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "Order" ALTER COLUMN "status" TYPE "OrderStatus_new" USING ("status"::text::"OrderStatus_new");
ALTER TYPE "OrderStatus" RENAME TO "OrderStatus_old";
ALTER TYPE "OrderStatus_new" RENAME TO "OrderStatus";
DROP TYPE "public"."OrderStatus_old";
ALTER TABLE "Order" ALTER COLUMN "status" SET DEFAULT 'PENDING';
COMMIT;

-- AlterEnum
BEGIN;
CREATE TYPE "PayoutStatus_new" AS ENUM ('PENDING', 'PAID', 'FAILED');
ALTER TABLE "public"."Payout" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "Payout" ALTER COLUMN "status" TYPE "PayoutStatus_new" USING ("status"::text::"PayoutStatus_new");
ALTER TYPE "PayoutStatus" RENAME TO "PayoutStatus_old";
ALTER TYPE "PayoutStatus_new" RENAME TO "PayoutStatus";
DROP TYPE "public"."PayoutStatus_old";
ALTER TABLE "Payout" ALTER COLUMN "status" SET DEFAULT 'PENDING';
COMMIT;

-- AlterEnum
BEGIN;
CREATE TYPE "SellerStatus_new" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
ALTER TABLE "public"."Seller" ALTER COLUMN "status" DROP DEFAULT;
ALTER TABLE "Seller" ALTER COLUMN "status" TYPE "SellerStatus_new" USING ("status"::text::"SellerStatus_new");
ALTER TYPE "SellerStatus" RENAME TO "SellerStatus_old";
ALTER TYPE "SellerStatus_new" RENAME TO "SellerStatus";
DROP TYPE "public"."SellerStatus_old";
ALTER TABLE "Seller" ALTER COLUMN "status" SET DEFAULT 'PENDING';
COMMIT;

-- DropIndex
DROP INDEX "Product_slug_key";

-- DropIndex
DROP INDEX "Seller_shopSlug_key";

-- AlterTable
ALTER TABLE "Inventory" DROP COLUMN "stock",
DROP COLUMN "updatedAt",
ADD COLUMN     "quantity" INTEGER NOT NULL DEFAULT 0,
ALTER COLUMN "location" DROP DEFAULT;

-- AlterTable
ALTER TABLE "Order" DROP COLUMN "currency",
DROP COLUMN "updatedAt";

-- AlterTable
ALTER TABLE "OrderItem" DROP COLUMN "createdAt",
ALTER COLUMN "quantity" SET DEFAULT 1;

-- AlterTable
ALTER TABLE "Product" DROP COLUMN "currency",
DROP COLUMN "slug",
DROP COLUMN "status",
DROP COLUMN "thumbnail",
DROP COLUMN "updatedAt",
ADD COLUMN     "stock" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "Seller" DROP COLUMN "phone",
DROP COLUMN "shopSlug",
ADD COLUMN     "description" TEXT;

-- DropEnum
DROP TYPE "ProductStatus";
