-- DropIndex
DROP INDEX "Message_senderId_idx";

-- DropIndex
DROP INDEX "Message_matchId_idx";

-- AlterTable
ALTER TABLE "User" ADD COLUMN "photoUrl" TEXT;

-- CreateIndex
CREATE INDEX "Message_matchId_createdAt_idx" ON "Message"("matchId", "createdAt");

-- CreateIndex
CREATE INDEX "Swipe_fromUserId_createdAt_idx" ON "Swipe"("fromUserId", "createdAt");
