import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { signAccessToken, signRefreshToken } from "./jwt.js";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();

export default {
  register: async (data) => {
    const { name, email, password, role } = data;

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) throw new Error("Email already registered");

    const hashed = await bcrypt.hash(password, 10);

    return prisma.user.create({
      data: {
        name,
        email,
        password: hashed,
        role: role || "USER",
      },
    });
  },

  login: async ({ email, password }) => {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw new Error("User not found");

    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new Error("Invalid credentials");

    return {
      accessToken: signAccessToken(user),
      refreshToken: signRefreshToken(user),
      user,
    };
  },

  refresh: async (refreshToken) => {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

      const user = await prisma.user.findUnique({
        where: { id: decoded.id },
      });

      if (!user) throw new Error("User not found");

      return {
        accessToken: signAccessToken(user),
      };
    } catch (err) {
      throw new Error("Invalid refresh token");
    }
  },
};

