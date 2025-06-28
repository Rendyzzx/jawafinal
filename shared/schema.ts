import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table for authentication
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  role: text("role").notNull().default("user"), // 'admin' or 'user'
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const numbers = pgTable("numbers", {
  id: serial("id").primaryKey(),
  number: text("number").notNull(),
  note: text("note"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  role: true,
});

export const updateUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  role: true,
}).partial();

export const insertNumberSchema = createInsertSchema(numbers).pick({
  number: true,
  note: true,
});

export const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

export const changeCredentialsSchema = z.object({
  newUsername: z.string().min(3, "Username must be at least 3 characters"),
  newPassword: z.string().min(6, "Password must be at least 6 characters"),
  currentPassword: z.string().min(1, "Current password is required"),
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type UpdateUser = z.infer<typeof updateUserSchema>;
export type User = Omit<typeof users.$inferSelect, 'password'>;
export type InsertNumber = z.infer<typeof insertNumberSchema>;
export type Number = typeof numbers.$inferSelect;
export type LoginRequest = z.infer<typeof loginSchema>;
export type ChangeCredentialsRequest = z.infer<typeof changeCredentialsSchema>;
