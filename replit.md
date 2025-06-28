# Number Database Management System

## Overview

This is a full-stack web application built with React and Express that provides a secure interface for managing a database of numbers with optional notes. The system features user authentication, CRUD operations, and a modern UI built with shadcn/ui components.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite for fast development and building
- **UI Library**: shadcn/ui components built on Radix UI primitives
- **Styling**: Tailwind CSS with CSS variables for theming
- **State Management**: TanStack Query (React Query) for server state
- **Form Handling**: React Hook Form with Zod validation
- **Routing**: Wouter for lightweight client-side routing

### Backend Architecture
- **Runtime**: Node.js with Express.js
- **Language**: TypeScript with ES modules
- **Session Management**: Express sessions with file-based storage
- **Data Storage**: File-based JSON storage (development setup)
- **Database ORM**: Drizzle ORM configured for PostgreSQL (ready for production)
- **Schema Validation**: Zod for runtime type checking

## Key Components

### Authentication System
- Secure file-based authentication with encrypted user storage
- Two user roles: admin (can delete numbers, change credentials) and user (view-only)
- Default admin: username "danixren", password "pendukungjava"
- User data stored in encrypted file (`server/security/users.enc`) with AES-256 encryption
- Password hashing with PBKDF2 (10,000 iterations) and unique salts
- Data integrity verification with SHA-256 checksums
- Session middleware protecting API routes with role-based access
- PostgreSQL session storage for persistence
- Automatic session timeout (30 minutes)

### Data Management
- **User Storage**: Secure encrypted file storage (`server/security/users.enc`) with AES-256 encryption
- **Numbers Storage**: Hybrid storage system - PostgreSQL with Drizzle ORM when DATABASE_URL is set, fallback to file-based JSON storage
- **Schema**: Numbers table (id, number, note, timestamp), Users table, Sessions table
- **Role System**: Admin users can delete numbers and manage credentials, regular users have read-only access
- **Security Features**: Password hashing, data integrity checks, file permissions (600)
- **Validation**: Zod schemas for input validation and type safety
- **Database Migration**: Automatic table creation with `npm run db:push` when PostgreSQL is configured

### UI Components
- **Design System**: shadcn/ui with "new-york" style variant
- **Theme**: Neutral color scheme with CSS variables
- **Responsive**: Mobile-first design with Tailwind CSS
- **Accessibility**: Radix UI primitives ensure ARIA compliance

### API Structure
- `POST /api/auth/login` - User authentication with role assignment
- `POST /api/auth/logout` - Session termination
- `GET /api/auth/me` - Current user info including role
- `POST /api/auth/change-credentials` - Change credentials (admin only)
- `GET /api/numbers` - Retrieve all numbers (authenticated users)
- `POST /api/numbers` - Add new number (authenticated users)
- `DELETE /api/numbers/:id` - Remove number (admin only)

## Data Flow

1. **Authentication Flow**:
   - User submits login form → Validation → Session creation → Dashboard redirect
   - Protected routes check session status → Redirect to login if unauthorized

2. **Data Operations**:
   - Dashboard loads → Query numbers from API → Display in UI
   - Add number → Form validation → API call → Optimistic update → Refresh data
   - Delete number → Confirmation → API call → Remove from UI

3. **Error Handling**:
   - Client-side validation with React Hook Form + Zod
   - Server-side validation and error responses
   - Toast notifications for user feedback

## External Dependencies

### Frontend Dependencies
- **Core**: React, TypeScript, Vite
- **UI**: Radix UI components, Tailwind CSS, Lucide icons
- **Data**: TanStack Query, React Hook Form, Zod
- **Routing**: Wouter
- **Utils**: clsx, tailwind-merge, date-fns

### Backend Dependencies
- **Core**: Express.js, TypeScript (tsx for development)
- **Database**: Drizzle ORM, @neondatabase/serverless
- **Auth**: express-session, connect-pg-simple
- **Validation**: Zod
- **Build**: esbuild for production bundling

## Deployment Strategy

### Development
- **Frontend**: Vite dev server with HMR
- **Backend**: tsx for TypeScript execution with file watching
- **Storage**: File-based JSON storage for rapid prototyping
- **Session**: In-memory sessions (development only)

### Production Ready
- **Database**: Hybrid storage - PostgreSQL with Neon serverless when configured, file-based fallback for development
- **Sessions**: PostgreSQL-backed session storage when database is available, memory store fallback
- **Build**: Vite build for frontend, esbuild for backend
- **Environment**: Optional `DATABASE_URL` for PostgreSQL, `SESSION_SECRET` recommended for production

### Build Commands
- `npm run dev` - Development with file watching
- `npm run build` - Production build (frontend + backend)
- `npm run start` - Production server
- `npm run db:push` - Database schema migration

## Database Setup

### Current Status
Your application uses a hybrid storage system that automatically adapts based on available resources:

1. **File-based Storage (Current)**: Uses encrypted JSON files for numbers and secure user authentication
2. **PostgreSQL Database (Optional)**: Full database support when `DATABASE_URL` is configured

### To Enable PostgreSQL Database:
1. Set up a PostgreSQL database (Neon, Supabase, or other provider)
2. Add `DATABASE_URL` environment variable to your Replit project
3. Run `npm run db:push` to create the database tables
4. Restart the application - it will automatically switch to database storage

### Benefits of PostgreSQL:
- Better performance with large datasets
- Persistent session storage
- Full ACID compliance
- Better concurrent access handling

## Security Features

### Authentication Protection
- Protected routes prevent bypassing login page
- Automatic redirect to dashboard when authenticated
- Session-based authentication with timeout
- Role-based access control (admin/user)

### Layout Improvements
- Responsive export button positioning
- Mobile-friendly dashboard layout
- Fixed overflow issues on smaller screens

## Recent Enhancements

### User Interface Improvements
- **Dark Mode by Default**: Application now starts in dark mode with seamless light/dark toggle
- **Responsive Header Layout**: Centered button layout with improved spacing and visual hierarchy
- **Developer Profile Popup**: Automatic popup after login with circular profile images and contact information
- **Enhanced Animations**: Smooth entrance animations across all pages and components

### Security Features
- **Password Protection for Number Entry**: Additional security layer requiring password "rendyzsuamihoshino" when adding new numbers
- **Session Management**: 30-minute timeout with rolling refresh on activity
- **Input Validation**: Numbers must start with "62" prefix and cannot be empty

### Form Enhancements
- **Smart Number Formatting**: Automatic "62" prefix enforcement without "+" symbol
- **Real-time Validation**: Immediate feedback for invalid input formats
- **Required Field Enforcement**: Numbers cannot be submitted empty

### Visual Design
- **Profile Integration**: Developer photos with online status indicators
- **Smooth Transitions**: Hover effects and scaling animations throughout
- **Loading States**: Animated spinners and progress indicators
- **Theme Consistency**: Proper color variables across all components

## Changelog
- June 28, 2025. Initial setup with role-based authentication system
- June 28, 2025. Migrated from JSON file storage to PostgreSQL database
- June 28, 2025. Implemented admin/user role system with restricted delete access
- June 28, 2025. Enhanced security: moved user data to encrypted file storage with AES-256 encryption, PBKDF2 password hashing, and integrity verification
- June 28, 2025. Added hybrid storage system with PostgreSQL support and authentication security improvements
- June 28, 2025. Fixed dashboard layout issues and implemented protected routing system
- June 28, 2025. Implemented dark mode default, developer profile popup, security password protection, number validation with 62 prefix, and comprehensive animations

## User Preferences

Preferred communication style: Simple, everyday language.