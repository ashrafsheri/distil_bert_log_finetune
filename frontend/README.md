# LogGuard Frontend

A modern, real-time log monitoring dashboard built with React, TypeScript, and Tailwind CSS.

## Features

- **Real-time Log Monitoring**: Live updates via WebSocket connections
- **Threat Detection**: AI-powered anomaly detection with visual indicators
- **Modern UI**: Clean, minimal design with dark/light theme support
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **TypeScript**: Full type safety and better developer experience

## Tech Stack

- **React 19** - Latest React with concurrent features
- **TypeScript** - Type-safe JavaScript
- **Tailwind CSS** - Utility-first CSS framework
- **React Router** - Client-side routing
- **WebSocket** - Real-time communication

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Open [http://localhost:5173](http://localhost:5173) in your browser

### Building for Production

```bash
npm run build
```

## Project Structure

```
src/
├── assets/          # Images, icons, fonts
├── components/      # Reusable UI components
├── layouts/         # Layout components
├── pages/           # Page-level views
├── hooks/           # Custom React hooks
├── context/         # React context providers
├── utils/           # Helper functions
├── styles/          # Global styles
└── main.tsx         # Entry point
```

## API Integration

The frontend expects the backend to provide:

- **GET /api/fetch** - Returns initial logs and WebSocket ID
- **WebSocket /ws/{id}** - Real-time log updates

### Log Entry Format

```typescript
interface LogEntry {
  timestamp: string;    // "12:04 7 Oct 2025"
  ipAddress: string;    // "201.12.12.24"
  apiAccessed: string;  // "/api/v1/fetch"
  statusCode: number;   // 200
  infected: boolean;    // true/false
}
```

## Color Theme

The application uses a custom color palette inspired by modern security tools:

- **Primary**: Deep indigo backgrounds with bright blue accents
- **Success**: Green for safe logs
- **Error**: Red for threats and errors
- **Warning**: Orange for warnings
- **Muted**: Gray for secondary text

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### Code Style

- Use TypeScript for all components
- Follow React functional component patterns
- Use Tailwind CSS for styling
- Implement proper error boundaries
- Use custom hooks for data fetching

## Contributing

1. Follow the existing code style
2. Add TypeScript types for all props and state
3. Use semantic commit messages
4. Test your changes thoroughly