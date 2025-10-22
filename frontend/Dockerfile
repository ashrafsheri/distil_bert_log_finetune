# Frontend Dockerfile
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Install a simple static file server
RUN npm install -g serve

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "3000"]
