# Deployment Steps for CSV Export Feature

## On Your Server

After pulling the latest changes from the Sprint/1 branch, you need to rebuild the Docker containers to include the new code.

### Step 1: Stop the containers
```bash
sudo docker-compose down
```

### Step 2: Rebuild the frontend and backend containers
```bash
sudo docker-compose build frontend backend
```

### Step 3: Start the containers
```bash
sudo docker-compose up -d
```

### Alternative: Rebuild and restart in one command
```bash
sudo docker-compose up -d --build frontend backend
```

## Verification

After the containers are rebuilt and running:

1. Open your browser and navigate to your website
2. Log in as an admin or manager user
3. You should see the "Export CSV" button beside the "Search" button in the dashboard
4. The button should have a download icon and be positioned between "Search" and "Clear" buttons

## Troubleshooting

If the button still doesn't appear:

1. **Check browser cache**: Hard refresh the page (Ctrl+Shift+R or Cmd+Shift+R)
2. **Check container logs**:
   ```bash
   sudo docker-compose logs frontend
   sudo docker-compose logs backend
   ```
3. **Verify the build includes new code**: Check the build timestamp
   ```bash
   sudo docker-compose ps
   ```
4. **Force rebuild without cache**:
   ```bash
   sudo docker-compose build --no-cache frontend backend
   sudo docker-compose up -d
   ```

## Why Restart Didn't Work

- `docker-compose restart` only restarts the running containers
- It does **not** rebuild the containers with new code
- The frontend code is built during the Docker build process (`npm run build`)
- To include new code changes, you must rebuild the container image
