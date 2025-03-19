#!/bin/bash

# Configuration
BACKUP_DIR="$HOME/backups/xbz0n-web"
SITE_DIR=$(pwd)
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_NAME="xbz0n-web_$DATE"
TAG_NAME="backup_$DATE"

# Create backup directories if they don't exist
mkdir -p "$BACKUP_DIR"

echo "Creating backup of xbz0n-web site..."
echo "Source: $SITE_DIR"
echo "Destination: $BACKUP_DIR/$BACKUP_NAME"

# Create a tar archive of the entire site
tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" \
    --exclude="node_modules" \
    --exclude=".next" \
    --exclude="out" \
    --exclude=".git" \
    -C "$SITE_DIR" .

echo "Backup archive created: $BACKUP_DIR/$BACKUP_NAME.tar.gz"

# Create a git tag for this backup
git tag "$TAG_NAME"
git push githubio "$TAG_NAME"

echo "Git tag created and pushed: $TAG_NAME"

# Create a backup of just the build output (for quick recovery)
mkdir -p "$BACKUP_DIR/$BACKUP_NAME-build"
cp -r "$SITE_DIR/out/" "$BACKUP_DIR/$BACKUP_NAME-build/"

echo "Build files backed up to: $BACKUP_DIR/$BACKUP_NAME-build"

echo "Backup completed successfully!"
echo ""
echo "To restore the full site: tar -xzf $BACKUP_DIR/$BACKUP_NAME.tar.gz -C /path/to/restore"
echo "To restore just the build: cp -r $BACKUP_DIR/$BACKUP_NAME-build/* /path/to/gh-pages/repo" 