#!/bin/bash

# Show usage if no arguments provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 [OPTIONS] BACKUP_NAME"
    echo ""
    echo "Options:"
    echo "  --build-only    Restore only the build files (faster for deployment)"
    echo "  --full          Restore the entire project (source code)"
    echo "  --list          List available backups"
    echo ""
    echo "Example:"
    echo "  $0 --list"
    echo "  $0 --full xbz0n-web_2023-05-10_12-34-56"
    echo "  $0 --build-only xbz0n-web_2023-05-10_12-34-56"
    exit 1
fi

# Configuration
BACKUP_DIR="$HOME/backups/xbz0n-web"
SITE_DIR=$(pwd)

# List available backups
list_backups() {
    echo "Available backups:"
    echo "----------------"
    ls -lt "$BACKUP_DIR" | grep "xbz0n-web_" | awk '{print $9}' | sed 's/.tar.gz//' | grep -v -- "-build"
    echo ""
    echo "Available Git tags:"
    git tag -l "backup_*" | sort -r
    exit 0
}

# Restore from Git tag
restore_from_tag() {
    TAG_NAME=$1
    echo "Restoring from Git tag: $TAG_NAME"
    git checkout $TAG_NAME
    npm install
    npm run build && npm run export
    echo "Restoration from tag completed. Site is ready to deploy."
    exit 0
}

# Process arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --full)
            FULL=true
            shift
            ;;
        --list)
            list_backups
            ;;
        --tag)
            shift
            restore_from_tag $1
            ;;
        *)
            BACKUP_NAME=$1
            shift
            ;;
    esac
done

if [ -z "$BACKUP_NAME" ]; then
    echo "Error: Backup name is required"
    exit 1
fi

# Restore build only (fast recovery)
if [ "$BUILD_ONLY" = true ]; then
    if [ ! -d "$BACKUP_DIR/${BACKUP_NAME}-build" ]; then
        echo "Error: Build backup not found: $BACKUP_DIR/${BACKUP_NAME}-build"
        exit 1
    fi
    
    echo "Restoring build files from: $BACKUP_DIR/${BACKUP_NAME}-build"
    mkdir -p "$SITE_DIR/out"
    cp -r "$BACKUP_DIR/${BACKUP_NAME}-build/out/"* "$SITE_DIR/out/"
    echo "Build files restored. Ready to deploy with: git add out/ && git commit -m 'Restore from backup' && git push githubio main"
    exit 0
fi

# Restore full project
if [ "$FULL" = true ]; then
    if [ ! -f "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" ]; then
        echo "Error: Backup archive not found: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"
        exit 1
    fi
    
    echo "Restoring full project from: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"
    echo "This will overwrite your current project files!"
    read -p "Are you sure you want to continue? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Create a temp directory for extraction
        TEMP_DIR=$(mktemp -d)
        tar -xzf "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" -C "$TEMP_DIR"
        
        # Copy files, preserving existing node_modules
        rsync -a --exclude="node_modules" --exclude=".git" "$TEMP_DIR/" "$SITE_DIR/"
        
        # Clean up
        rm -rf "$TEMP_DIR"
        
        echo "Project files restored. Now installing dependencies and building..."
        npm install
        npm run build && npm run export
        
        echo "Full restoration completed. Site is ready to deploy."
    else
        echo "Restoration cancelled."
    fi
    exit 0
fi

echo "Error: Please specify either --build-only or --full"
exit 1 