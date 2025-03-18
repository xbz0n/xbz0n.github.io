# Setup Instructions for GitHub Pages User Site

For a GitHub Pages user site to work properly, the repository must be named exactly `<username>.github.io`. Here's how to set this up:

## 1. Create a New Repository on GitHub

1. Go to GitHub and create a new repository named exactly `xbz0n.github.io`
   - Visit: https://github.com/new
   - Repository name: xbz0n.github.io
   - Make it Public
   - Do not initialize with README or any other files

## 2. Push Your Code to the New Repository

```bash
# Add the new repository as another remote
git remote add githubio https://github.com/xbz0n/xbz0n.github.io.git

# Push your code to the new repository
git push -u githubio main
```

## 3. For Future Updates

When making changes to your site, push to both repositories to keep them in sync:

```bash
# Push to original repository
git push origin main

# Push to GitHub Pages repository
git push githubio main
```

## 4. GitHub Pages Settings

After pushing to the new repository:

1. Go to the repository settings on GitHub: https://github.com/xbz0n/xbz0n.github.io/settings/pages
2. Under "Source", ensure it's set to "GitHub Actions"
3. Your site will be published at https://xbz0n.github.io/

The next time your GitHub Actions workflow runs, your site will be deployed to your user GitHub Pages site.
