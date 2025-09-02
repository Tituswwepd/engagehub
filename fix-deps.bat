:: fix-deps.bat
:: 0) Be at the project root
cd "C:\Users\User\Downloads\engagehub-pro-colorfun\engagehub-pro-colorfun"

:: 1) Ensure we only track source, not node_modules
git rm -r --cached node_modules 2>nul
echo node_modules/>> .gitignore

:: 2) Regenerate dependencies + lockfile from scratch
rd /s /q node_modules
del package-lock.json 2>nul

:: 3) Reinstall deps (this creates a fresh package-lock.json)
npm install

:: 4) Verify the two modules actually exist locally
npm ls jsonwebtoken
npm ls sqlite3

:: 5) Commit the files Render needs to install correctly
git add package.json package-lock.json .gitignore
git commit -m "chore: clean install; commit lockfile; ignore node_modules"
git push
