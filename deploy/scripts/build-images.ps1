# UMS
Copy-Item ..\..\backend\bird\ums\build\libs\ums-1.3.jar app.jar -Force
docker build -t ums:1.3 -f ..\docker\ums.Dockerfile .
Remove-Item app.jar -Force

# Twitter
Copy-Item ..\..\backend\bird\twitter\build\libs\twitter-1.3.jar app.jar -Force
docker build -t twitter:1.3 -f ..\docker\twitter.Dockerfile .
Remove-Item app.jar -Force

# UI (React)
docker build -t ui-login:1.0 -f ..\docker\ui.Dockerfile ..\..\frontend