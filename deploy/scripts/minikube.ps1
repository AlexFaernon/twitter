minikube start --cpus=2 --memory=4096 --driver=docker
minikube addons enable ingress
& minikube docker-env --shell powershell | Invoke-Expression